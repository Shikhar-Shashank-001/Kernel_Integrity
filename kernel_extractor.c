// SPDX-License-Identifier: GPL-2.0
/*
 * kernel_extractor.c - Module 1: Kernel Memory Extractor (LKM side)
 *
 * Continuously snapshots read-only kernel memory (.text, syscall tables,
 * module text/rodata) into a shared ring that user space maps with mmap().
 * User space never calls read()/copy_to_user(): it consumes frames in place.
 *
 *   worker kthread --memcpy--> [desc ring | 16 KiB payload slots] <--mmap-- daemon
 *        |                          head (release)   tail (acquire)
 *        +-- never sleeps while holding a lock, never blocks on the consumer:
 *            ring full => publish what we have, back off 100-300us, retry.
 *
 * Safety model
 *   - kallsyms_lookup_name() is bootstrapped through a transient kprobe
 *     (it is not exported since v5.7). IBT/ENDBR is handled.
 *   - Every page is checked with lookup_address() (page-table walk) before it
 *     is read; the read itself uses copy_from_kernel_nofault() unless
 *     fast_copy=1, so a bad address yields a zero-filled frame + KIM_F_FAULT
 *     instead of an Oops.
 *   - Module memory cannot be freed under us: the MODULE_STATE_GOING notifier
 *     takes the same mutex as the copy loop.
 *   - direct_text=1 (default): kernel text is not copied. Its physical pages
 *     (contiguous, never freed) are offered as one extra read-only, never
 *     executable mmap window and text frames are published as descriptors
 *     only (KIM_F_DIRECT). Each scan still walks the page tables for every
 *     text page and checks it maps to the physical page the window exposes
 *     (else: copy + KIM_F_REMAP), so the daemon hashes what the CPU executes.
 *   - The consumer-owned tail is untrusted and sanity-checked every time.
 *   - Device is CAP_SYS_ADMIN only and single-opener (SPSC invariant). The
 *     ring is vzalloc()ed, so no stale kernel data leaks to user space.
 *
 * Tested layout: x86_64, Linux >= 5.15 (struct module layout differs at 6.4).
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/version.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/uaccess.h>
#include <linux/ktime.h>
#include <linux/capability.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/string.h>
#include <linux/cpumask.h>
#include <linux/log2.h>
#include <asm/io.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/pgtable_types.h>
#include <asm/unistd.h>

#include "kim_uapi.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kernel Integrity Monitor");
MODULE_DESCRIPTION("Zero-copy kernel memory extractor for integrity verification");

#ifndef CONFIG_X86_64
# error "kernel_extractor: x86_64 only (page-table/PTE helpers are arch specific)"
#endif

/* ------------------------------------------------------------------ */
/* Tunables                                                           */
/* ------------------------------------------------------------------ */
static unsigned int scan_interval_ms = 1000;
module_param(scan_interval_ms, uint, 0644);
MODULE_PARM_DESC(scan_interval_ms, "Idle time between full scans; 0 = free-run");

static int worker_cpu = -1;
module_param(worker_cpu, int, 0444);
MODULE_PARM_DESC(worker_cpu, "Pin worker to this CPU (e.g. an E-core); -1 = unbound");

static int worker_nice = 10;
module_param(worker_nice, int, 0444);
MODULE_PARM_DESC(worker_nice, "Nice value of the worker thread");

static bool fast_copy;
module_param(fast_copy, bool, 0444);
MODULE_PARM_DESC(fast_copy, "After PTE validation use plain memcpy instead of the nofault copy");

static unsigned int ring_slots = KIM_NSLOTS;
module_param(ring_slots, uint, 0444);
MODULE_PARM_DESC(ring_slots, "Ring frames (power of two, 256-4096, default 2048; 16 KiB + 64 B each)");

static unsigned int backoff_us = 100;
module_param(backoff_us, uint, 0444);
MODULE_PARM_DESC(backoff_us, "Ring-full back-off: sleep backoff_us..3*backoff_us (10-1000)");

static bool direct_text = true;
module_param(direct_text, bool, 0444);
MODULE_PARM_DESC(direct_text, "Expose kernel text read-only instead of copying it each scan");

static bool monitor_modules = true;
module_param(monitor_modules, bool, 0444);
MODULE_PARM_DESC(monitor_modules, "Track loaded LKMs");

#define KIM_MAX_SEGS      1024
#define KIM_MAX_MODS       512
#define KIM_BATCH_FRAMES    64

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
# define kim_vm_set(v, f)    vm_flags_set((v), (f))
# define kim_vm_clear(v, f)  vm_flags_clear((v), (f))
#else
# define kim_vm_set(v, f)    ((v)->vm_flags |= (f))
# define kim_vm_clear(v, f)  ((v)->vm_flags &= ~(f))
#endif

/* Table sizes from the kernel's own dispatcher bounds, when available. */
#ifdef NR_syscalls
# define KIM_NR_NATIVE ((unsigned long)NR_syscalls)
#else
# define KIM_NR_NATIVE 0UL
#endif
#ifdef IA32_NR_syscalls
# define KIM_NR_IA32 ((unsigned long)IA32_NR_syscalls)
#else
# define KIM_NR_IA32 0UL
#endif
#ifdef X32_NR_syscalls
# define KIM_NR_X32 ((unsigned long)X32_NR_syscalls)
#else
# define KIM_NR_X32 0UL
#endif

/* ------------------------------------------------------------------ */
/* State                                                              */
/* ------------------------------------------------------------------ */
typedef unsigned long (*kim_lookup_fn)(const char *name);
typedef int (*kim_size_off_fn)(unsigned long addr, unsigned long *size,
			       unsigned long *off);

struct kim_seg {
	bool          used;
	u32           type;
	u32           id;
	u32           len;
	unsigned long base;
	const void   *owner;               /* struct module * (identity only) */
	char          name[KIM_NAME_LEN];
};

static struct {
	/* shared pages */
	struct kim_hdr  *hdr;
	struct kim_cons *cons;
	void            *ring;
	struct kim_desc *desc;
	u8              *data;
	u64              head_priv;        /* frames written (maybe unpublished) */
	u64              head_pub;         /* == hdr->head                       */
	u32              nslots;           /* == hdr->nslots, pow2               */
	u64              t_last;           /* producer: end of the previous frame */

	/* segment table (seg_lock protects everything below up to 'worker') */
	struct mutex     seg_lock;
	struct kim_seg  *segs;
	unsigned int     seg_hi;           /* high-water mark                    */
	u32              next_id;
	unsigned int     cur_idx;          /* resumable scan cursor              */
	u32              cur_off, cur_id, epoch, epoch_frames;

	kim_lookup_fn    lookup;
	kim_size_off_fn  size_off;

	/* text window (immutable after init; len 0 = disabled) */
	unsigned long    text_win, text_win_len, text_pfn0;
	pgd_t           *kpgd;            /* init_mm.pgd (not exported) */

	struct task_struct *worker;
	wait_queue_head_t   kick_wq, poll_wq;
	int                 kick;
	unsigned int        interval_ms;
	atomic_t            opened;
	struct notifier_block mod_nb;
	bool                nb_registered;
} kim;

#define KIM_STAT_ADD(f, v) WRITE_ONCE(kim.hdr->f, kim.hdr->f + (v))

/* ------------------------------------------------------------------ */
/* Symbol resolution                                                  */
/* ------------------------------------------------------------------ */

/*
 * kallsyms_lookup_name() lost its export in v5.7. A kprobe registered on the
 * symbol reports its address in kp.addr; we then unregister immediately.
 * With CONFIG_X86_KERNEL_IBT the kprobe core moves kp.addr 4 bytes past the
 * ENDBR64 at function entry. Calling there would raise #CP on IBT hardware,
 * so detect the ENDBR and step back to the real entry point.
 */
static int kim_bootstrap_kallsyms(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
	kim.lookup = kallsyms_lookup_name;
	return 0;
#else
	struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
	unsigned long addr;
	u32 insn = 0;
	int ret;

	ret = register_kprobe(&kp);
	if (ret) {
		pr_err("kprobe bootstrap failed (%d); need CONFIG_KPROBES\n", ret);
		return ret;
	}
	addr = (unsigned long)kp.addr;
	unregister_kprobe(&kp);

	if (!copy_from_kernel_nofault(&insn, (void *)(addr - 4), sizeof(insn)) &&
	    insn == 0xfa1e0ff3u)                 /* endbr64 */
		addr -= 4;

	kim.lookup = (kim_lookup_fn)addr;
	/* self check: the function must resolve its own name to itself */
	if (kim.lookup("kallsyms_lookup_name") != addr) {
		kim.lookup = NULL;
		return -EFAULT;
	}
	return 0;
#endif
}

static unsigned long kim_sym(const char *name)
{
	return kim.lookup ? kim.lookup(name) : 0;
}

static unsigned long kim_sym_bytes(unsigned long addr, unsigned long hint)
{
	unsigned long size = 0, off = 0;

	if (hint)
		return hint;
	if (kim.size_off && kim.size_off(addr, &size, &off) && !off)
		return size;
	return 0;
}

/* ------------------------------------------------------------------ */
/* Segment table                                                      */
/* ------------------------------------------------------------------ */
static int kim_seg_add_locked(u32 type, unsigned long base, unsigned long len,
			      const char *name, const void *owner)
{
	unsigned int i;
	struct kim_seg *s = NULL;

	/* defensive: kernel-half canonical address, no wrap, fits u32 */
	if (!len || len > U32_MAX || (long)base >= 0 || base + len < base)
		return -EINVAL;

	for (i = 0; i < KIM_MAX_SEGS; i++)
		if (!kim.segs[i].used) {
			s = &kim.segs[i];
			break;
		}
	if (!s) {
		KIM_STAT_ADD(seg_overflow, 1);
		return -ENOSPC;
	}
	s->type  = type;
	s->base  = base;
	s->len   = len;
	s->owner = owner;
	s->id    = ++kim.next_id;
	strscpy(s->name, name, sizeof(s->name));
	s->used  = true;
	if (i + 1 > kim.seg_hi)
		kim.seg_hi = i + 1;
	WRITE_ONCE(kim.hdr->n_segments, kim.hdr->n_segments + 1);
	return 0;
}

static void kim_seg_del_owner_locked(const void *owner)
{
	unsigned int i;

	for (i = 0; i < kim.seg_hi; i++)
		if (kim.segs[i].used && kim.segs[i].owner == owner) {
			kim.segs[i].used = false;
			WRITE_ONCE(kim.hdr->n_segments, kim.hdr->n_segments - 1);
		}
}

static bool kim_owner_known_locked(const void *owner)
{
	unsigned int i;

	for (i = 0; i < kim.seg_hi; i++)
		if (kim.segs[i].used && kim.segs[i].owner == owner)
			return true;
	return false;
}

/* Physical page of va from a lookup_address() result (4K, 2M or 1G mapping). */
static unsigned long kim_pte_pfn(pte_t *pte, unsigned int level, unsigned long va)
{
	switch (level) {
	case PG_LEVEL_1G:
		return pud_pfn(*(pud_t *)pte) + ((va & ~PUD_MASK) >> PAGE_SHIFT);
	case PG_LEVEL_2M:
		return pmd_pfn(*(pmd_t *)pte) + ((va & ~PMD_MASK) >> PAGE_SHIFT);
	default:
		return pte_pfn(*pte);
	}
}

/*
 * lookup_address() takes no lock and reads the PMD twice (leaf test, then
 * pte_offset_kernel()), so it races with x86 CPA splitting and re-merging
 * large pages, which the module ROX cache does to its shared 2M pages on every
 * module load and unload. It can then read the code bytes of a just-merged 2M
 * page as PTEs, or a PTE table that is being freed, and report a W bit nobody
 * set (seen twice in a 10 min soak, on rfcomm and xfs text). Every reading
 * that would raise an alarm is redone here: each level read once, as gup_fast
 * does, with interrupts off, so the flush_tlb_all() that collapse waits for
 * before freeing the old table cannot complete under us.
 * Returns the entry's flags (0 if not present) and its pfn. Needs kim.kpgd.
 */
static pteval_t kim_pte_stable(unsigned long va, unsigned long *pfn)
{
	pgd_t *pgdp = pgd_offset_pgd(kim.kpgd, va), pgd;
	p4d_t *p4dp, p4d;
	pud_t *pudp, pud;
	pmd_t *pmdp, pmd;
	pte_t pte;
	pteval_t f = 0;
	unsigned long irq;

	*pfn = 0;
	local_irq_save(irq);
	pgd = READ_ONCE(*pgdp);
	if (!pgd_present(pgd))
		goto out;
	p4dp = p4d_offset_lockless(pgdp, pgd, va);
	p4d = READ_ONCE(*p4dp);
	if (!p4d_present(p4d))
		goto out;
	pudp = pud_offset_lockless(p4dp, p4d, va);
	pud = READ_ONCE(*pudp);
	if (!pud_present(pud))
		goto out;
	if (pud_leaf(pud)) {
		f = pud_flags(pud);
		*pfn = pud_pfn(pud) + ((va & ~PUD_MASK) >> PAGE_SHIFT);
		goto out;
	}
	pmdp = pmd_offset_lockless(pudp, pud, va);
	pmd = READ_ONCE(*pmdp);
	if (!pmd_present(pmd))
		goto out;
	if (pmd_leaf(pmd)) {
		f = pmd_flags(pmd);
		*pfn = pmd_pfn(pmd) + ((va & ~PMD_MASK) >> PAGE_SHIFT);
		goto out;
	}
	pte = READ_ONCE(*pte_offset_kernel(&pmd, va));
	if (pte_present(pte)) {
		f = pte_flags(pte);
		*pfn = pte_pfn(pte);
	}
out:
	local_irq_restore(irq);
	return f;
}

/* Redo an alarming reading (f, pfn) with kim_pte_stable(); count overrules. */
static pteval_t kim_pte_recheck(unsigned long va, pteval_t f, unsigned long *pfn)
{
	unsigned long p;
	pteval_t g;

	if (!kim.kpgd)
		return f;
	g = kim_pte_stable(va, &p);
	KIM_STAT_ADD(pte_rechecks, 1);
	if (((f ^ g) & (_PAGE_PRESENT | _PAGE_RW)) || p != *pfn)
		KIM_STAT_ADD(pte_overruled, 1);
	*pfn = p;
	return g;
}

/*
 * Text window for direct_text: [_stext, _etext) rounded out to pages (the page
 * after PAGE_ALIGN(_etext) may be freed at boot, so never beyond). Refused
 * unless every page is present and maps linearly from __pa_symbol(start),
 * i.e. the kernel's own physical layout.
 */
static void kim_setup_text_window(void)
{
	unsigned long start = kim.hdr->ktext_start & PAGE_MASK;
	unsigned long end = PAGE_ALIGN(kim.hdr->ktext_end);
	unsigned long pfn0 = __pa_symbol(start) >> PAGE_SHIFT;
	unsigned long va;

	if (!direct_text)
		return;
	for (va = start; va < end; va += PAGE_SIZE) {
		unsigned int level;
		pte_t *pte = lookup_address(va, &level);

		if (!pte || !(pte_flags(*pte) & _PAGE_PRESENT) ||
		    kim_pte_pfn(pte, level, va) != pfn0 + ((va - start) >> PAGE_SHIFT) ||
		    !pfn_valid(pfn0 + ((va - start) >> PAGE_SHIFT))) {
			pr_warn("kernel text not mapped linearly: direct_text off\n");
			return;
		}
	}
	kim.text_win = start;
	kim.text_win_len = end - start;
	kim.text_pfn0 = pfn0;
	kim.hdr->text_win_base = start;
	kim.hdr->text_win_len = end - start;
}

static int kim_resolve_static_segments(void)
{
	static const struct {
		const char *sym, *tag;
		u32 type;
		unsigned long nr;
	} tbl[] = {
		{ "sys_call_table",      "sys_call_table", KIM_SEG_SYSCALL_TABLE, KIM_NR_NATIVE },
		{ "ia32_sys_call_table", "ia32_sct",       KIM_SEG_COMPAT_TABLE,  KIM_NR_IA32 },
		{ "x32_sys_call_table",  "x32_sct",        KIM_SEG_COMPAT_TABLE,  KIM_NR_X32 },
	};
	unsigned long stext, etext, slide, a;
	unsigned int i;
	int ret;

	kim.size_off = (kim_size_off_fn)kim_sym("kallsyms_lookup_size_offset");
	a = kim_sym("init_mm");
	kim.kpgd = a ? ((struct mm_struct *)a)->pgd : NULL;
	if (!kim.kpgd)
		pr_warn("init_mm not resolved: alarming PTE readings are not re-walked\n");

	stext = kim_sym("_stext") ?: kim_sym("_text");
	etext = kim_sym("_etext");
	if (!stext || !etext || etext <= stext) {
		pr_err("cannot resolve kernel text bounds\n");
		return -ENOENT;
	}

	/* KASLR validation: inside the kernel-image window, page aligned slide */
	slide = stext - (unsigned long)__START_KERNEL;
	if (stext < __START_KERNEL_map || stext >= MODULES_VADDR ||
	    (slide & (PAGE_SIZE - 1))) {
		pr_err("implausible KASLR layout (text outside image window)\n");
		return -ERANGE;
	}
	kim.hdr->kaslr_slide = (s64)slide;
	kim.hdr->ktext_start = stext;
	kim.hdr->ktext_end   = etext;
	kim.hdr->ktext_phys  = slow_virt_to_phys((void *)stext);

	mutex_lock(&kim.seg_lock);
	ret = kim_seg_add_locked(KIM_SEG_KTEXT, stext, etext - stext, "ktext", NULL);
	for (i = 0; !ret && i < ARRAY_SIZE(tbl); i++) {
		unsigned long len;

		a = kim_sym(tbl[i].sym);
		if (!a)
			continue;               /* e.g. no x32 on this kernel */
		len = kim_sym_bytes(a, tbl[i].nr * sizeof(unsigned long));
		if (!len || len > 64 * 1024) {
			pr_warn("skip %s: size unknown\n", tbl[i].sym);
			continue;
		}
		if (kim_seg_add_locked(tbl[i].type, a, len, tbl[i].tag, NULL))
			continue;
		switch (i) {
		case 0: kim.hdr->sys_call_table = a;
			kim.hdr->sct_phys = slow_virt_to_phys((void *)a); break;
		case 1: kim.hdr->ia32_sct = a; break;
		case 2: kim.hdr->x32_sct = a;  break;
		}
	}
	mutex_unlock(&kim.seg_lock);

	if (!ret && !kim.hdr->sys_call_table) {
		pr_err("sys_call_table not resolvable\n");
		return -ENOENT;
	}
	return ret;
}

/* ------------------------------------------------------------------ */
/* Loadable module enumeration                                        */
/* ------------------------------------------------------------------ */
struct kim_range { unsigned long base; unsigned long len; u32 type; };

/* Static (post-init) code and read-only data of a module. */
static int kim_module_ranges(struct module *mod, struct kim_range r[2])
{
	int n = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	if (mod->mem[MOD_TEXT].size)
		r[n++] = (struct kim_range){ (unsigned long)mod->mem[MOD_TEXT].base,
					     mod->mem[MOD_TEXT].size, KIM_SEG_MOD_TEXT };
	if (mod->mem[MOD_RODATA].size)
		r[n++] = (struct kim_range){ (unsigned long)mod->mem[MOD_RODATA].base,
					     mod->mem[MOD_RODATA].size, KIM_SEG_MOD_RODATA };
#else
	unsigned long base = (unsigned long)mod->core_layout.base;
	unsigned long text = mod->core_layout.text_size;
	unsigned long ro   = mod->core_layout.ro_size;

	if (text)
		r[n++] = (struct kim_range){ base, text, KIM_SEG_MOD_TEXT };
	if (ro > text)
		r[n++] = (struct kim_range){ base + text, ro - text, KIM_SEG_MOD_RODATA };
#endif
	return n;
}

static void kim_add_module_locked(struct module *mod)
{
	struct kim_range r[2];
	int i, n;

	if (kim_owner_known_locked(mod))
		return;
	n = kim_module_ranges(mod, r);
	for (i = 0; i < n; i++)
		kim_seg_add_locked(r[i].type, r[i].base, r[i].len, mod->name, mod);
}

static int kim_module_event(struct notifier_block *nb, unsigned long action, void *data)
{
	struct module *mod = data;

	switch (action) {
	case MODULE_STATE_LIVE:
		mutex_lock(&kim.seg_lock);
		kim_add_module_locked(mod);
		mutex_unlock(&kim.seg_lock);
		break;
	case MODULE_STATE_GOING:
		/*
		 * Blocks until the worker finished the frame it is copying, so
		 * the module's memory cannot be freed underneath it.
		 */
		mutex_lock(&kim.seg_lock);
		kim_seg_del_owner_locked(mod);
		mutex_unlock(&kim.seg_lock);
		break;
	}
	return NOTIFY_DONE;
}

/* The 'modules' list head lives in the kernel image, real modules do not. */
static inline bool kim_is_module_mem(unsigned long a)
{
	return (a >= MODULES_VADDR && a < MODULES_END) || is_vmalloc_addr((void *)a);
}

/*
 * Enumerate modules that were loaded before us. We walk the circular list
 * starting at our own node under RCU, pin each module with try_module_get()
 * (blocks unload), then register segments outside the RCU section. Modules
 * loaded/unloaded afterwards are handled by the notifier.
 *
 * Limitation: a module that unlinked itself from the list is invisible here
 * (it is still seen by the notifier if it was loaded after us).
 */
static void kim_enumerate_modules(void)
{
	struct module **tmp;
	struct list_head *pos;
	int i, n = 0;

	tmp = kvmalloc_array(KIM_MAX_MODS, sizeof(*tmp), GFP_KERNEL);
	if (!tmp)
		return;

	rcu_read_lock();
	for (pos = rcu_dereference(list_next_rcu(&THIS_MODULE->list));
	     pos != &THIS_MODULE->list && n < KIM_MAX_MODS;
	     pos = rcu_dereference(list_next_rcu(pos))) {
		struct module *m;

		if (!kim_is_module_mem((unsigned long)pos))
			continue;               /* sentinel list head */
		m = list_entry(pos, struct module, list);
		if (try_module_get(m))
			tmp[n++] = m;
	}
	rcu_read_unlock();

	for (i = 0; i < n; i++) {
		mutex_lock(&kim.seg_lock);
		kim_add_module_locked(tmp[i]);
		mutex_unlock(&kim.seg_lock);
		module_put(tmp[i]);
	}
	kvfree(tmp);
}

/* ------------------------------------------------------------------ */
/* Extraction path (non-blocking, no sleeping locks held across copies) */
/* ------------------------------------------------------------------ */

/*
 * Copy n bytes of kernel memory into a ring slot, one page at a time.
 * Walk the kernel page tables first; unmapped pages never get touched.
 */
static u16 kim_copy_region(u8 *dst, unsigned long src, u32 n, u32 *faults)
{
	u16 flags = 0;
	u32 done = 0;

	while (done < n) {
		unsigned long va = src + done;
		u32 chunk = min_t(u32, PAGE_SIZE - (va & ~PAGE_MASK), n - done);
		unsigned int level;
		pte_t *pte = lookup_address(va, &level);
		pteval_t f = pte ? pte_flags(*pte) : 0;
		unsigned long pfn;
		bool ok = false;

		if ((f & (_PAGE_PRESENT | _PAGE_RW)) != _PAGE_PRESENT) {
			pfn = (f & _PAGE_PRESENT) ? kim_pte_pfn(pte, level, va) : 0;
			f = kim_pte_recheck(va, f, &pfn);
		}
		if (f & _PAGE_PRESENT) {
			if (f & _PAGE_RW)
				flags |= KIM_F_PTE_W;
			if (!(f & _PAGE_NX))
				flags |= KIM_F_PTE_X;
			if (fast_copy) {
				memcpy(dst + done, (const void *)va, chunk);
				ok = true;
			} else {
				ok = !copy_from_kernel_nofault(dst + done,
							       (const void *)va, chunk);
			}
		}
		if (!ok) {
			memset(dst + done, 0, chunk);
			flags |= KIM_F_FAULT;
			(*faults)++;
		}
		done += chunk;
	}
	if (n < KIM_FRAME_BYTES)
		memset(dst + n, 0, KIM_FRAME_BYTES - n);
	return flags;
}

/*
 * Kernel text frame without a copy: every page must be present and still map
 * to the physical page the text window exposes. Returns false (and sets
 * KIM_F_REMAP if a page had moved) when the frame must be copied instead.
 */
static bool kim_text_direct(unsigned long src, u32 n, u16 *flags)
{
	unsigned long va, end = src + n;
	u16 f16 = 0;

	for (va = src & PAGE_MASK; va < end; va += PAGE_SIZE) {
		unsigned int level;
		pte_t *pte = lookup_address(va, &level);
		pteval_t f = pte ? pte_flags(*pte) : 0;
		unsigned long want = kim.text_pfn0 + ((va - kim.text_win) >> PAGE_SHIFT);
		unsigned long pfn = (f & _PAGE_PRESENT) ? kim_pte_pfn(pte, level, va) : 0;

		if ((f & (_PAGE_PRESENT | _PAGE_RW)) != _PAGE_PRESENT || pfn != want)
			f = kim_pte_recheck(va, f, &pfn);
		if (!(f & _PAGE_PRESENT))
			return false;           /* copy path reports the fault */
		if (pfn != want) {
			*flags |= KIM_F_REMAP;
			return false;
		}
		if (f & _PAGE_RW)
			f16 |= KIM_F_PTE_W;
		if (!(f & _PAGE_NX))
			f16 |= KIM_F_PTE_X;
	}
	*flags |= f16 | KIM_F_DIRECT;
	return true;
}

enum { KIM_EMIT_OK = 0, KIM_EMIT_EPOCH_END, KIM_EMIT_FULL };

/* Emit one frame at the scan cursor. Caller holds seg_lock. */
static int kim_emit_next_locked(void)
{
	struct kim_seg *s;
	struct kim_desc *d;
	u32 off, n, slot, faults = 0;
	u16 flags;
	u64 tail;
	u8 *dst;

	for (;;) {
		if (kim.cur_idx >= kim.seg_hi) {
			kim.cur_idx = 0;
			kim.cur_off = 0;
			kim.epoch++;
			return KIM_EMIT_EPOCH_END;
		}
		s = &kim.segs[kim.cur_idx];
		if (s->used) {
			if (!kim.cur_off)
				kim.cur_id = s->id;
			if (kim.cur_id == s->id && kim.cur_off < s->len)
				break;
		}
		kim.cur_idx++;                  /* done, removed or replaced */
		kim.cur_off = 0;
	}

	/* backpressure: never block, never overwrite unconsumed slots */
	tail = smp_load_acquire(&kim.cons->tail);
	if (unlikely(tail > kim.head_pub)) {      /* hostile or buggy consumer */
		KIM_STAT_ADD(bad_tail_events, 1);
		return KIM_EMIT_FULL;
	}
	if (kim.head_priv - tail >= kim.nslots) {
		KIM_STAT_ADD(ring_full_events, 1);
		return KIM_EMIT_FULL;
	}

	off  = kim.cur_off;
	n    = min_t(u32, KIM_FRAME_BYTES, s->len - off);
	slot = kim.head_priv & (kim.nslots - 1);
	dst  = kim.data + (size_t)slot * KIM_FRAME_BYTES;
	d    = &kim.desc[slot];

	flags = 0;
	if (s->type == KIM_SEG_KTEXT && kim.text_win_len &&
	    kim_text_direct(s->base + off, n, &flags)) {
		KIM_STAT_ADD(direct_frames, 1);
	} else {
		if (flags & KIM_F_REMAP)
			KIM_STAT_ADD(remap_frames, 1);
		flags |= kim_copy_region(dst, s->base + off, n, &faults);
	}

	d->base_address = s->base + off;
	d->timestamp_ns = ktime_get_ns();
	/* cost of this frame (incl. lock + loop) from the timestamp we take anyway */
	if (flags & KIM_F_DIRECT)
		KIM_STAT_ADD(direct_ns, d->timestamp_ns - kim.t_last);
	else
		KIM_STAT_ADD(copy_ns, d->timestamp_ns - kim.t_last);
	kim.t_last = d->timestamp_ns;
	d->segment_type = s->type;
	d->segment_id   = s->id;
	d->length       = n;
	d->seg_length   = s->len;
	d->seg_offset   = off;
	d->scan_epoch   = kim.epoch;
	d->page_offset  = (s->base + off) & ~PAGE_MASK;
	d->flags        = flags | (off == 0 ? KIM_F_FIRST : 0) |
			  (off + n >= s->len ? KIM_F_LAST : 0);
	strscpy_pad(d->name, s->name, sizeof(d->name));

	kim.cur_off += n;
	kim.head_priv++;
	kim.epoch_frames++;
	KIM_STAT_ADD(frames_total, 1);
	KIM_STAT_ADD(bytes_total, n);
	if (faults)
		KIM_STAT_ADD(fault_pages, faults);
	return KIM_EMIT_OK;
}

static void kim_publish(void)
{
	if (kim.head_priv == kim.head_pub)
		return;
	kim.head_pub = kim.head_priv;
	smp_store_release(&kim.hdr->head, kim.head_pub);
	if (wq_has_sleeper(&kim.poll_wq))
		wake_up_interruptible(&kim.poll_wq);
}

#define KIM_BATCH_MORE   0
#define KIM_BATCH_EPOCH  1

/* Emit up to KIM_BATCH_FRAMES frames; lock is taken per frame (bounded hold). */
static int kim_scan_batch(void)
{
	int i;

	kim.t_last = ktime_get_ns();
	for (i = 0; i < KIM_BATCH_FRAMES; i++) {
		int r;

		mutex_lock(&kim.seg_lock);
		r = kim_emit_next_locked();
		mutex_unlock(&kim.seg_lock);

		if (r == KIM_EMIT_FULL) {
			kim_publish();
			return -EAGAIN;
		}
		if (r == KIM_EMIT_EPOCH_END) {
			kim_publish();
			/* frames visible first, then the epoch counter */
			WRITE_ONCE(kim.hdr->epoch, kim.epoch);
			WRITE_ONCE(kim.hdr->last_epoch_ns, ktime_get_ns());
			smp_store_release(&kim.hdr->epochs_done,
					  kim.hdr->epochs_done + 1);
			return KIM_BATCH_EPOCH;
		}
	}
	kim_publish();
	return KIM_BATCH_MORE;
}

static int kim_worker(void *unused)
{
	set_user_nice(current, worker_nice);

	while (!kthread_should_stop()) {
		int r = kim_scan_batch();

		if (r == -EAGAIN) {             /* consumer lagging: back off */
			usleep_range(backoff_us, 3 * backoff_us);
			continue;
		}
		if (r == KIM_BATCH_EPOCH) {
			unsigned int ms = READ_ONCE(kim.interval_ms);

			if (!kim.epoch_frames)  /* empty table: do not spin */
				ms = max(ms, 10U);
			kim.epoch_frames = 0;
			if (ms)
				wait_event_interruptible_timeout(kim.kick_wq,
					kthread_should_stop() || READ_ONCE(kim.kick),
					msecs_to_jiffies(ms));
			WRITE_ONCE(kim.kick, 0);
			continue;
		}
		cond_resched();
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* Character device                                                   */
/* ------------------------------------------------------------------ */
static int kim_open(struct inode *ino, struct file *f)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (atomic_cmpxchg(&kim.opened, 0, 1))
		return -EBUSY;          /* single consumer keeps the ring SPSC */
	return 0;
}

static int kim_release(struct inode *ino, struct file *f)
{
	atomic_set(&kim.opened, 0);
	return 0;
}

static int kim_mmap(struct file *f, struct vm_area_struct *vma)
{
	unsigned long off = vma->vm_pgoff << PAGE_SHIFT;
	unsigned long len = vma->vm_end - vma->vm_start;
	unsigned long i, want;
	void *kva;
	bool rw = false;

	switch (off) {
	case KIM_OFF_HDR:  kva = kim.hdr;  want = PAGE_SIZE;      break;
	case KIM_OFF_CONS: kva = kim.cons; want = PAGE_SIZE; rw = true; break;
	case KIM_OFF_RING: kva = kim.ring; want = KIM_RING_BYTES_N(kim.nslots); break;
	case KIM_OFF_TEXT: kva = NULL;     want = kim.text_win_len; break;
	default:           return -EINVAL;
	}
	if (!want)
		return -ENODEV;         /* text window disabled */
	if (len != want || !(vma->vm_flags & VM_SHARED))
		return -EINVAL;

	if (!rw) {
		/* read-only forever: refuse PROT_WRITE and forbid mprotect upgrade */
		if (vma->vm_flags & VM_WRITE)
			return -EPERM;
		kim_vm_clear(vma, VM_MAYWRITE);
	}
	kim_vm_set(vma, VM_DONTEXPAND | VM_DONTDUMP | VM_DONTCOPY);

	if (!kva) {
		/* live kernel text: physically contiguous, never executable here */
		if (vma->vm_flags & VM_EXEC)
			return -EPERM;
		kim_vm_clear(vma, VM_MAYEXEC);
		return remap_pfn_range(vma, vma->vm_start, kim.text_pfn0, len,
				       vma->vm_page_prot);
	}

	for (i = 0; i < len; i += PAGE_SIZE) {
		void *p = kva + i;
		unsigned long pfn = is_vmalloc_addr(p) ? vmalloc_to_pfn(p)
						       : virt_to_phys(p) >> PAGE_SHIFT;
		int ret = remap_pfn_range(vma, vma->vm_start + i, pfn, PAGE_SIZE,
					  vma->vm_page_prot);
		if (ret)
			return ret;     /* core tears the partial mapping down */
	}
	return 0;
}

static __poll_t kim_poll(struct file *f, poll_table *wait)
{
	poll_wait(f, &kim.poll_wq, wait);
	return READ_ONCE(kim.hdr->head) > smp_load_acquire(&kim.cons->tail) ?
	       (EPOLLIN | EPOLLRDNORM) : 0;
}

static long kim_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	u32 ms;

	switch (cmd) {
	case KIM_IOC_SET_INTERVAL:
		if (get_user(ms, (u32 __user *)arg))
			return -EFAULT;
		WRITE_ONCE(kim.interval_ms, min_t(u32, ms, 3600 * 1000));
		WRITE_ONCE(kim.kick, 1);
		wake_up(&kim.kick_wq);
		return 0;
	case KIM_IOC_KICK:
		WRITE_ONCE(kim.kick, 1);
		wake_up(&kim.kick_wq);
		return 0;
	case KIM_IOC_RESCAN:
		if (monitor_modules)
			kim_enumerate_modules();
		return 0;
	}
	return -ENOTTY;
}

static const struct file_operations kim_fops = {
	.owner          = THIS_MODULE,
	.open           = kim_open,
	.release        = kim_release,
	.mmap           = kim_mmap,
	.poll           = kim_poll,
	.unlocked_ioctl = kim_ioctl,
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)
	.llseek         = no_llseek,
#endif
};

static struct miscdevice kim_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = KIM_DEV_NAME,
	.fops  = &kim_fops,
	.mode  = 0600,
};

/* ------------------------------------------------------------------ */
/* Init / exit                                                        */
/* ------------------------------------------------------------------ */
static void kim_free(void)
{
	kvfree(kim.segs);
	vfree(kim.ring);
	free_page((unsigned long)kim.cons);
	free_page((unsigned long)kim.hdr);
	kim.segs = NULL; kim.ring = NULL; kim.cons = NULL; kim.hdr = NULL;
}

static int __init kim_init(void)
{
	struct kim_hdr *h;
	int ret;

	BUILD_BUG_ON(PAGE_SIZE != KIM_PAGE);

	mutex_init(&kim.seg_lock);
	init_waitqueue_head(&kim.kick_wq);
	init_waitqueue_head(&kim.poll_wq);
	atomic_set(&kim.opened, 0);
	kim.interval_ms = scan_interval_ms;
	kim.epoch = 1;

	if (ring_slots < KIM_NSLOTS_MIN || ring_slots > KIM_NSLOTS_MAX ||
	    !is_power_of_2(ring_slots)) {
		pr_err("ring_slots must be a power of two in [%u, %u]\n",
		       KIM_NSLOTS_MIN, KIM_NSLOTS_MAX);
		return -EINVAL;
	}
	if (backoff_us < 10 || backoff_us > 1000) {
		pr_err("backoff_us must be in [10, 1000]\n");
		return -EINVAL;
	}
	kim.nslots = ring_slots;

	ret = kim_bootstrap_kallsyms();
	if (ret)
		return ret;

	kim.hdr  = (void *)get_zeroed_page(GFP_KERNEL);
	kim.cons = (void *)get_zeroed_page(GFP_KERNEL);
	kim.ring = vzalloc(KIM_RING_BYTES_N(kim.nslots));
	kim.segs = kvcalloc(KIM_MAX_SEGS, sizeof(*kim.segs), GFP_KERNEL);
	if (!kim.hdr || !kim.cons || !kim.ring || !kim.segs) {
		ret = -ENOMEM;
		goto err_free;
	}
	kim.desc = kim.ring;
	kim.data = (u8 *)kim.ring + KIM_DESC_RING_BYTES_N(kim.nslots);

	h = kim.hdr;
	h->magic = KIM_MAGIC;
	h->abi_version = KIM_ABI_VERSION;
	h->nslots = kim.nslots;
	h->frame_bytes = KIM_FRAME_BYTES;
	h->desc_size = KIM_DESC_SIZE;
	h->desc_off = 0;
	h->data_off = KIM_DESC_RING_BYTES_N(kim.nslots);

	ret = kim_resolve_static_segments();
	if (ret)
		goto err_free;
	kim_setup_text_window();

	if (monitor_modules) {
		kim.mod_nb.notifier_call = kim_module_event;
		ret = register_module_notifier(&kim.mod_nb);
		if (ret)
			goto err_free;
		kim.nb_registered = true;
		kim_enumerate_modules();
	}

	if (worker_cpu >= 0 && cpu_online(worker_cpu)) {
		kim.worker = kthread_create(kim_worker, NULL, "kim_extractor");
		if (!IS_ERR(kim.worker))
			kthread_bind(kim.worker, worker_cpu);
	} else {
		kim.worker = kthread_create(kim_worker, NULL, "kim_extractor");
	}
	if (IS_ERR(kim.worker)) {
		ret = PTR_ERR(kim.worker);
		kim.worker = NULL;
		goto err_nb;
	}
	wake_up_process(kim.worker);

	ret = misc_register(&kim_misc);
	if (ret)
		goto err_worker;

	pr_info("ready: %llu segments, device /dev/%s, direct text %s (no addresses logged)\n",
		(unsigned long long)kim.hdr->n_segments, KIM_DEV_NAME,
		kim.text_win_len ? "on" : "off");
	return 0;

err_worker:
	kthread_stop(kim.worker);
err_nb:
	if (kim.nb_registered)
		unregister_module_notifier(&kim.mod_nb);
err_free:
	kim_free();
	return ret;
}

static void __exit kim_exit(void)
{
	/* No mapping can exist: open files/VMAs pin the module via fops.owner. */
	misc_deregister(&kim_misc);
	kthread_stop(kim.worker);
	if (kim.nb_registered)
		unregister_module_notifier(&kim.mod_nb);
	kim_free();
}

module_init(kim_init);
module_exit(kim_exit);
