// SPDX-License-Identifier: GPL-2.0
/*
 * test_extractor.c - functional tests + benchmarks for kernel_extractor.ko
 *
 * Run as root with the module loaded:  sudo ./test_extractor
 *
 * Functional:
 *   T1 header/ABI/geometry and 64-byte alignment of mapped structures
 *   T2 mmap hardening (no writable ring mapping, single opener, bad length)
 *   T3 one full epoch: frame continuity, FIRST/LAST flags, no faults
 *   T4 mapped addresses == /proc/kallsyms (_stext,_etext,sys_call_table)
 *   T5 sys_call_table integrity: every entry inside [_stext,_etext)
 *   T6 ring payload == live memory read through /proc/kcore (syscall table)
 *   T7 direct_text: every text frame DIRECT, none REMAP, window bytes ==
 *      /proc/kcore; window hardening is part of T2
 * Benchmarks:
 *   B1 producer rate (consumer skips payload)       GB/s
 *   B2 end-to-end ingest incl. AVX2 read of payload GB/s + frame-age latency
 *   B3 kick -> first frame visible latency (idle ring)
 */
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include "ingestion_daemon.h"

static int g_fail, g_pass, g_skip;
#define PASS(...) do { g_pass++; printf("  [PASS] "); printf(__VA_ARGS__); putchar('\n'); } while (0)
#define FAIL(...) do { g_fail++; printf("  [FAIL] "); printf(__VA_ARGS__); putchar('\n'); } while (0)
#define SKIP(...) do { g_skip++; printf("  [SKIP] "); printf(__VA_ARGS__); putchar('\n'); } while (0)
#define CHECK(c, ...) do { if (c) PASS(__VA_ARGS__); else FAIL(__VA_ARGS__); } while (0)

static void set_interval(struct kim_ctx *c, uint32_t ms)
{
	ioctl(c->fd, KIM_IOC_SET_INTERVAL, &ms);
}

/* Discard everything until the producer has been idle for ~300 ms. */
static void drain_idle(struct kim_ctx *c)
{
	uint64_t idle_since = kim_now_ns();

	while (kim_now_ns() - idle_since < 300000000ull) {
		uint64_t n = kim_available(c);

		if (n) {
			kim_consume(c, (uint32_t)n);
			idle_since = kim_now_ns();
		} else {
			usleep(2000);
		}
	}
}

/* ---------------- epoch collection ---------------- */
struct epoch {
	uint64_t frames, bytes;
	uint64_t ktext_base, ktext_bytes;
	uint64_t sct_base;  uint32_t sct_len;  uint8_t sct[64 * 1024];
	unsigned mod_segs, fault_frames, w_frames_text, bad_seq;
	unsigned ktext_frames, direct_frames, remap_frames, direct_nontext;
	int complete;
};

static int collect_epoch(struct kim_ctx *c, struct epoch *e, int timeout_ms)
{
	uint64_t start = __atomic_load_n(&c->hdr->epochs_done, __ATOMIC_ACQUIRE);
	uint64_t t0 = kim_now_ns();
	uint32_t cur_id = 0, next_off = 0;

	memset(e, 0, sizeof(*e));
	ioctl(c->fd, KIM_IOC_KICK);

	while ((kim_now_ns() - t0) / 1000000 < (uint64_t)timeout_ms) {
		struct kim_frame f[64];
		size_t n = kim_peek(c, f, 64), i;

		for (i = 0; i < n; i++) {
			const struct kim_desc *d = f[i].d;

			e->frames++;
			e->bytes += d->length;
			if (d->flags & KIM_F_FAULT) e->fault_frames++;
			if ((d->flags & KIM_F_PTE_W) && d->segment_type == KIM_SEG_KTEXT)
				e->w_frames_text++;

			/* continuity inside a segment */
			if (d->flags & KIM_F_FIRST) {
				if (d->seg_offset) e->bad_seq++;
				cur_id = d->segment_id;
				if (d->segment_type == KIM_SEG_MOD_TEXT ||
				    d->segment_type == KIM_SEG_MOD_RODATA) e->mod_segs++;
			} else if (d->segment_id != cur_id || d->seg_offset != next_off) {
				e->bad_seq++;
			}
			next_off = d->seg_offset + d->length;

			if (d->flags & KIM_F_DIRECT) {
				e->direct_frames++;
				if (d->segment_type != KIM_SEG_KTEXT) e->direct_nontext++;
			}
			if (d->flags & KIM_F_REMAP) e->remap_frames++;
			if (d->segment_type == KIM_SEG_KTEXT) {
				if (d->flags & KIM_F_FIRST) e->ktext_base = d->base_address;
				e->ktext_bytes += d->length;
				e->ktext_frames++;
			} else if (d->segment_type == KIM_SEG_SYSCALL_TABLE) {
				e->sct_base = d->base_address - d->seg_offset;
				e->sct_len = d->seg_length;
				if (d->seg_offset + d->length <= sizeof(e->sct))
					memcpy(e->sct + d->seg_offset, f[i].payload, d->length);
			}
		}
		if (n) {
			kim_consume(c, (uint32_t)n);
		} else if (__atomic_load_n(&c->hdr->epochs_done, __ATOMIC_ACQUIRE) > start &&
			   !kim_available(c)) {
			e->complete = 1;
			return 0;
		} else {
			kim_wait(c, 5);
		}
	}
	return -ETIMEDOUT;
}

/* ---------------- /proc/kallsyms ---------------- */
static unsigned long kallsym(const char *want)
{
	FILE *f = fopen("/proc/kallsyms", "r");
	char line[512], name[256], type;
	unsigned long a, r = 0;

	if (!f) return 0;
	while (fgets(line, sizeof(line), f))
		if (sscanf(line, "%lx %c %255s", &a, &type, name) == 3 && !strcmp(name, want)) {
			r = a;
			break;
		}
	fclose(f);
	return r;
}

/* ---------------- /proc/kcore ---------------- */
static int kcore_read(unsigned long va, void *buf, size_t len)
{
	int fd = open("/proc/kcore", O_RDONLY);
	Elf64_Ehdr eh;
	int rc = -1;

	if (fd < 0) return -1;
	if (pread(fd, &eh, sizeof(eh), 0) == sizeof(eh) && !memcmp(eh.e_ident, ELFMAG, SELFMAG)) {
		for (unsigned i = 0; i < eh.e_phnum; i++) {
			Elf64_Phdr ph;

			if (pread(fd, &ph, sizeof(ph), eh.e_phoff + (off_t)i * sizeof(ph)) != sizeof(ph))
				break;
			if (ph.p_type == PT_LOAD && va >= ph.p_vaddr &&
			    va + len <= ph.p_vaddr + ph.p_filesz) {
				rc = pread(fd, buf, len, ph.p_offset + (va - ph.p_vaddr)) == (ssize_t)len ? 0 : -1;
				break;
			}
		}
	}
	close(fd);
	return rc;
}

/* ---------------- stats ---------------- */
static int cmp_u64(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

	return x < y ? -1 : x > y;
}
static uint64_t pct(uint64_t *v, size_t n, double p)
{
	if (!n) return 0;
	qsort(v, n, sizeof(*v), cmp_u64);
	return v[(size_t)((n - 1) * p)];
}

/* ---------------- tests ---------------- */
static void t_header(struct kim_ctx *c)
{
	puts("T1 header / geometry / alignment");
	CHECK(c->hdr->magic == KIM_MAGIC && c->hdr->abi_version == KIM_ABI_VERSION, "magic + ABI version");
	CHECK(c->hdr->nslots >= KIM_NSLOTS_MIN && c->hdr->nslots <= KIM_NSLOTS_MAX &&
	      !(c->hdr->nslots & (c->hdr->nslots - 1)) && c->hdr->frame_bytes == KIM_FRAME_BYTES &&
	      c->hdr->data_off == KIM_DESC_RING_BYTES_N(c->hdr->nslots), "ring geometry %u x %u B",
	      c->hdr->nslots, c->hdr->frame_bytes);
	CHECK(sizeof(struct kim_desc) == 64 && ((uintptr_t)c->desc & 63) == 0, "descriptors 64B sized and aligned");
	CHECK(((uintptr_t)c->data & (KIM_FRAME_BYTES - 1)) == 0, "payload slots 16 KiB aligned");
	CHECK(KIM_FRAME_BYTES * 2 == KIM_CHUNK_E_CORE && KIM_CHUNK_P_MIN % KIM_FRAME_BYTES == 0 &&
	      KIM_CHUNK_P_MAX % KIM_FRAME_BYTES == 0, "frames tile 16-32 KiB (E) and 64-256 KiB (P) chunks");
	CHECK(c->hdr->head >= c->tail && c->hdr->head - c->tail <= c->hdr->nslots, "head/tail invariant");
	CHECK(c->hdr->ktext_start && c->hdr->ktext_end > c->hdr->ktext_start, "text bounds resolved");
	CHECK((c->hdr->kaslr_slide & (KIM_PAGE - 1)) == 0, "KASLR slide page aligned (slide=0x%llx)",
	      (unsigned long long)c->hdr->kaslr_slide);
	if (!c->hdr->text_win_len) {
		SKIP("text window off (direct_text=0 or refused at load, see dmesg)");
		return;
	}
	CHECK(c->text && c->hdr->text_win_base == (c->hdr->ktext_start & ~(KIM_PAGE - 1)) &&
	      c->hdr->text_win_len == ((c->hdr->ktext_end + KIM_PAGE - 1) & ~(KIM_PAGE - 1)) -
				      c->hdr->text_win_base,
	      "text window mapped, covers [_stext,_etext) page-rounded (%.1f MiB)",
	      c->hdr->text_win_len / 1048576.0);
}

static void t_mmap_hardening(struct kim_ctx *c)
{
	void *p;
	int fd2;

	puts("T2 mmap / open hardening");
	p = mmap(NULL, c->ring_len, PROT_READ | PROT_WRITE, MAP_SHARED, c->fd, (off_t)KIM_OFF_RING);
	CHECK(p == MAP_FAILED && errno == EPERM, "writable ring mapping refused");
	if (p != MAP_FAILED) munmap(p, c->ring_len);

	p = mmap(NULL, 2 * KIM_PAGE, PROT_READ, MAP_SHARED, c->fd, (off_t)KIM_OFF_HDR);
	CHECK(p == MAP_FAILED && errno == EINVAL, "wrong-length mapping refused");
	if (p != MAP_FAILED) munmap(p, 2 * KIM_PAGE);

	p = mmap(NULL, KIM_PAGE, PROT_READ, MAP_PRIVATE, c->fd, (off_t)KIM_OFF_HDR);
	CHECK(p == MAP_FAILED, "MAP_PRIVATE refused");
	if (p != MAP_FAILED) munmap(p, KIM_PAGE);

	if (c->hdr->text_win_len) {
		size_t tl = c->hdr->text_win_len;

		p = mmap(NULL, tl, PROT_READ | PROT_WRITE, MAP_SHARED, c->fd, (off_t)KIM_OFF_TEXT);
		CHECK(p == MAP_FAILED && errno == EPERM, "writable text window refused");
		if (p != MAP_FAILED) munmap(p, tl);
		p = mmap(NULL, tl, PROT_READ | PROT_EXEC, MAP_SHARED, c->fd, (off_t)KIM_OFF_TEXT);
		CHECK(p == MAP_FAILED && errno == EPERM, "executable text window refused");
		if (p != MAP_FAILED) munmap(p, tl);
		p = mmap(NULL, tl - KIM_PAGE, PROT_READ, MAP_SHARED, c->fd, (off_t)KIM_OFF_TEXT);
		CHECK(p == MAP_FAILED && errno == EINVAL, "wrong-length text window refused");
		if (p != MAP_FAILED) munmap(p, tl - KIM_PAGE);
		p = mmap(NULL, tl, PROT_READ, MAP_SHARED, c->fd, (off_t)KIM_OFF_TEXT);
		if (p == MAP_FAILED) {
			FAIL("read-only text window mapping failed: %s", strerror(errno));
		} else {
			int w = mprotect(p, tl, PROT_READ | PROT_WRITE);
			int x = mprotect(p, tl, PROT_READ | PROT_EXEC);

			CHECK(w && x, "mprotect cannot make the text window writable or executable");
			munmap(p, tl);
		}
	}

	fd2 = open(KIM_DEV_PATH, O_RDWR);
	CHECK(fd2 < 0 && errno == EBUSY, "second opener gets EBUSY (SPSC preserved)");
	if (fd2 >= 0) close(fd2);
}

static struct epoch E;

static void t_epoch(struct kim_ctx *c)
{
	int rc;

	puts("T3 one full scan epoch");
	rc = collect_epoch(c, &E, 20000);
	CHECK(rc == 0 && E.complete, "epoch completed (%llu frames, %.1f MiB, %u module segments)",
	      (unsigned long long)E.frames, E.bytes / 1048576.0, E.mod_segs);
	CHECK(E.bad_seq == 0, "per-segment frame continuity (bad=%u)", E.bad_seq);
	CHECK(E.fault_frames == 0, "no unreadable pages (fault frames=%u, fault_pages=%llu)", E.fault_frames,
	      (unsigned long long)c->hdr->fault_pages);
	CHECK(E.w_frames_text == 0, "no writable PTEs inside kernel text (W^X)");
	CHECK(E.ktext_bytes == c->hdr->ktext_end - c->hdr->ktext_start, ".text bytes == _etext-_stext (%llu)",
	      (unsigned long long)E.ktext_bytes);
	CHECK(c->hdr->bad_tail_events == 0, "kernel saw no invalid tail values");
}

/* T7: direct frames are the live text: compare window bytes with /proc/kcore.
 * Retries a sample a few times in case a static key flips between the reads. */
static void t_direct(struct kim_ctx *c)
{
	const double where[] = { 0.0, 0.25, 0.5, 0.75, 0.999 };
	uint8_t live[KIM_FRAME_BYTES];
	unsigned i, same = 0, n = sizeof(where) / sizeof(where[0]);

	puts("T7 direct kernel text (no copy)");
	if (!c->hdr->text_win_len) {
		SKIP("text window off");
		CHECK(E.direct_frames == 0, "no DIRECT frames without a window");
		return;
	}
	CHECK(E.direct_frames == E.ktext_frames && !E.direct_nontext,
	      "every kernel text frame DIRECT, nothing else (%u/%u)", E.direct_frames, E.ktext_frames);
	CHECK(E.remap_frames == 0 && c->hdr->remap_frames == 0,
	      "no text page moved since load (REMAP frames %u)", E.remap_frames);
	for (i = 0; i < n; i++) {
		uint64_t off = (uint64_t)(where[i] * (c->hdr->ktext_end - c->hdr->ktext_start)) &
			       ~(uint64_t)(KIM_FRAME_BYTES - 1);
		uint64_t va = c->hdr->ktext_start + off, len = c->hdr->ktext_end - va;
		const uint8_t *w = c->text + (va - c->text_base);
		int t;

		if (len > KIM_FRAME_BYTES) len = KIM_FRAME_BYTES;
		for (t = 0; t < 3; t++) {
			if (kcore_read(va, live, len) != 0) {
				SKIP("/proc/kcore unavailable (lockdown or CONFIG_PROC_KCORE=n)");
				return;
			}
			if (!memcmp(live, w, len)) { same++; break; }
			usleep(10000);
		}
	}
	CHECK(same == n, "text window == live memory via /proc/kcore (%u/%u sampled frames)", same, n);
}

static void t_symbols(struct kim_ctx *c)
{
	unsigned long st = kallsym("_stext"), et = kallsym("_etext"), sct = kallsym("sys_call_table");

	puts("T4 mapped addresses vs /proc/kallsyms");
	if (!st || !et || !sct) {
		SKIP("kallsyms hidden (kptr_restrict) or unreadable");
		return;
	}
	CHECK(E.ktext_base == st && c->hdr->ktext_start == st, "_stext matches");
	CHECK(c->hdr->ktext_end == et, "_etext matches");
	CHECK(E.sct_base == sct && c->hdr->sys_call_table == sct, "sys_call_table matches");
}

static void t_sct(struct kim_ctx *c)
{
	unsigned bad = 0, n = E.sct_len / 8, i;
	uint8_t live[64 * 1024];

	puts("T5/T6 sys_call_table integrity");
	if (!E.sct_len) { FAIL("no syscall table frames captured"); return; }
	for (i = 0; i < n; i++) {
		uint64_t v;

		memcpy(&v, E.sct + 8 * i, 8);
		if (v < c->hdr->ktext_start || v >= c->hdr->ktext_end) bad++;
	}
	CHECK(bad == 0, "%u/%u syscall entries inside kernel text (hooked entries: %u)", n - bad, n, bad);

	if (kcore_read(E.sct_base, live, E.sct_len) != 0) {
		SKIP("/proc/kcore unavailable (lockdown or CONFIG_PROC_KCORE=n)");
		return;
	}
	CHECK(!memcmp(live, E.sct, E.sct_len), "ring payload == live memory via /proc/kcore (%u bytes)", E.sct_len);
}

/* B1/B2: free-running producer. touch=0 only advances tail. */
static void bench_throughput(struct kim_ctx *c, int touch, double secs, uint32_t chunk)
{
	uint64_t bytes = 0, t0, t1, *age = NULL, nage = 0, cap = 1u << 20, sink = 0;

	if (touch) age = malloc(cap * sizeof(*age));
	drain_idle(c);
	set_interval(c, 0);
	t0 = kim_now_ns();
	do {
		struct kim_chunk ck;
		uint32_t n = kim_peek_chunk(c, chunk, &ck);

		if (!n) { kim_wait(c, 1); t1 = kim_now_ns(); continue; }
		if (touch) {
			if (nage < cap) age[nage++] = kim_now_ns() - ck.first->timestamp_ns;
			sink ^= kim_xor_checksum(ck.data, ck.bytes);
		}
		bytes += ck.bytes;
		kim_consume(c, n);
		t1 = kim_now_ns();
	} while ((t1 - t0) / 1e9 < secs);
	set_interval(c, 1000);

	printf("  %s chunk=%3u KiB : %6.2f GB/s (%.0f MiB in %.2fs)", touch ? "ingest+AVX2" : "producer    ",
	       chunk / 1024, bytes / ((t1 - t0) / 1e9) / 1e9, bytes / 1048576.0, (t1 - t0) / 1e9);
	if (touch)
		printf(" | frame age p50 %.1f us p99 %.1f us max %.1f us (saturated ring) [x=%llx]",
		       pct(age, nage, 0.50) / 1e3, pct(age, nage, 0.99) / 1e3, pct(age, nage, 1.0) / 1e3,
		       (unsigned long long)(sink & 0xff));
	putchar('\n');
	free(age);
}

static void bench_kick_latency(struct kim_ctx *c)
{
	enum { N = 100 };
	uint64_t lat[N];
	int i;

	set_interval(c, 60000);
	drain_idle(c);
	for (i = 0; i < N; i++) {
		struct kim_chunk ck;
		uint64_t t0, t1, start = c->hdr->epochs_done;

		t0 = kim_now_ns();
		ioctl(c->fd, KIM_IOC_KICK);
		while (!kim_peek_chunk(c, KIM_CHUNK_E_CORE, &ck)) kim_wait(c, 1);
		t1 = kim_now_ns();
		lat[i] = t1 - t0;
		/* finish the epoch so the next kick starts a fresh one */
		while (__atomic_load_n(&c->hdr->epochs_done, __ATOMIC_ACQUIRE) == start || kim_available(c)) {
			uint64_t a = kim_available(c);

			if (a) kim_consume(c, (uint32_t)a); else usleep(200);
		}
	}
	set_interval(c, 1000);
	printf("  kick -> first frame : p50 %.1f us  p99 %.1f us  max %.1f us (n=%d)\n",
	       pct(lat, N, 0.5) / 1e3, pct(lat, N, 0.99) / 1e3, pct(lat, N, 1.0) / 1e3, N);
}

int main(void)
{
	struct kim_ctx c;
	int rc = kim_ctx_open(&c, KIM_DEV_PATH);

	if (rc) {
		fprintf(stderr, "cannot open %s: %s (run as root, insmod kernel_extractor.ko)\n",
			KIM_DEV_PATH, strerror(-rc));
		return 2;
	}
	set_interval(&c, 60000);
	drain_idle(&c);

	t_header(&c);
	t_mmap_hardening(&c);
	t_epoch(&c);
	t_symbols(&c);
	t_sct(&c);
	t_direct(&c);

	puts("\nBenchmarks");
	bench_throughput(&c, 0, 3.0, KIM_CHUNK_P_CORE);
	bench_throughput(&c, 1, 3.0, KIM_CHUNK_E_CORE);
	bench_throughput(&c, 1, 3.0, KIM_CHUNK_P_CORE);
	bench_throughput(&c, 1, 3.0, KIM_CHUNK_P_MAX);
	bench_kick_latency(&c);

	printf("\n%d passed, %d failed, %d skipped | ring_full_events=%llu | direct_frames=%llu remap_frames=%llu\n",
	       g_pass, g_fail, g_skip, (unsigned long long)c.hdr->ring_full_events,
	       (unsigned long long)c.hdr->direct_frames, (unsigned long long)c.hdr->remap_frames);
	kim_ctx_close(&c);
	return g_fail ? 1 : 0;
}
