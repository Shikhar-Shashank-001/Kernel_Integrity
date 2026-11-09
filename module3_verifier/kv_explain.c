// SPDX-License-Identifier: GPL-2.0
/*
 * kv_explain.c - kallsyms symbolisation and changed-frame explanation
 * (see kv_explain.h)
 */
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kv_explain.h"

#define KV_MAX_SYM_SIZE (1u << 20)      /* larger "symbols" are gaps, not code */
#define KV_MAX_RANGES   12              /* changed ranges described per frame  */
#define KV_MERGE_GAP    4               /* bytes between diffs merged into one */

struct kv_sym {
	uint64_t addr;
	uint32_t name;          /* offsets into str */
	uint32_t mod;           /* 0 = vmlinux      */
};

struct kv_syms {
	struct kv_sym *v;
	size_t         n;
	char          *str;
	size_t         len, cap;
};

static uint32_t str_add(struct kv_syms *s, const char *p)
{
	size_t l = strlen(p) + 1;
	uint32_t off;

	if (s->len + l > s->cap) {
		size_t cap = s->cap ? s->cap * 2 : 1 << 20;
		char *n;

		while (cap < s->len + l)
			cap *= 2;
		n = realloc(s->str, cap);
		if (!n)
			return 0;
		s->str = n;
		s->cap = cap;
	}
	off = (uint32_t)s->len;
	memcpy(s->str + off, p, l);
	s->len += l;
	return off;
}

static int sym_cmp(const void *a, const void *b)
{
	const struct kv_sym *x = a, *y = b;

	return x->addr < y->addr ? -1 : x->addr > y->addr;
}

struct kv_syms *kv_syms_load(const char *path)
{
	struct kv_syms *s = calloc(1, sizeof(*s));
	char line[512], name[256], mod[128], lastmod[128] = "";
	uint32_t lastmod_off = 0;
	size_t cap = 0;
	FILE *f;

	if (!s)
		return NULL;
	f = fopen(path ? path : "/proc/kallsyms", "r");
	if (!f) {
		free(s);
		return NULL;
	}
	str_add(s, "");                         /* offset 0 = no module */
	while (fgets(line, sizeof(line), f)) {
		unsigned long long a;
		char type;
		int k;

		mod[0] = '\0';
		k = sscanf(line, "%llx %c %255s [%127[^]]]", &a, &type, name, mod);
		if (k < 3 || !a)
			continue;
		if (s->n == cap) {
			struct kv_sym *v = realloc(s->v, (cap ? cap * 2 : 65536) * sizeof(*v));

			if (!v)
				break;
			s->v = v;
			cap = cap ? cap * 2 : 65536;
		}
		s->v[s->n].addr = a;
		s->v[s->n].name = str_add(s, name);
		if (mod[0] && strcmp(mod, lastmod)) {   /* module symbols come grouped */
			snprintf(lastmod, sizeof(lastmod), "%s", mod);
			lastmod_off = str_add(s, mod);
		}
		s->v[s->n].mod = mod[0] ? lastmod_off : 0;
		s->n++;
	}
	fclose(f);
	if (!s->n) {                            /* addresses hidden: useless */
		kv_syms_free(s);
		return NULL;
	}
	qsort(s->v, s->n, sizeof(*s->v), sym_cmp);
	return s;
}

void kv_syms_free(struct kv_syms *s)
{
	if (!s)
		return;
	free(s->v);
	free(s->str);
	free(s);
}

size_t kv_syms_count(const struct kv_syms *s)
{
	return s ? s->n : 0;
}

int kv_syms_lookup(const struct kv_syms *s, uint64_t addr, char *buf, size_t n,
		   uint64_t *start, uint64_t *end)
{
	size_t lo = 0, hi;
	const struct kv_sym *k;
	uint64_t e;

	if (n)
		snprintf(buf, n, "?");
	if (!s || !s->n || addr < s->v[0].addr)
		return -1;
	hi = s->n;
	while (hi - lo > 1) {                   /* last symbol with addr <= target */
		size_t mid = (lo + hi) / 2;

		if (s->v[mid].addr <= addr)
			lo = mid;
		else
			hi = mid;
	}
	while (lo + 1 < s->n && s->v[lo + 1].addr == s->v[lo].addr)
		lo++;                           /* aliases: take the last one */
	k = &s->v[lo];
	e = lo + 1 < s->n ? s->v[lo + 1].addr : k->addr + 1;
	if (addr >= e || e - k->addr > KV_MAX_SYM_SIZE)
		return -1;
	if (n)
		snprintf(buf, n, "%s+0x%llx/0x%llx%s%s%s", s->str + k->name,
			 (unsigned long long)(addr - k->addr), (unsigned long long)(e - k->addr),
			 k->mod ? " [" : "", k->mod ? s->str + k->mod : "", k->mod ? "]" : "");
	if (start)
		*start = k->addr;
	if (end)
		*end = e;
	return 0;
}

const char *kv_verdict_name(enum kv_verdict v)
{
	static const char *const n[] = { "patch-like", "unexplained", "no-bytes" };

	return v <= KV_X_NO_BYTES ? n[v] : "?";
}

/* ------------------------------------------------------------------ */
struct out { char *p; size_t n, used; };

static void emit(struct out *o, const char *fmt, ...)
{
	va_list ap;
	int r;

	if (o->used + 1 >= o->n)
		return;
	va_start(ap, fmt);
	r = vsnprintf(o->p + o->used, o->n - o->used, fmt, ap);
	va_end(ap);
	if (r > 0)
		o->used += (size_t)r < o->n - o->used ? (size_t)r : o->n - o->used - 1;
}

static void hexbytes(char *buf, const uint8_t *p, uint32_t n)
{
	static const char hx[] = "0123456789abcdef";
	uint32_t i;

	for (i = 0; i < n && i < 16; i++) {
		buf[2 * i] = hx[p[i] >> 4];
		buf[2 * i + 1] = hx[p[i] & 15];
	}
	buf[2 * i] = '\0';
}

static bool is_nop5(const uint8_t *p)
{
	static const uint8_t nop5[5] = { 0x0f, 0x1f, 0x44, 0x00, 0x00 };

	return !memcmp(p, nop5, 5);
}

static bool is_nop2(const uint8_t *p)
{
	return p[0] == 0x66 && p[1] == 0x90;
}

static uint64_t rel_target(uint64_t va, const uint8_t *insn, int len)
{
	int32_t r32;

	if (len == 2)
		return va + 2 + (int64_t)(int8_t)insn[1];
	memcpy(&r32, insn + 1, 4);
	return va + 5 + (int64_t)r32;
}

static bool trampoline_name(const char *sym)
{
	return strstr(sym, "ftrace") || strstr(sym, "trampoline") || strstr(sym, "bpf") ||
	       strstr(sym, "fentry");
}

/*
 * Decode the patched 5- or 2-byte branch instruction that covers offset a
 * (start p with p <= a < p + len). Returns its end offset p + len and
 * describes it, or 0 if the bytes match no known patch pattern.
 * nop<->branch transitions are tried before retargets in every form: a
 * transition matches 2-5 specific bytes, a retarget only one unchanged opcode
 * byte, so an unrelated 0xe9/0xe8 byte up to 4 before a jmp8->nop2 site would
 * otherwise win as a bogus 5-byte "jmp retarget" (seen in the 2026-11-06 soak).
 */
static uint32_t decode_one(const struct kv_syms *s, uint64_t va0, const uint8_t *old,
			   const uint8_t *cur, uint32_t flen, uint32_t a,
			   struct out *o, bool *plausible)
{
	static const struct { int len; uint8_t op; } forms[] = {
		{ 5, 0xe9 }, { 5, 0xe8 }, { 2, 0xeb },
	};
	unsigned int f, pass;
	uint32_t p;

	for (pass = 0; pass < 2; pass++)
	for (f = 0; f < sizeof(forms) / sizeof(forms[0]); f++) {
		uint32_t len = (uint32_t)forms[f].len;
		uint8_t op = forms[f].op;

		for (p = a >= len - 1 ? a - (len - 1) : 0; p <= a; p++) {
			bool old_nop, cur_nop, old_br, cur_br;
			const uint8_t *br;
			uint64_t site = va0 + p, tgt, fs = 0, fe = 0;
			char ssym[160], tsym[160];
			const char *what;
			int site_ok, tgt_ok;

			if (p + len > flen)
				continue;
			old_nop = len == 5 ? is_nop5(old + p) : is_nop2(old + p);
			cur_nop = len == 5 ? is_nop5(cur + p) : is_nop2(cur + p);
			old_br = old[p] == op;
			cur_br = cur[p] == op;
			if (pass == 0 && old_nop && cur_br) {
				what = op == 0xe8 ? "nop5->call" : len == 5 ? "nop5->jmp" : "nop2->jmp8";
				br = cur + p;
			} else if (pass == 0 && old_br && cur_nop) {
				what = op == 0xe8 ? "call->nop5" : len == 5 ? "jmp->nop5" : "jmp8->nop2";
				br = old + p;
			} else if (pass == 1 && old_br && cur_br) {
				what = op == 0xe8 ? "call retarget" : "jmp retarget";
				br = cur + p;
			} else {
				continue;
			}
			tgt = rel_target(site, br, (int)len);
			site_ok = kv_syms_lookup(s, site, ssym, sizeof(ssym), &fs, &fe);
			tgt_ok = kv_syms_lookup(s, tgt, tsym, sizeof(tsym), NULL, NULL);
			if (old_br && cur_br)    /* static_call / ftrace_call switch */
				*plausible = !site_ok && !tgt_ok;
			else if (op == 0xe8)     /* entry call: ftrace/BPF attach */
				*plausible = !site_ok && !tgt_ok && site - fs <= 16 &&
					     trampoline_name(tsym);
			else                     /* jump label: branch inside the function */
				*plausible = !site_ok && tgt >= fs && tgt < fe;
			emit(o, " %s target=%s%s", what, tsym,
			     *plausible ? "" : " (implausible target)");
			if (old_br && cur_br) {
				char osym[160];

				kv_syms_lookup(s, rel_target(site, old + p, (int)len), osym,
					       sizeof(osym), NULL, NULL);
				emit(o, " was=%s", osym);
			}
			return p + len;
		}
	}
	return 0;
}

/* A changed range may hold several adjacent patch sites (e.g. nop5 + nop2,
 * or three nop2 jump labels back to back): decode them one after another. */
static bool decode_range(const struct kv_syms *s, uint64_t va0, const uint8_t *old,
			 const uint8_t *cur, uint32_t flen, uint32_t a, uint32_t b,
			 struct out *o)
{
	bool all = true, first = true;
	uint32_t q = a;

	while (q < b) {
		bool plausible = false;
		uint32_t end;

		if (!first)
			emit(o, ";");
		first = false;
		end = decode_one(s, va0, old, cur, flen, q, o, &plausible);
		if (!end) {
			emit(o, " unrecognised");
			return false;
		}
		all &= plausible;
		for (q = end; q < b && old[q] == cur[q]; q++)
			;
	}
	return all;
}

static enum kv_verdict explain_table(const struct kv_syms *s, const struct kim_desc *d,
				     const uint8_t *old, const uint8_t *cur, struct out *o)
{
	uint32_t i, shown = 0, total = 0;

	for (i = 0; i + 8 <= d->length; i += 8) {
		uint64_t a, b;
		char sa[160], sb[160];

		memcpy(&a, old + i, 8);
		memcpy(&b, cur + i, 8);
		if (a == b)
			continue;
		total++;
		if (shown++ >= KV_MAX_RANGES)
			continue;
		kv_syms_lookup(s, a, sa, sizeof(sa), NULL, NULL);
		kv_syms_lookup(s, b, sb, sizeof(sb), NULL, NULL);
		emit(o, "\n  %s[%u]: %s -> %s", d->name, (d->seg_offset + i) / 8, sa, sb);
	}
	emit(o, "\n  %u table entries changed (tables are read-only: always unexplained)", total);
	return KV_X_UNEXPLAINED;
}

enum kv_verdict kv_explain_frame(const struct kv_syms *s, const struct kim_desc *d,
				 const uint8_t *old, const uint8_t *cur,
				 char *outbuf, size_t n)
{
	struct out o = { outbuf, n, 0 };
	enum kv_verdict v = KV_X_PATCH_LIKE;
	uint32_t i = 0, ranges = 0, bytes = 0;

	if (n)
		outbuf[0] = '\0';
	if (!old || !cur) {
		emit(&o, "  baseline bytes not kept: frame-level change only");
		return KV_X_NO_BYTES;
	}
	if (d->segment_type == KIM_SEG_SYSCALL_TABLE || d->segment_type == KIM_SEG_COMPAT_TABLE)
		return explain_table(s, d, old, cur, &o);

	while (i < d->length) {
		uint32_t a, b;
		char site[160], ob[33], nb[33];
		struct out none = { NULL, 0, 0 }, *po;

		if (old[i] == cur[i]) {
			i++;
			continue;
		}
		a = i;
		b = i + 1;
		for (i = b; i < d->length && i < b + KV_MERGE_GAP; i++)
			if (old[i] != cur[i])
				b = i + 1;
		i = b;
		ranges++;
		bytes += b - a;
		/* every range counts for the verdict; only the first few are printed */
		po = ranges <= KV_MAX_RANGES ? &o : &none;
		kv_syms_lookup(s, d->base_address + a, site, sizeof(site), NULL, NULL);
		hexbytes(ob, old + a, b - a);
		hexbytes(nb, cur + a, b - a);
		emit(po, "\n  +0x%x %s (%u B): %s -> %s%s", d->seg_offset + a, site, b - a, ob, nb,
		     b - a > 16 ? "..." : "");
		if (!decode_range(s, d->base_address, old, cur, d->length, a, b, po))
			v = KV_X_UNEXPLAINED;
	}
	emit(&o, "\n  %u changed range(s), %u byte(s)%s", ranges, bytes,
	     ranges > KV_MAX_RANGES ? " (list truncated)" : "");
	return v;
}
