// SPDX-License-Identifier: GPL-2.0
/*
 * test_baseline.c - learn / re-verify / explain tests (no root needed).
 *
 * Synthetic scans of a small "kernel" (3-frame text, 2-entry syscall table,
 * two modules) are tagged with the real AES-GCM-SIV engine and fed to the
 * baseline engine epoch by epoch, with a mock kallsyms:
 *
 *   E1-E2   learn                              -> LEARNED, nothing else
 *   E3      unchanged                          -> no events
 *   E4-E5   func_a+0x10 nop5 -> jmp func_a+0x40 -> CHANGED (patch-like) on E5 only
 *   E6      reverted                           -> REVERTED
 *   E7-E8   one byte flipped for one scan      -> TRANSIENT
 *   E9-E10  func_b+4 nop5 -> call ftrace_caller -> CHANGED patch-like
 *           func_a+0x20 nop5 -> call evil_hook  -> CHANGED unexplained
 *   E11-E12 sys_call_table[0] -> evil_hook      -> CHANGED unexplained
 *   E12     modA gone                          -> VANISHED
 *   E13     modB loaded, ktext W PTE, fault    -> NEW_SEGMENT, WX, FAULT (once)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "kv_baseline.h"
#include "kv_tag.h"

static int g_fail, g_pass;
#define PASS(...) do { g_pass++; printf("  [PASS] "); printf(__VA_ARGS__); putchar('\n'); } while (0)
#define FAIL(...) do { g_fail++; printf("  [FAIL] "); printf(__VA_ARGS__); putchar('\n'); } while (0)
#define CHECK(c, ...) do { if (c) PASS(__VA_ARGS__); else FAIL(__VA_ARGS__); } while (0)

#define FR     KIM_FRAME_BYTES
#define KBASE  0xffffffff81000000ull
#define SBASE  0xffffffff82000000ull
#define MBASE  0xffffffffc0100000ull
#define EVIL   0xffffffffc0001000ull

/* symbol offsets inside the fake kernel text */
#define FUNC_A  0x1000u
#define FUNC_B  0x5000u
#define FTRACE  0x9000u
#define SYSRD   0x9100u
#define SYSWR   0x9200u

static const char *KALLSYMS =
	"ffffffff81000000 T _stext\n"
	"ffffffff81001000 T func_a\n"
	"ffffffff81001100 t func_a_cold\n"
	"ffffffff81005000 T func_b\n"
	"ffffffff81005200 t func_c\n"
	"ffffffff81009000 T ftrace_caller\n"
	"ffffffff81009100 T __x64_sys_read\n"
	"ffffffff81009200 T __x64_sys_write\n"
	"ffffffff8100c000 T _etext\n"
	"ffffffffc0001000 t evil_hook\t[rootkit]\n"
	"ffffffffc0001100 t evil_helper\t[rootkit]\n";

/* ------------------------------------------------------------------ */
struct rec {
	enum kv_ev_type type;
	uint32_t epoch, seg, off;
	enum kv_verdict verdict;
	char detail[2048];
};

static struct rec g_ev[256];
static int g_nev;

static void on_event(const struct kv_event *ev, void *arg)
{
	struct rec *r = &g_ev[g_nev < 255 ? g_nev++ : 255];

	(void)arg;
	r->type = ev->type;
	r->epoch = ev->epoch;
	r->seg = ev->desc.segment_id;
	r->off = ev->desc.seg_offset;
	r->verdict = ev->verdict;
	snprintf(r->detail, sizeof(r->detail), "%s", ev->detail ? ev->detail : "");
	if (getenv("KV_VERBOSE"))
		printf("    event %-11s epoch %2u seg %u +0x%x %s%s\n", kv_ev_name(ev->type), ev->epoch,
		       r->seg, r->off, kv_verdict_name(ev->verdict), r->detail);
}

static int count(enum kv_ev_type t, uint32_t epoch)
{
	int i, n = 0;

	for (i = 0; i < g_nev; i++)
		n += g_ev[i].type == t && (!epoch || g_ev[i].epoch == epoch);
	return n;
}

static const struct rec *find(enum kv_ev_type t, uint32_t epoch, uint32_t seg, uint32_t off)
{
	int i;

	for (i = 0; i < g_nev; i++)
		if (g_ev[i].type == t && g_ev[i].epoch == epoch && g_ev[i].seg == seg &&
		    g_ev[i].off == off)
			return &g_ev[i];
	return NULL;
}

static int events_in(uint32_t epoch)
{
	int i, n = 0;

	for (i = 0; i < g_nev; i++)
		n += g_ev[i].epoch == epoch;
	return n;
}

/* ------------------------------------------------------------------ */
static const uint8_t ENDBR[4] = { 0xf3, 0x0f, 0x1e, 0xfa };
static const uint8_t NOP5[5] = { 0x0f, 0x1f, 0x44, 0x00, 0x00 };

static void put_branch(uint8_t *buf, uint64_t base, uint32_t off, uint8_t op, uint64_t target)
{
	int32_t rel = (int32_t)(target - (base + off + 5));

	buf[off] = op;
	memcpy(buf + off + 1, &rel, 4);
}

/* Kernel text as it looks in a given epoch. */
static void build_ktext(uint8_t *t, uint32_t e)
{
	uint32_t i;

	for (i = 0; i < 3 * FR; i++)
		t[i] = (uint8_t)(i * 7 + 0x41);
	memcpy(t + FUNC_A, ENDBR, 4);
	memcpy(t + FUNC_A + 0x10, NOP5, 5);     /* jump-label site       */
	memcpy(t + FUNC_A + 0x20, NOP5, 5);     /* site the attacker uses */
	memcpy(t + FUNC_B, ENDBR, 4);
	memcpy(t + FUNC_B + 4, NOP5, 5);        /* ftrace site            */

	if (e == 4 || e == 5)
		put_branch(t, KBASE, FUNC_A + 0x10, 0xe9, KBASE + FUNC_A + 0x40);
	if (e == 7)
		t[FTRACE + 0x50] ^= 0xff;
	if (e >= 9) {
		put_branch(t, KBASE, FUNC_B + 4, 0xe8, KBASE + FTRACE);
		put_branch(t, KBASE, FUNC_A + 0x20, 0xe8, EVIL);
	}
}

static void build_sct(uint8_t *t, uint32_t e)
{
	uint64_t ent[2] = { KBASE + SYSRD, KBASE + SYSWR };

	if (e >= 11)
		ent[0] = EVIL;
	memcpy(t, ent, sizeof(ent));
}

static void feed_seg(struct kv_baseline *b, const struct kv_key *k, uint32_t id, uint32_t type,
		     const char *name, uint64_t base, const uint8_t *data, uint32_t len, uint32_t e,
		     uint16_t flags_first)
{
	uint32_t off;

	for (off = 0; off < len; off += FR) {
		struct kim_desc d;
		uint8_t tag[16];

		memset(&d, 0, sizeof(d));
		d.base_address = base + off;
		d.segment_type = type;
		d.segment_id = id;
		d.length = len - off < FR ? len - off : FR;
		d.seg_length = len;
		d.seg_offset = off;
		d.scan_epoch = e;
		d.flags = (off == 0 ? KIM_F_FIRST | flags_first : 0) |
			  (off + d.length >= len ? KIM_F_LAST : 0);
		snprintf(d.name, sizeof(d.name), "%s", name);
		kv_frame_tag(k, &d, data + off, tag);
		kv_baseline_frame(b, &d, tag, data + off);
	}
}

static void scan(struct kv_baseline *b, const struct kv_key *k, uint32_t e)
{
	static uint8_t ktext[3 * FR], sct[16], moda[20000], modb[5000];
	uint32_t i;

	build_ktext(ktext, e);
	build_sct(sct, e);
	for (i = 0; i < sizeof(moda); i++)
		moda[i] = (uint8_t)(i * 13);
	for (i = 0; i < sizeof(modb); i++)
		modb[i] = (uint8_t)(i * 17);

	feed_seg(b, k, 1, KIM_SEG_KTEXT, "ktext", KBASE, ktext, sizeof(ktext), e,
		 e >= 13 ? KIM_F_PTE_W | KIM_F_FAULT | KIM_F_REMAP : 0);
	feed_seg(b, k, 2, KIM_SEG_SYSCALL_TABLE, "sys_call_table", SBASE, sct, sizeof(sct), e, 0);
	if (e < 12)
		feed_seg(b, k, 3, KIM_SEG_MOD_TEXT, "modA", MBASE, moda, sizeof(moda), e, 0);
	if (e >= 13)
		feed_seg(b, k, 4, KIM_SEG_MOD_TEXT, "modB", MBASE + 0x100000, modb, sizeof(modb), e, 0);
	kv_baseline_epoch_end(b, e, false);
}

static char *write_kallsyms(const char *body)
{
	const char *tmp = getenv("TMPDIR");
	char *path;
	int fd;

	if (asprintf(&path, "%s/kv_kallsyms.XXXXXX", tmp ? tmp : "/tmp") < 0)
		exit(2);
	fd = mkstemp(path);
	if (fd < 0 || write(fd, body, strlen(body)) != (ssize_t)strlen(body))
		exit(2);
	close(fd);
	return path;
}

/* ------------------------------------------------------------------ */
static void t_symbols(const char *ks)
{
	struct kv_syms *s = kv_syms_load(ks);
	char buf[160];
	uint64_t st = 0, en = 0;
	char *hidden;

	puts("X1 kallsyms symbolisation");
	CHECK(s && kv_syms_count(s) == 11, "mock kallsyms loaded (%zu symbols)", kv_syms_count(s));
	CHECK(!kv_syms_lookup(s, KBASE + FUNC_A + 0x10, buf, sizeof(buf), &st, &en) &&
	      !strcmp(buf, "func_a+0x10/0x100") && st == KBASE + FUNC_A && en == KBASE + 0x1100,
	      "func_a+0x10 -> \"%s\" with bounds", buf);
	CHECK(!kv_syms_lookup(s, EVIL + 8, buf, sizeof(buf), NULL, NULL) &&
	      !strcmp(buf, "evil_hook+0x8/0x100 [rootkit]"), "module symbol -> \"%s\"", buf);
	CHECK(kv_syms_lookup(s, KBASE + 0x5000000, buf, sizeof(buf), NULL, NULL) == -1 &&
	      kv_syms_lookup(s, 0x1000, buf, sizeof(buf), NULL, NULL) == -1 && !strcmp(buf, "?"),
	      "addresses in gaps / below all symbols -> \"?\"");
	kv_syms_free(s);

	hidden = write_kallsyms("0000000000000000 T _stext\n0000000000000000 T func_a\n");
	CHECK(kv_syms_load(hidden) == NULL, "kallsyms with hidden addresses (non-root) -> NULL");
	unlink(hidden);
	free(hidden);
}

/* Patterns seen on the real kernel (live_check.sh, 2026-10-29). */
static void t_patterns(const char *ks)
{
	static uint8_t old[FR], cur[FR];
	static const uint8_t NOP2[2] = { 0x66, 0x90 };
	struct kv_syms *s = kv_syms_load(ks);
	struct kim_desc d;
	char out[4096];
	enum kv_verdict v;
	uint32_t i, k;

	puts("X2 explanation of real-kernel patch patterns");
	memset(&d, 0, sizeof(d));
	d.base_address = KBASE;
	d.segment_type = KIM_SEG_KTEXT;
	d.length = FR;
	d.seg_length = 3 * FR;
	snprintf(d.name, sizeof(d.name), "ktext");
#define RESET() do { for (i = 0; i < FR; i++) old[i] = (uint8_t)(i * 7 + 0x41); } while (0)
#define JMP8(buf, off, tgt) do { (buf)[off] = 0xeb; (buf)[(off) + 1] = (uint8_t)((tgt) - ((off) + 2)); } while (0)

	/* three nop2 jump labels back to back (sched: normalize_rt_tasks) */
	RESET();
	for (k = 0; k < 3; k++)
		memcpy(old + FUNC_A + 0x30 + 2 * k, NOP2, 2);
	memcpy(cur, old, FR);
	for (k = 0; k < 3; k++)
		JMP8(cur, FUNC_A + 0x30 + 2 * k, FUNC_A + 0x70 + 4 * k);
	v = kv_explain_frame(s, &d, old, cur, out, sizeof(out));
	CHECK(v == KV_X_PATCH_LIKE && strstr(out, "nop2->jmp8") &&
	      strstr(strstr(strstr(out, "nop2->jmp8") + 1, "nop2->jmp8") + 1, "nop2->jmp8"),
	      "3 adjacent nop2->jmp8 sites decoded one by one: patch-like");

	/* nop5 then nop2 (sched: wake_affine) */
	RESET();
	memcpy(old + FUNC_A + 0x60, NOP5, 5);
	memcpy(old + FUNC_A + 0x65, NOP2, 2);
	memcpy(cur, old, FR);
	put_branch(cur, KBASE, FUNC_A + 0x60, 0xe9, KBASE + FUNC_A + 0xe0);
	JMP8(cur, FUNC_A + 0x65, FUNC_A + 0xc0);
	v = kv_explain_frame(s, &d, old, cur, out, sizeof(out));
	CHECK(v == KV_X_PATCH_LIKE && strstr(out, "nop5->jmp") && strstr(out, "nop2->jmp8"),
	      "adjacent nop5 + nop2 jump labels: patch-like");

	/* jmp8->nop2 with an unchanged 0xe9 byte 3 before it (soak 2026-11-06,
	 * udp_destroy_sock eb20 -> 6690): not a 5-byte "jmp retarget" */
	RESET();
	JMP8(old, FUNC_A + 0x36, FUNC_A + 0x58);
	old[FUNC_A + 0x33] = 0xe9;
	memcpy(cur, old, FR);
	memcpy(cur + FUNC_A + 0x36, NOP2, 2);
	v = kv_explain_frame(s, &d, old, cur, out, sizeof(out));
	CHECK(v == KV_X_PATCH_LIKE && strstr(out, "jmp8->nop2") && !strstr(out, "retarget"),
	      "jmp8->nop2 behind a stray 0xe9 byte: transition wins over retarget");

	/* func_b lives in frame 1 */
	d.base_address = KBASE + FR;
	d.seg_offset = FR;

	/* tracepoint static call / ftrace_call switched between kernel functions */
	RESET();
	put_branch(old, KBASE + FR, FUNC_B - FR + 0x40, 0xe8, KBASE + SYSRD);
	memcpy(cur, old, FR);
	put_branch(cur, KBASE + FR, FUNC_B - FR + 0x40, 0xe8, KBASE + SYSWR);
	v = kv_explain_frame(s, &d, old, cur, out, sizeof(out));
	CHECK(v == KV_X_PATCH_LIKE && strstr(out, "call retarget target=__x64_sys_write") &&
	      strstr(out, "was=__x64_sys_read"), "mid-function call retarget between known symbols: patch-like");

	/* call retarget to an address no symbol covers */
	memcpy(cur, old, FR);
	put_branch(cur, KBASE + FR, FUNC_B - FR + 0x40, 0xe8, KBASE + 0x5000000);
	v = kv_explain_frame(s, &d, old, cur, out, sizeof(out));
	CHECK(v == KV_X_UNEXPLAINED && strstr(out, "target=?"), "retarget into unknown memory: unexplained");

	/* a valid jump label followed by bytes that are no branch at all (frame 0) */
	d.base_address = KBASE;
	d.seg_offset = 0;
	RESET();
	memcpy(old + FUNC_A + 0x30, NOP2, 2);
	memcpy(old + FUNC_A + 0x32, NOP2, 2);
	memcpy(cur, old, FR);
	JMP8(cur, FUNC_A + 0x30, FUNC_A + 0x70);
	cur[FUNC_A + 0x32] = 0xcc;
	cur[FUNC_A + 0x33] = 0xcc;
	v = kv_explain_frame(s, &d, old, cur, out, sizeof(out));
	CHECK(v == KV_X_UNEXPLAINED && strstr(out, "nop2->jmp8") && strstr(out, "unrecognised"),
	      "legit site next to injected int3 bytes: unexplained");

	/* 14 separate jump labels in one frame (func_b, frame 1): verdict uses
	 * all of them, the printed list is capped */
	d.base_address = KBASE + FR;
	d.seg_offset = FR;
	RESET();
	for (k = 0; k < 14; k++)
		memcpy(old + FUNC_B - FR + 0x10 + 16 * k, NOP2, 2);
	memcpy(cur, old, FR);
	for (k = 0; k < 14; k++)
		JMP8(cur, FUNC_B - FR + 0x10 + 16 * k, FUNC_B - FR + 0x18 + 16 * k);
	v = kv_explain_frame(s, &d, old, cur, out, sizeof(out));
	CHECK(v == KV_X_PATCH_LIKE && strstr(out, "14 changed range(s)") && strstr(out, "truncated"),
	      "14 sites in one frame: patch-like, printed list truncated");
	cur[FUNC_B - FR + 0x10 + 16 * 13] = 0xcc;      /* last site becomes an int3 */
	v = kv_explain_frame(s, &d, old, cur, out, sizeof(out));
	CHECK(v == KV_X_UNEXPLAINED, "implausible site beyond the printed list still counts");
#undef JMP8
#undef RESET
	kv_syms_free(s);
}

static void t_scenario(const char *ks)
{
	struct kv_baseline_cfg cfg = { 2, 1, true, ks, on_event, NULL };
	struct kv_baseline_stats st;
	struct kv_baseline *b;
	const struct rec *r, *r2;
	struct kv_key k;
	uint8_t key[32] = { 9 };
	uint32_t e;

	puts("B1 learn / re-verify / explain scenario");
	kv_key_init(&k, key, 32, NULL, KV_IMPL_AUTO);
	b = kv_baseline_new(&cfg);
	for (e = 1; e <= 14; e++)
		scan(b, &k, e);

	CHECK(count(KV_EV_LEARNED, 2) == 1 && events_in(1) == 0 && events_in(2) == 1,
	      "learning: LEARNED after epoch 2, no other events");
	r = find(KV_EV_LEARNED, 2, 0, 0);
	CHECK(r && strstr(r->detail, "3 segments") && strstr(r->detail, "0 unstable"),
	      "summary: %s", r ? r->detail : "-");
	CHECK(events_in(3) == 0 && events_in(4) == 0,
	      "unchanged scan and first differing scan raise nothing (re-verify)");
	r = find(KV_EV_CHANGED, 5, 1, 0);
	CHECK(r && r->verdict == KV_X_PATCH_LIKE && strstr(r->detail, "nop5->jmp") &&
	      strstr(r->detail, "func_a+0x10/") && strstr(r->detail, "target=func_a+0x40/"),
	      "jump-label patch confirmed on 2nd scan, explained as patch-like");
	CHECK(find(KV_EV_REVERTED, 6, 1, 0) != NULL, "revert reported");
	CHECK(find(KV_EV_TRANSIENT, 8, 1, 2 * FR) != NULL && count(KV_EV_CHANGED, 7) == 0 &&
	      count(KV_EV_CHANGED, 8) == 0, "one-scan glitch reported as TRANSIENT, never CHANGED");
	r = find(KV_EV_CHANGED, 10, 1, FR);
	CHECK(r && r->verdict == KV_X_PATCH_LIKE && strstr(r->detail, "nop5->call") &&
	      strstr(r->detail, "target=ftrace_caller"), "ftrace attach at func_b entry: patch-like");
	r2 = find(KV_EV_CHANGED, 10, 1, 0);
	CHECK(r2 && r2->verdict == KV_X_UNEXPLAINED && strstr(r2->detail, "nop5->call") &&
	      strstr(r2->detail, "evil_hook") && strstr(r2->detail, "implausible"),
	      "mid-function call into [rootkit]: unexplained");
	r = find(KV_EV_CHANGED, 12, 2, 0);
	CHECK(r && r->verdict == KV_X_UNEXPLAINED &&
	      strstr(r->detail, "sys_call_table[0]: __x64_sys_read+0x0/0x100 -> evil_hook+0x0/0x100 [rootkit]"),
	      "syscall table hijack: entry, old and new target named");
	CHECK(find(KV_EV_VANISHED, 12, 3, 0) != NULL, "unloaded module reported VANISHED");
	CHECK(find(KV_EV_NEW_SEGMENT, 13, 4, 0) != NULL && count(KV_EV_CHANGED, 14) == 0,
	      "module loaded after learning: NEW_SEGMENT, then learned (no CHANGED)");
	CHECK(count(KV_EV_WX, 0) == 1 && count(KV_EV_FAULT, 0) == 1 && count(KV_EV_REMAP, 0) == 1,
	      "W^X, fault and remap alarms raised once per frame, not every scan");
	CHECK(count(KV_EV_CHANGED, 11) == 0 && count(KV_EV_CHANGED, 13) == 0 &&
	      count(KV_EV_CHANGED, 14) == 0, "persisting changes are not re-reported every scan");

	kv_baseline_get_stats(b, &st);
	CHECK(st.checking && st.frames_changed == 3 && st.segments == 3 &&
	      st.bytes_kept == 3 * FR + 16 + 5000,
	      "stats: %llu frames in CHANGED, %llu segments, %llu bytes kept",
	      (unsigned long long)st.frames_changed, (unsigned long long)st.segments,
	      (unsigned long long)st.bytes_kept);
	kv_baseline_free(b);
	kv_key_wipe(&k);
}

static void t_variants(const char *ks)
{
	struct kv_baseline_cfg cfg = { 3, 1, true, ks, on_event, NULL };
	struct kv_baseline *b;
	struct kv_key k;
	uint8_t key[16] = { 5 };
	uint32_t e;

	puts("B2 variants");
	kv_key_init(&k, key, 16, NULL, KV_IMPL_AUTO);

	/* change during learning: UNSTABLE once, latest content becomes baseline */
	g_nev = 0;
	b = kv_baseline_new(&cfg);
	scan(b, &k, 1);
	scan(b, &k, 4);         /* epoch 4 content arrives as the 2nd learning scan */
	{
		/* feed epoch-5 content (same as 4) as learning scan 3 and checks 4.. */
		scan(b, &k, 5);
	}
	CHECK(count(KV_EV_UNSTABLE, 0) == 1 && count(KV_EV_LEARNED, 0) == 1 &&
	      count(KV_EV_CHANGED, 0) == 0, "change while learning -> one UNSTABLE, no CHANGED");
	kv_baseline_free(b);

	/* no baseline bytes: frame-level verdict only */
	g_nev = 0;
	cfg.learn_epochs = 1;
	cfg.keep_bytes = false;
	b = kv_baseline_new(&cfg);
	for (e = 3; e <= 5; e++)
		scan(b, &k, e);
	CHECK(count(KV_EV_CHANGED, 5) == 1 && g_ev[g_nev - 1].verdict == KV_X_NO_BYTES,
	      "keep_bytes off: CHANGED with verdict no-bytes");
	kv_baseline_free(b);

	/* confirm_epochs = 0: report on the first differing scan */
	g_nev = 0;
	cfg.keep_bytes = true;
	cfg.confirm_epochs = 0;
	b = kv_baseline_new(&cfg);
	scan(b, &k, 3);
	scan(b, &k, 4);
	CHECK(count(KV_EV_CHANGED, 4) == 1, "confirm_epochs 0: immediate CHANGED");
	kv_baseline_free(b);
	kv_key_wipe(&k);
}

int main(void)
{
	char *ks = write_kallsyms(KALLSYMS);

	t_symbols(ks);
	t_patterns(ks);
	t_scenario(ks);
	t_variants(ks);
	unlink(ks);
	free(ks);
	printf("\n%d passed, %d failed\n", g_pass, g_fail);
	return g_fail ? 1 : 0;
}
