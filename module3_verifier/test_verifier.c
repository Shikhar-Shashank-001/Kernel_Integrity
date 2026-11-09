// SPDX-License-Identifier: GPL-2.0
/*
 * test_verifier.c - Module 3 known-answer tests, differential tests, benchmarks.
 * No root needed.
 *
 *   T1 AES-128/256 vs FIPS-197 (expected values from OpenSSL)
 *   T2 POLYVAL: x^128 * x^-128 identity, RFC 8452 appendix A example
 *   T3 RFC 8452 C.1 (empty AAD, empty plaintext)
 *   T4 AES-GCM-SIV tags vs python3-cryptography, 42 vectors, every impl
 *   T5 frame tags (location block || payload) vs python3-cryptography
 *   T6 fast vs reference: random keys, lengths, alignments, POLYVAL block counts
 *   B1 tag throughput per core type, in-cache frame and streamed from DRAM
 */
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>

#include "kv_tag.h"
#include "kv_vectors.h"

static int g_fail, g_pass;
#define PASS(...) do { g_pass++; printf("  [PASS] "); printf(__VA_ARGS__); putchar('\n'); } while (0)
#define FAIL(...) do { g_fail++; printf("  [FAIL] "); printf(__VA_ARGS__); putchar('\n'); } while (0)
#define CHECK(c, ...) do { if (c) PASS(__VA_ARGS__); else FAIL(__VA_ARGS__); } while (0)

static void unhex(const char *s, uint8_t *out, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++) {
		unsigned int v;

		sscanf(s + 2 * i, "%2x", &v);
		out[i] = (uint8_t)v;
	}
}

static void pat(uint8_t *b, size_t n, unsigned mul, unsigned j, unsigned add)
{
	size_t i;

	for (i = 0; i < n; i++)
		b[i] = (uint8_t)(i * mul + j * add + 1);
}

static void key_of(uint8_t *k, unsigned j, size_t klen)
{
	size_t i;

	for (i = 0; i < klen; i++)
		k[i] = (uint8_t)(i * 29 + j * 101 + 7);
}

static void nonce_of(uint8_t *n, unsigned j)
{
	int i;

	for (i = 0; i < 12; i++)
		n[i] = (uint8_t)(i * 47 + j * 13 + 3);
}

static uint64_t now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static uint64_t g_rng = 0x9e3779b97f4a7c15ull;

static uint64_t rnd(void)
{
	g_rng ^= g_rng << 13;
	g_rng ^= g_rng >> 7;
	g_rng ^= g_rng << 17;
	return g_rng;
}

static void fill_rnd(uint8_t *b, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		b[i] = (uint8_t)rnd();
}

static enum kv_impl IMPLS[] = { KV_IMPL_REF, KV_IMPL_VPCLMUL };
#define NIMPLS (sizeof(IMPLS) / sizeof(IMPLS[0]))

/* ------------------------------------------------------------------ */
static void t_aes(void)
{
	uint8_t key[32], rk[15 * 16], pt[16], ct[16], want[16];
	size_t i;
	int rounds;

	puts("T1 AES (FIPS-197)");
	for (i = 0; i < 32; i++)
		key[i] = (uint8_t)i;
	unhex("00112233445566778899aabbccddeeff", pt, 16);
	for (i = 0; i < sizeof(AES_KAT) / sizeof(AES_KAT[0]); i++) {
		kv_ref_aes_expand(key, (size_t)AES_KAT[i].klen, rk, &rounds);
		kv_ref_aes_encrypt(rk, rounds, pt, ct);
		unhex(AES_KAT[i].ct, want, 16);
		CHECK(!memcmp(ct, want, 16), "AES-%d known answer", AES_KAT[i].klen * 8);
	}
}

static void t_polyval(void)
{
	uint8_t h[16], x1[16], x2[16], s[16], want[16], a[16], x128[16] = { 1 }, r[16];
	int i, bad = 0;

	puts("T2 POLYVAL");
	/* x^128 mod P = 1 + x^121 + x^126 + x^127: dot(a, x^128) must be a */
	x128[15] = 0xc2;                /* bits 121, 126, 127 */
	for (i = 0; i < 64; i++) {
		fill_rnd(a, 16);
		kv_ref_polyval_dot(a, x128, r);
		bad += memcmp(a, r, 16) != 0;
	}
	CHECK(!bad, "dot(a, x^128 mod P) == a (x^-128 constant correct)");

	unhex("25629347589242761d31f826ba4b757b", h, 16);
	unhex("4f4f95668c83dfb6401762bb2d01a262", x1, 16);
	unhex("d1a24ddd2721d006bbe45f20d3c9f362", x2, 16);
	unhex("f7a3b47b846119fae5b7866cf5e5b77e", want, 16);
	kv_ref_polyval_dot(x1, h, s);
	for (i = 0; i < 16; i++)
		s[i] ^= x2[i];
	kv_ref_polyval_dot(s, h, s);
	CHECK(!memcmp(s, want, 16), "RFC 8452 appendix A POLYVAL(H, X1, X2)");
}

static void t_rfc_c1(void)
{
	uint8_t key[16] = { 1 }, nonce[12] = { 3 }, tag[16], want[16];
	struct kv_key k;
	size_t i;

	puts("T3 RFC 8452 C.1");
	unhex("dc20e2d83f25705bb49e439eca56de25", want, 16);
	for (i = 0; i < NIMPLS; i++) {
		if (kv_key_init(&k, key, 16, nonce, IMPLS[i]))
			continue;
		kv_siv_tag(&k, NULL, 0, tag);
		CHECK(!memcmp(tag, want, 16), "%s: empty message tag", kv_impl_name(IMPLS[i]));
		kv_key_wipe(&k);
	}
}

static void t_siv_vectors(void)
{
	static uint8_t aad[20000];
	uint8_t key[32], nonce[12], tag[16], want[16];
	size_t n = sizeof(SIV_KAT) / sizeof(SIV_KAT[0]), i, v;

	puts("T4 AES-GCM-SIV vs python3-cryptography");
	for (i = 0; i < NIMPLS; i++) {
		int bad = 0;

		if (!kv_impl_available(IMPLS[i])) {
			printf("  [----] %s not supported by this CPU\n", kv_impl_name(IMPLS[i]));
			continue;
		}
		for (v = 0; v < n; v++) {
			struct kv_key k;

			key_of(key, (unsigned)SIV_KAT[v].j, (size_t)SIV_KAT[v].klen);
			nonce_of(nonce, (unsigned)SIV_KAT[v].j);
			pat(aad, SIV_KAT[v].len, 167, (unsigned)SIV_KAT[v].j, 59);
			kv_key_init(&k, key, (size_t)SIV_KAT[v].klen, nonce, IMPLS[i]);
			kv_siv_tag(&k, aad, SIV_KAT[v].len, tag);
			unhex(SIV_KAT[v].tag, want, 16);
			if (memcmp(tag, want, 16)) {
				if (!bad)
					printf("    first mismatch: klen %d len %u\n", SIV_KAT[v].klen,
					       SIV_KAT[v].len);
				bad++;
			}
		}
		CHECK(!bad, "%s: %zu/%zu vectors (AES-128/256, AAD 0..16400 B)",
		      kv_impl_name(IMPLS[i]), n - (size_t)bad, n);
	}
}

static void t_frame_vectors(void)
{
	static uint8_t payload[KIM_FRAME_BYTES];
	uint8_t key[32], tag[16], want[16];
	size_t n = sizeof(FRAME_KAT) / sizeof(FRAME_KAT[0]), i, v;

	puts("T5 frame tags vs python3-cryptography");
	key_of(key, 100, 32);
	for (i = 0; i < NIMPLS; i++) {
		struct kv_key k;
		int bad = 0;

		if (kv_key_init(&k, key, 32, NULL, IMPLS[i]))
			continue;
		for (v = 0; v < n; v++) {
			struct kim_desc d;

			memset(&d, 0, sizeof(d));
			d.segment_type = FRAME_KAT[v].type;
			d.seg_offset = FRAME_KAT[v].off;
			d.length = FRAME_KAT[v].len;
			d.seg_length = FRAME_KAT[v].seglen;
			snprintf(d.name, sizeof(d.name), "%s", FRAME_KAT[v].name);
			d.base_address = 0xffffffff81000000ull;  /* must not affect the tag */
			d.scan_epoch = 1234;
			pat(payload, d.length, 211, (unsigned)v, 17);
			kv_frame_tag(&k, &d, payload, tag);
			unhex(FRAME_KAT[v].tag, want, 16);
			bad += memcmp(tag, want, 16) != 0;
		}
		CHECK(!bad, "%s: %zu/%zu frames (full, syscall table, short)",
		      kv_impl_name(IMPLS[i]), n - (size_t)bad, n);
		kv_key_wipe(&k);
	}
}

static void t_differential(void)
{
	static uint8_t buf[4096 + 64];
	struct kv_key kr, kf;
	uint8_t key[32], nonce[12], tr[16], tf[16], sr[16], sf[16];
	int it, bad = 0, badp = 0;

	puts("T6 fast vs reference");
	if (!kv_impl_available(KV_IMPL_VPCLMUL)) {
		printf("  [----] vpclmul not supported by this CPU\n");
		return;
	}
	for (it = 0; it < 400; it++) {
		size_t klen = (rnd() & 1) ? 32 : 16, len = rnd() % 4096, off = rnd() % 64;

		fill_rnd(key, klen);
		fill_rnd(nonce, 12);
		fill_rnd(buf, sizeof(buf));
		kv_key_init(&kr, key, klen, nonce, KV_IMPL_REF);
		kv_key_init(&kf, key, klen, nonce, KV_IMPL_VPCLMUL);
		kv_siv_tag(&kr, buf + off, len, tr);
		kv_siv_tag(&kf, buf + off, len, tf);
		bad += memcmp(tr, tf, 16) != 0;

		/* raw POLYVAL, every block count around the 8-block stride */
		memset(sr, 0, 16);
		fill_rnd(sr, (size_t)(rnd() % 17));
		memcpy(sf, sr, 16);
		kv_polyval(&kr, sr, buf + off, (size_t)(it % 41));
		kv_polyval(&kf, sf, buf + off, (size_t)(it % 41));
		badp += memcmp(sr, sf, 16) != 0;
	}
	CHECK(!bad, "400 random tags identical (AES-128/256, 0..4095 B, unaligned)");
	CHECK(!badp, "POLYVAL identical for 0..40 blocks from a non-zero state");
	kv_key_wipe(&kr);
	kv_key_wipe(&kf);
}

/* ------------------------------------------------------------------ */
static int first_cpu(const char *path)
{
	FILE *f = fopen(path, "r");
	int c = -1;

	if (f) {
		if (fscanf(f, "%d", &c) != 1)
			c = -1;
		fclose(f);
	}
	return c;
}

static double bench(const struct kv_key *k, const uint8_t *buf, size_t span, double secs)
{
	struct kim_desc d;
	uint8_t tag[16], acc = 0;
	uint64_t t0 = now_ns(), t, bytes = 0;
	size_t off = 0;

	memset(&d, 0, sizeof(d));
	d.segment_type = KIM_SEG_KTEXT;
	d.length = KIM_FRAME_BYTES;
	d.seg_length = (uint32_t)span;
	do {
		int i;

		for (i = 0; i < 64; i++) {
			d.seg_offset = (uint32_t)off;
			kv_frame_tag(k, &d, buf + off, tag);
			acc ^= tag[0];
			bytes += KIM_FRAME_BYTES;
			off += KIM_FRAME_BYTES;
			if (off >= span)
				off = 0;
		}
		t = now_ns();
	} while ((t - t0) / 1e9 < secs);
	__asm__ __volatile__("" :: "r"(acc));
	return bytes / ((t - t0) / 1e9) / 1e9;
}

static void b_throughput(void)
{
	const size_t big = 256u << 20;
	int cpus[2] = { first_cpu("/sys/devices/cpu_core/cpus"),
			first_cpu("/sys/devices/cpu_atom/cpus") };
	const char *cls[2] = { "P-core", "E-core" };
	uint8_t key[32];
	struct kv_key k;
	cpu_set_t saved, one;
	uint8_t *buf;
	int c;

	puts("\nB1 frame-tag throughput, one thread (AES-256-GCM-SIV, 16 KiB frames)");
	if (kv_key_init(&k, (fill_rnd(key, 32), key), 32, NULL, KV_IMPL_AUTO)) {
		FAIL("key init");
		return;
	}
	buf = mmap(NULL, big, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (buf == MAP_FAILED)
		return;
	fill_rnd(buf, big);
	sched_getaffinity(0, sizeof(saved), &saved);
	for (c = 0; c < 2; c++) {
		double hot, cold;

		if (cpus[c] < 0)
			continue;
		CPU_ZERO(&one);
		CPU_SET(cpus[c], &one);
		if (sched_setaffinity(0, sizeof(one), &one))
			continue;
		bench(&k, buf, KIM_FRAME_BYTES, 0.2);                   /* warm up */
		hot = bench(&k, buf, KIM_FRAME_BYTES, 1.0);
		cold = bench(&k, buf, big, 1.0);
		printf("  %s cpu %2d [%s]: in-cache %6.2f GB/s | streamed from DRAM %6.2f GB/s\n",
		       cls[c], cpus[c], kv_impl_name(k.impl), hot, cold);
	}
	sched_setaffinity(0, sizeof(saved), &saved);
	munmap(buf, big);
	kv_key_wipe(&k);
}

int main(int argc, char **argv)
{
	printf("fast path (AES-NI + VPCLMULQDQ): %s\n",
	       kv_impl_available(KV_IMPL_VPCLMUL) ? "available" : "NOT available");
	t_aes();
	t_polyval();
	t_rfc_c1();
	t_siv_vectors();
	t_frame_vectors();
	t_differential();
	if (!(argc > 1 && !strcmp(argv[1], "--no-bench")))
		b_throughput();
	printf("\n%d passed, %d failed\n", g_pass, g_fail);
	return g_fail ? 1 : 0;
}
