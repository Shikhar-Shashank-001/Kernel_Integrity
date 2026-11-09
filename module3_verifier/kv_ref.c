// SPDX-License-Identifier: GPL-2.0
/*
 * kv_ref.c - portable reference implementation (test oracle, key setup).
 *
 * Written straight from the specifications, sharing no tricks with the fast
 * path: AES from FIPS-197 (S-box computed from GF(2^8) inverses, no typed
 * tables), POLYVAL from RFC 8452 as dot(a, b) = a * b * x^-128 mod P with
 * bitwise multiplication.
 */
#include <pthread.h>
#include <string.h>

#include "kv_impl.h"

/* ------------------------------------------------------------------ */
/* AES (FIPS-197), encryption only                                    */
/* ------------------------------------------------------------------ */
static uint8_t sbox[256];
static pthread_once_t sbox_once = PTHREAD_ONCE_INIT;

static uint8_t xtime(uint8_t a)
{
	return (uint8_t)((a << 1) ^ (a & 0x80 ? 0x1b : 0));
}

static uint8_t gmul(uint8_t a, uint8_t b)
{
	uint8_t r = 0;

	while (b) {
		if (b & 1)
			r ^= a;
		a = xtime(a);
		b >>= 1;
	}
	return r;
}

static uint8_t rotl8(uint8_t x, int n)
{
	return (uint8_t)((x << n) | (x >> (8 - n)));
}

static void sbox_build(void)
{
	int x;

	for (x = 0; x < 256; x++) {
		uint8_t inv = 0, p = (uint8_t)x;
		int e;

		if (x) {                        /* x^254 = x^-1 in GF(2^8) */
			inv = 1;
			for (e = 254; e; e >>= 1) {
				if (e & 1)
					inv = gmul(inv, p);
				p = gmul(p, p);
			}
		}
		sbox[x] = inv ^ rotl8(inv, 1) ^ rotl8(inv, 2) ^ rotl8(inv, 3) ^
			  rotl8(inv, 4) ^ 0x63;
	}
}

void kv_ref_init(void)
{
	pthread_once(&sbox_once, sbox_build);
}

void kv_ref_aes_expand(const uint8_t *key, size_t key_len, uint8_t *rk, int *rounds)
{
	int nk = (int)key_len / 4, nr = nk + 6, i;
	uint8_t rcon = 1;

	kv_ref_init();
	memcpy(rk, key, key_len);
	for (i = nk; i < 4 * (nr + 1); i++) {
		uint8_t t[4];

		memcpy(t, rk + 4 * (i - 1), 4);
		if (i % nk == 0) {
			uint8_t t0 = t[0];

			t[0] = sbox[t[1]] ^ rcon;
			t[1] = sbox[t[2]];
			t[2] = sbox[t[3]];
			t[3] = sbox[t0];
			rcon = xtime(rcon);
		} else if (nk > 6 && i % nk == 4) {
			t[0] = sbox[t[0]];
			t[1] = sbox[t[1]];
			t[2] = sbox[t[2]];
			t[3] = sbox[t[3]];
		}
		rk[4 * i + 0] = rk[4 * (i - nk) + 0] ^ t[0];
		rk[4 * i + 1] = rk[4 * (i - nk) + 1] ^ t[1];
		rk[4 * i + 2] = rk[4 * (i - nk) + 2] ^ t[2];
		rk[4 * i + 3] = rk[4 * (i - nk) + 3] ^ t[3];
	}
	*rounds = nr;
}

void kv_ref_aes_encrypt(const uint8_t *rk, int rounds, const uint8_t in[16], uint8_t out[16])
{
	uint8_t s[16], t[16];
	int r, i, c;

	for (i = 0; i < 16; i++)
		s[i] = in[i] ^ rk[i];
	for (r = 1; r <= rounds; r++) {
		/* SubBytes + ShiftRows: byte (row, col) at index row + 4 col */
		for (c = 0; c < 4; c++)
			for (i = 0; i < 4; i++)
				t[i + 4 * c] = sbox[s[i + 4 * ((c + i) & 3)]];
		if (r < rounds) {               /* MixColumns */
			for (c = 0; c < 4; c++) {
				uint8_t *a = t + 4 * c, a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3];

				a[0] = xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3;
				a[1] = a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3;
				a[2] = a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3;
				a[3] = xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3);
			}
		}
		for (i = 0; i < 16; i++)
			s[i] = t[i] ^ rk[16 * r + i];
	}
	memcpy(out, s, 16);
}

/* ------------------------------------------------------------------ */
/* POLYVAL (RFC 8452): GF(2^128) mod P = x^128 + x^127 + x^126 + x^121 + 1,  */
/* little-endian: bit i of the 128-bit LE integer is the coefficient of x^i  */
/* ------------------------------------------------------------------ */
struct gf { uint64_t lo, hi; };

static struct gf gf_load(const uint8_t b[16])
{
	struct gf r = { 0, 0 };
	int i;

	for (i = 7; i >= 0; i--) {
		r.lo = r.lo << 8 | b[i];
		r.hi = r.hi << 8 | b[8 + i];
	}
	return r;
}

static void gf_store(struct gf a, uint8_t b[16])
{
	int i;

	for (i = 0; i < 8; i++) {
		b[i] = (uint8_t)(a.lo >> (8 * i));
		b[8 + i] = (uint8_t)(a.hi >> (8 * i));
	}
}

/* a * b mod P, shift-and-add */
static struct gf gf_mulmod(struct gf a, struct gf b)
{
	struct gf r = { 0, 0 };
	int i;

	for (i = 0; i < 128; i++) {
		uint64_t bit = i < 64 ? (b.lo >> i) & 1 : (b.hi >> (i - 64)) & 1;
		uint64_t carry = a.hi >> 63;

		if (bit) {
			r.lo ^= a.lo;
			r.hi ^= a.hi;
		}
		a.hi = a.hi << 1 | a.lo >> 63;          /* a *= x */
		a.lo <<= 1;
		if (carry) {                            /* x^128 = x^127 + x^126 + x^121 + 1 */
			a.lo ^= 1;
			a.hi ^= 1ull << 57 | 1ull << 62 | 1ull << 63;
		}
	}
	return r;
}

/* x^-128 mod P = x^127 + x^124 + x^121 + x^114 + 1 (RFC 8452, section 3) */
static const struct gf GF_XINV128 = { 1, 1ull << 63 | 1ull << 60 | 1ull << 57 | 1ull << 50 };

void kv_ref_polyval_dot(const uint8_t a[16], const uint8_t b[16], uint8_t out[16])
{
	gf_store(gf_mulmod(gf_mulmod(gf_load(a), gf_load(b)), GF_XINV128), out);
}

static void ref_polyval(const struct kv_key *k, uint8_t s[16], const uint8_t *p, size_t n)
{
	uint8_t x[16];
	int i;

	for (; n; n--, p += 16) {
		for (i = 0; i < 16; i++)
			x[i] = s[i] ^ p[i];
		kv_ref_polyval_dot(x, k->h, s);
	}
}

static void ref_encrypt(const struct kv_key *k, const uint8_t in[16], uint8_t out[16])
{
	kv_ref_aes_encrypt(k->enc_rk, k->rounds, in, out);
}

const struct kv_ops kv_ops_ref = { ref_polyval, ref_encrypt };
