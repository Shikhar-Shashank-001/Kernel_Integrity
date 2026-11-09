// SPDX-License-Identifier: GPL-2.0
/*
 * kv_fast.c - AES-NI + VPCLMULQDQ path. Built with -mavx2 -mvpclmulqdq
 * -mpclmul -maes; only reached after kv_impl_available() checked the CPU.
 *
 * POLYVAL is linear, so 8 blocks are folded per step with precomputed powers
 *     S' = dot(S ^ X1, H_8) ^ dot(X2, H_7) ^ ... ^ dot(X8, H_1)
 * accumulating the 256-bit carry-less products and reducing once per step.
 * Each 256-bit VPCLMULQDQ multiplies two blocks (one per 128-bit lane).
 *
 * Reduction (Montgomery, multiply by x^-128): with D = [d3 d2 d1 d0] and
 * c = 0xC200000000000000 (x^127 + x^126 + x^121 as the high qword),
 * fold d0 then d1 upward:  d1 ^= lo(d0*c), d2 ^= hi(d0*c) ^ d0,
 *                          d2 ^= lo(d1*c), d3 ^= hi(d1*c) ^ d1,  result [d3 d2].
 */
#include <immintrin.h>
#include <string.h>

#include "kv_impl.h"

static inline __m128i gf_reduce(__m128i lo, __m128i hi)
{
	const __m128i poly = _mm_set_epi64x((long long)0xC200000000000000ull, 0);
	__m128i t, x;

	t = _mm_clmulepi64_si128(lo, poly, 0x10);         /* d0 * c */
	x = _mm_xor_si128(_mm_shuffle_epi32(lo, 0x4e), t); /* [d0^hi(t) : d1^lo(t)] */
	t = _mm_clmulepi64_si128(x, poly, 0x10);          /* d1' * c */
	x = _mm_xor_si128(_mm_shuffle_epi32(x, 0x4e), t);
	return _mm_xor_si128(hi, x);
}

static inline __m128i gf_mul(__m128i a, __m128i b)
{
	__m128i lo = _mm_clmulepi64_si128(a, b, 0x00);
	__m128i hi = _mm_clmulepi64_si128(a, b, 0x11);
	__m128i mid = _mm_xor_si128(_mm_clmulepi64_si128(a, b, 0x01),
				    _mm_clmulepi64_si128(a, b, 0x10));

	lo = _mm_xor_si128(lo, _mm_slli_si128(mid, 8));
	hi = _mm_xor_si128(hi, _mm_srli_si128(mid, 8));
	return gf_reduce(lo, hi);
}

static inline __m128i fold_lanes(__m256i v)
{
	return _mm_xor_si128(_mm256_castsi256_si128(v), _mm256_extracti128_si256(v, 1));
}

static void fast_polyval(const struct kv_key *k, uint8_t s8[16], const uint8_t *p, size_t n)
{
	__m128i s = _mm_loadu_si128((const __m128i *)s8);

	if (n >= 8) {
		const __m256i h87 = _mm256_load_si256((const __m256i *)(k->hpow + 0));
		const __m256i h65 = _mm256_load_si256((const __m256i *)(k->hpow + 32));
		const __m256i h43 = _mm256_load_si256((const __m256i *)(k->hpow + 64));
		const __m256i h21 = _mm256_load_si256((const __m256i *)(k->hpow + 96));

		for (; n >= 8; n -= 8, p += 128) {
			__m256i x0 = _mm256_xor_si256(_mm256_loadu_si256((const __m256i *)p),
						      _mm256_zextsi128_si256(s));
			__m256i x1 = _mm256_loadu_si256((const __m256i *)(p + 32));
			__m256i x2 = _mm256_loadu_si256((const __m256i *)(p + 64));
			__m256i x3 = _mm256_loadu_si256((const __m256i *)(p + 96));
			__m256i lo, hi, mid;
			__m128i l, h, m;

#define CL(a, b, i) _mm256_clmulepi64_epi128((a), (b), (i))
			lo = _mm256_xor_si256(_mm256_xor_si256(CL(x0, h87, 0x00), CL(x1, h65, 0x00)),
					      _mm256_xor_si256(CL(x2, h43, 0x00), CL(x3, h21, 0x00)));
			hi = _mm256_xor_si256(_mm256_xor_si256(CL(x0, h87, 0x11), CL(x1, h65, 0x11)),
					      _mm256_xor_si256(CL(x2, h43, 0x11), CL(x3, h21, 0x11)));
			mid = _mm256_xor_si256(_mm256_xor_si256(CL(x0, h87, 0x01), CL(x1, h65, 0x01)),
					       _mm256_xor_si256(CL(x2, h43, 0x01), CL(x3, h21, 0x01)));
			mid = _mm256_xor_si256(mid,
				_mm256_xor_si256(_mm256_xor_si256(CL(x0, h87, 0x10), CL(x1, h65, 0x10)),
						 _mm256_xor_si256(CL(x2, h43, 0x10), CL(x3, h21, 0x10))));
#undef CL
			l = fold_lanes(lo);
			h = fold_lanes(hi);
			m = fold_lanes(mid);
			l = _mm_xor_si128(l, _mm_slli_si128(m, 8));
			h = _mm_xor_si128(h, _mm_srli_si128(m, 8));
			s = gf_reduce(l, h);
		}
	}
	if (n) {
		const __m128i h1 = _mm_loadu_si128((const __m128i *)k->h);

		for (; n; n--, p += 16)
			s = gf_mul(_mm_xor_si128(s, _mm_loadu_si128((const __m128i *)p)), h1);
	}
	_mm_storeu_si128((__m128i *)s8, s);
}

static void fast_encrypt(const struct kv_key *k, const uint8_t in[16], uint8_t out[16])
{
	const __m128i *rk = (const __m128i *)k->enc_rk;
	__m128i b = _mm_xor_si128(_mm_loadu_si128((const __m128i *)in), _mm_load_si128(rk));
	int r;

	for (r = 1; r < k->rounds; r++)
		b = _mm_aesenc_si128(b, _mm_load_si128(rk + r));
	b = _mm_aesenclast_si128(b, _mm_load_si128(rk + k->rounds));
	_mm_storeu_si128((__m128i *)out, b);
}

const struct kv_ops kv_ops_vpclmul = { fast_polyval, fast_encrypt };
