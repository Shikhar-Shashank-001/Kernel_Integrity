// SPDX-License-Identifier: GPL-2.0
/*
 * kv_tag.c - key setup, CPU dispatch and the AES-GCM-SIV tag driver
 * (see kv_tag.h). Key setup always uses the reference AES; only the
 * per-frame path (POLYVAL + final AES) is dispatched.
 */
#include <errno.h>
#include <string.h>

#include "kv_impl.h"

static const uint8_t KV_DEFAULT_NONCE[KV_NONCE_BYTES] __attribute__((nonstring)) = "KIM-FRAME-v1";

bool kv_impl_available(enum kv_impl impl)
{
	switch (impl) {
	case KV_IMPL_AUTO:
	case KV_IMPL_REF:
		return true;
	case KV_IMPL_VPCLMUL:
#if defined(__x86_64__)
		__builtin_cpu_init();
		return __builtin_cpu_supports("avx2") && __builtin_cpu_supports("vpclmulqdq") &&
		       __builtin_cpu_supports("pclmul") && __builtin_cpu_supports("aes");
#endif
	default:
		return false;
	}
}

const char *kv_impl_name(enum kv_impl impl)
{
	static const char *const n[KV_NIMPL] = { "auto", "ref", "vpclmul" };

	return impl < KV_NIMPL ? n[impl] : "?";
}

static void put_le32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

static void put_le64(uint8_t *p, uint64_t v)
{
	put_le32(p, (uint32_t)v);
	put_le32(p + 4, (uint32_t)(v >> 32));
}

int kv_key_init(struct kv_key *k, const uint8_t *key, size_t key_len,
		const uint8_t *nonce, enum kv_impl impl)
{
	uint8_t kgk_rk[15 * 16], blk[16], out[16], mek[32], hk[16];
	int kr, i, nblk;

	if (key_len != 16 && key_len != 32)
		return -EINVAL;
	if (impl == KV_IMPL_AUTO)
		impl = kv_impl_available(KV_IMPL_VPCLMUL) ? KV_IMPL_VPCLMUL : KV_IMPL_REF;
	else if (impl >= KV_NIMPL || !kv_impl_available(impl))
		return -ENOTSUP;

	memset(k, 0, sizeof(*k));
	memcpy(k->nonce, nonce ? nonce : KV_DEFAULT_NONCE, KV_NONCE_BYTES);

	/* RFC 8452 section 4: per-nonce keys from AES_K(LE32(i) || nonce) */
	kv_ref_aes_expand(key, key_len, kgk_rk, &kr);
	nblk = key_len == 16 ? 4 : 6;
	for (i = 0; i < nblk; i++) {
		put_le32(blk, (uint32_t)i);
		memcpy(blk + 4, k->nonce, KV_NONCE_BYTES);
		kv_ref_aes_encrypt(kgk_rk, kr, blk, out);
		if (i < 2)
			memcpy(k->h + 8 * i, out, 8);
		else
			memcpy(mek + 8 * (i - 2), out, 8);
	}
	kv_ref_aes_expand(mek, key_len, k->enc_rk, &k->rounds);

	/* POLYVAL powers H_1 .. H_8, stored H_8 first (see kv_fast.c) */
	memcpy(hk, k->h, 16);
	memcpy(k->hpow + 7 * 16, hk, 16);
	for (i = 6; i >= 0; i--) {
		kv_ref_polyval_dot(hk, k->h, hk);
		memcpy(k->hpow + i * 16, hk, 16);
	}

	k->impl = impl;
	k->ops = impl == KV_IMPL_VPCLMUL ? &kv_ops_vpclmul : &kv_ops_ref;
	explicit_bzero(kgk_rk, sizeof(kgk_rk));
	explicit_bzero(mek, sizeof(mek));
	explicit_bzero(out, sizeof(out));
	explicit_bzero(hk, sizeof(hk));
	return 0;
}

void kv_key_wipe(struct kv_key *k)
{
	explicit_bzero(k, sizeof(*k));
}

void kv_polyval(const struct kv_key *k, uint8_t s[16], const void *blocks, size_t nblocks)
{
	k->ops->polyval(k, s, blocks, nblocks);
}

/* POLYVAL over [loc block] || data || zero pad || length block, then finish. */
static void siv_core(const struct kv_key *k, const uint8_t *loc, const uint8_t *p,
		     size_t len, uint8_t tag[KV_TAG_BYTES])
{
	uint8_t s[16] = { 0 }, blk[16];
	size_t full = len / 16, rem = len % 16;
	int i;

	if (loc)
		k->ops->polyval(k, s, loc, 1);
	if (full)
		k->ops->polyval(k, s, p, full);
	if (rem) {
		memset(blk, 0, sizeof(blk));
		memcpy(blk, p + full * 16, rem);
		k->ops->polyval(k, s, blk, 1);
	}
	put_le64(blk, ((uint64_t)len + (loc ? KV_LOC_BYTES : 0)) * 8);  /* AAD bits */
	put_le64(blk + 8, 0);                                             /* plaintext bits */
	k->ops->polyval(k, s, blk, 1);

	for (i = 0; i < KV_NONCE_BYTES; i++)
		s[i] ^= k->nonce[i];
	s[15] &= 0x7f;
	k->ops->encrypt(k, s, tag);
}

void kv_siv_tag(const struct kv_key *k, const void *aad, size_t aad_len,
		uint8_t tag[KV_TAG_BYTES])
{
	siv_core(k, NULL, aad, aad_len, tag);
}

void kv_loc_block(const struct kim_desc *d, uint8_t blk[KV_LOC_BYTES])
{
	uint32_t h = 2166136261u;                       /* FNV-1a over the name */
	unsigned int i;

	for (i = 0; i < KIM_NAME_LEN && d->name[i]; i++)
		h = (h ^ (uint8_t)d->name[i]) * 16777619u;
	put_le32(blk, d->segment_type);
	put_le32(blk + 4, d->seg_offset);
	put_le32(blk + 8, d->seg_length);
	put_le32(blk + 12, h);
}

void kv_frame_tag(const struct kv_key *k, const struct kim_desc *d,
		  const void *payload, uint8_t tag[KV_TAG_BYTES])
{
	uint8_t loc[KV_LOC_BYTES];

	kv_loc_block(d, loc);
	siv_core(k, loc, payload, d->length, tag);
}
