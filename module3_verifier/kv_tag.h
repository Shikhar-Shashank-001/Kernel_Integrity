/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kv_tag.h - Module 3: per-frame integrity tag (AES-GCM-SIV, RFC 8452).
 *
 * The tag of a frame is the AES-GCM-SIV encryption of an EMPTY plaintext
 * whose additional data is
 *
 *     location block (16 B) || frame payload (desc->length bytes)
 *     location block = LE32(segment_type) LE32(seg_offset) LE32(seg_length)
 *                      LE32(fnv1a32(name))
 *
 * i.e. tag = AES_Kenc( POLYVAL_H(AAD || length block) ^ nonce, msb cleared ).
 * It is deterministic for (key, location, content), so scans can be compared
 * with a baseline, and nonce reuse is safe by design (SIV). Kernel addresses,
 * segment ids and epochs are deliberately NOT bound: they change across
 * reloads/scans while the content they describe does not.
 *
 * The nonce is fixed per key, so the derived keys and POLYVAL powers are
 * computed once in kv_key_init(); the per-frame cost is POLYVAL + one AES.
 *
 * Implementations: KV_IMPL_REF (portable, by-definition, slow - test oracle)
 * and KV_IMPL_VPCLMUL (AES-NI + 256-bit VPCLMULQDQ, 8-block aggregated
 * reduction). KV_IMPL_AUTO picks the fastest one the CPU supports.
 */
#ifndef KV_TAG_H
#define KV_TAG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "kim_uapi.h"

#define KV_TAG_BYTES   16
#define KV_NONCE_BYTES 12
#define KV_LOC_BYTES   16

enum kv_impl { KV_IMPL_AUTO = 0, KV_IMPL_REF, KV_IMPL_VPCLMUL, KV_NIMPL };

struct kv_ops;

/* Expanded key material: read-only after init, shared by all workers.
 * Holds secrets - keep it in locked memory and kv_key_wipe() it. */
struct kv_key {
	uint8_t  hpow[8 * 16] __attribute__((aligned(32)));  /* H_8 .. H_1 (POLYVAL powers) */
	uint8_t  enc_rk[15 * 16] __attribute__((aligned(16))); /* message-encryption key schedule */
	uint8_t  h[16];                 /* message-authentication key (H_1)   */
	uint8_t  nonce[KV_NONCE_BYTES];
	int      rounds;                /* 10 (AES-128) or 14 (AES-256)       */
	enum kv_impl impl;
	const struct kv_ops *ops;
};

bool        kv_impl_available(enum kv_impl impl);
const char *kv_impl_name(enum kv_impl impl);

/* key_len 16 or 32 (AES-128/256-GCM-SIV). nonce NULL = the fixed default.
 * Returns 0, -EINVAL or -ENOTSUP (impl not supported by this CPU). */
int  kv_key_init(struct kv_key *k, const uint8_t *key, size_t key_len,
		 const uint8_t *nonce, enum kv_impl impl);
void kv_key_wipe(struct kv_key *k);

/* RFC 8452 AES-GCM-SIV over (aad, empty plaintext): the 16-byte tag. */
void kv_siv_tag(const struct kv_key *k, const void *aad, size_t aad_len,
		uint8_t tag[KV_TAG_BYTES]);

/* Integrity tag of one ring frame (descriptor + payload). */
void kv_loc_block(const struct kim_desc *d, uint8_t blk[KV_LOC_BYTES]);
void kv_frame_tag(const struct kv_key *k, const struct kim_desc *d,
		  const void *payload, uint8_t tag[KV_TAG_BYTES]);

/* Building blocks, exposed for known-answer tests. */
void kv_ref_aes_expand(const uint8_t *key, size_t key_len, uint8_t *rk, int *rounds);
void kv_ref_aes_encrypt(const uint8_t *rk, int rounds, const uint8_t in[16], uint8_t out[16]);
void kv_ref_polyval_dot(const uint8_t a[16], const uint8_t b[16], uint8_t out[16]);
void kv_polyval(const struct kv_key *k, uint8_t s[16], const void *blocks, size_t nblocks);

#endif /* KV_TAG_H */
