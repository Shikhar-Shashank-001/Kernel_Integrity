/* SPDX-License-Identifier: GPL-2.0 */
/* kv_impl.h - internal: per-implementation primitives behind kv_tag.c */
#ifndef KV_IMPL_H
#define KV_IMPL_H

#include "kv_tag.h"

struct kv_ops {
	/* s = POLYVAL state, updated over nblocks full 16-byte blocks */
	void (*polyval)(const struct kv_key *k, uint8_t s[16], const uint8_t *p, size_t nblocks);
	/* one block with the message-encryption key */
	void (*encrypt)(const struct kv_key *k, const uint8_t in[16], uint8_t out[16]);
};

extern const struct kv_ops kv_ops_ref;
extern const struct kv_ops kv_ops_vpclmul;   /* only call when kv_impl_available() */

void kv_ref_init(void);                      /* S-box tables; idempotent */

#endif /* KV_IMPL_H */
