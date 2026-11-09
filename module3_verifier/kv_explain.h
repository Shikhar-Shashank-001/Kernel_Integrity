/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kv_explain.h - describe HOW a frame differs from its baseline.
 *
 * Byte-level diff of a changed frame, symbolised through /proc/kallsyms, with
 * the instruction patterns the kernel legitimately writes at runtime decoded:
 *   nop5 <-> jmp rel32, nop2 <-> jmp rel8   static keys / jump labels
 *   nop5 <-> call rel32 at function entry   ftrace / BPF trampolines
 *   call/jmp rel32 retargeted               static_call, ftrace updates
 * plus per-entry decoding for the syscall tables.
 *
 * The verdict is a HINT for prioritising alerts: an attacker can write the
 * same patterns. "patch-like" requires the branch target to resolve to a known
 * symbol and to be plausible (same function for jump labels, a trampoline for
 * entry calls); everything else is "unexplained".
 */
#ifndef KV_EXPLAIN_H
#define KV_EXPLAIN_H

#include <stddef.h>
#include <stdint.h>

#include "kim_uapi.h"

struct kv_syms;

/* NULL path = /proc/kallsyms. Returns NULL if unreadable or addresses are
 * hidden (not root / kptr_restrict). */
struct kv_syms *kv_syms_load(const char *path);
void            kv_syms_free(struct kv_syms *s);
size_t          kv_syms_count(const struct kv_syms *s);

/* Symbol containing addr: 0 and "name+0xoff/0xsize [mod]" in buf, or -1 ("?").
 * start/end (optional) get the symbol's bounds. */
int kv_syms_lookup(const struct kv_syms *s, uint64_t addr, char *buf, size_t n,
		   uint64_t *start, uint64_t *end);

enum kv_verdict {
	KV_X_PATCH_LIKE = 0,    /* every changed range matches a legitimate pattern */
	KV_X_UNEXPLAINED,       /* at least one range does not                       */
	KV_X_NO_BYTES,          /* baseline bytes not kept: frame-level only         */
};

const char *kv_verdict_name(enum kv_verdict v);

/* Explain how cur differs from old (both d->length bytes of the frame d).
 * Writes text to out (always NUL terminated) and returns the verdict. */
enum kv_verdict kv_explain_frame(const struct kv_syms *s, const struct kim_desc *d,
				 const uint8_t *old, const uint8_t *cur,
				 char *out, size_t n);

#endif /* KV_EXPLAIN_H */
