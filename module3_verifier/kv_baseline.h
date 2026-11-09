/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kv_baseline.h - learn a per-frame tag baseline, then check every scan
 * against it (CLAUDE.md section 5.1, decision "learn, re-verify, explain").
 *
 *   LEARNING  the first learn_epochs complete epochs: every frame's tag is
 *             recorded; a frame whose tag changes meanwhile is reported
 *             UNSTABLE and the latest value kept.
 *   CHECKING  a frame that differs from the baseline becomes a suspect; it is
 *             only reported CHANGED if it still differs on the next
 *             confirm_epochs scans (rules out reading mid text_poke). A suspect
 *             that matches again is TRANSIENT, a confirmed change that matches
 *             again is REVERTED. CHANGED events carry a byte-level explanation
 *             when baseline bytes are kept.
 *
 * Also: NEW_SEGMENT (module loaded after learning; trusted on first use and
 * learned), VANISHED (segment missing from a complete epoch), WX (writable
 * PTE on code/read-only data), FAULT (unreadable page), REMAP (kernel text
 * page no longer maps to its load-time physical page). Frames are keyed by
 * (segment_id, seg_offset): segment ids are stable while the device is open.
 *
 * Single-threaded: call from the dispatcher's on_result/on_epoch (reader
 * thread), in ring order. The baseline lives in memory only.
 */
#ifndef KV_BASELINE_H
#define KV_BASELINE_H

#include <stdbool.h>
#include <stdint.h>

#include "kim_uapi.h"
#include "kv_explain.h"

enum kv_ev_type {
	KV_EV_LEARNED = 0,      /* learning finished (summary)           */
	KV_EV_UNSTABLE,         /* frame changed during learning         */
	KV_EV_CHANGED,          /* confirmed difference from baseline    */
	KV_EV_TRANSIENT,        /* differed once, then matched again     */
	KV_EV_REVERTED,         /* confirmed change went back to baseline */
	KV_EV_NEW_SEGMENT,      /* segment appeared after learning       */
	KV_EV_VANISHED,         /* learned segment no longer scanned     */
	KV_EV_WX,               /* writable PTE on text / read-only data */
	KV_EV_FAULT,            /* unreadable page (zero-filled frame)   */
	KV_EV_REMAP,            /* kernel text page remapped (KIM_F_REMAP) */
	KV_EV_NTYPES
};

struct kv_event {
	enum kv_ev_type type;
	uint32_t        epoch;
	struct kim_desc desc;           /* the frame (first frame for segment events) */
	enum kv_verdict verdict;        /* CHANGED only                               */
	const char     *detail;         /* explanation, valid during the callback     */
};

typedef void (*kv_event_fn)(const struct kv_event *ev, void *arg);

struct kv_baseline_cfg {
	unsigned int learn_epochs;      /* >= 1 complete epochs           (3)  */
	unsigned int confirm_epochs;    /* extra scans before CHANGED     (1)  */
	bool         keep_bytes;        /* baseline copy for explanations      */
	const char  *kallsyms;          /* NULL = /proc/kallsyms               */
	kv_event_fn  on_event;
	void        *arg;
};

struct kv_baseline_stats {
	bool     checking;
	uint32_t epochs_learned, epochs_checked;
	uint64_t segments, frames, bytes_kept;
	uint64_t frames_changed;        /* currently in CHANGED state */
	uint64_t events[KV_EV_NTYPES];
	size_t   symbols;
};

struct kv_baseline;

const char         *kv_ev_name(enum kv_ev_type t);
struct kv_baseline *kv_baseline_new(const struct kv_baseline_cfg *cfg);
void kv_baseline_free(struct kv_baseline *b);
/* payload may be NULL when keep_bytes is false */
void kv_baseline_frame(struct kv_baseline *b, const struct kim_desc *d,
		       const uint8_t tag[16], const uint8_t *payload);
void kv_baseline_epoch_end(struct kv_baseline *b, uint32_t epoch, bool partial);
void kv_baseline_get_stats(const struct kv_baseline *b, struct kv_baseline_stats *st);

#endif /* KV_BASELINE_H */
