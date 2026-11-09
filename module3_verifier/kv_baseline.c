// SPDX-License-Identifier: GPL-2.0
/*
 * kv_baseline.c - learn/check state machine (see kv_baseline.h)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kv_baseline.h"

enum { F_UNSET = 0, F_OK, F_SUSPECT, F_CHANGED };

#define A_WX       0x1          /* alarms already raised for a frame */
#define A_FAULT    0x2
#define A_UNSTABLE 0x4
#define A_REMAP    0x8

struct kv_frame {
	uint8_t  tag[16];       /* baseline                          */
	uint8_t  last[16];      /* last differing tag seen           */
	uint8_t  state, alarms;
	uint16_t streak;        /* consecutive scans differing       */
};

struct kv_seg {
	bool             used, gone;
	uint32_t         type, seg_length, nframes, last_seen;
	uint64_t         base;
	char             name[KIM_NAME_LEN];
	struct kv_frame *fr;
	uint8_t         *bytes; /* baseline copy (keep_bytes)        */
};

struct kv_baseline {
	struct kv_baseline_cfg cfg;
	struct kv_syms *syms;
	bool            syms_stale;     /* modules appeared since kallsyms was read */
	uint32_t        syms_epoch;     /* epoch of the last kallsyms reload        */
	struct kv_seg  *seg;            /* indexed by segment_id */
	uint32_t        nseg;
	bool            checking;
	uint32_t        epochs_learned, epochs_checked;
	uint64_t        segments, frames, bytes_kept, changed;
	uint64_t        events[KV_EV_NTYPES];
	char            detail[8192];
};

const char *kv_ev_name(enum kv_ev_type t)
{
	static const char *const n[KV_EV_NTYPES] = {
		"LEARNED", "UNSTABLE", "CHANGED", "TRANSIENT", "REVERTED",
		"NEW_SEGMENT", "VANISHED", "WX", "FAULT", "REMAP",
	};

	return t < KV_EV_NTYPES ? n[t] : "?";
}

struct kv_baseline *kv_baseline_new(const struct kv_baseline_cfg *cfg)
{
	struct kv_baseline *b = calloc(1, sizeof(*b));

	if (!b)
		return NULL;
	b->cfg = *cfg;
	if (!b->cfg.learn_epochs)
		b->cfg.learn_epochs = 1;
	b->syms = kv_syms_load(cfg->kallsyms);
	return b;
}

static void seg_release(struct kv_baseline *b, struct kv_seg *s)
{
	uint32_t i;

	for (i = 0; i < s->nframes; i++) {
		if (s->fr[i].state == F_CHANGED)
			b->changed--;
		if (s->fr[i].state != F_UNSET)
			b->frames--;
	}
	if (s->bytes)
		b->bytes_kept -= s->seg_length;
	free(s->fr);
	free(s->bytes);
	s->fr = NULL;
	s->bytes = NULL;
	s->gone = true;
}

void kv_baseline_free(struct kv_baseline *b)
{
	uint32_t i;

	if (!b)
		return;
	for (i = 0; i < b->nseg; i++)
		if (b->seg[i].used && !b->seg[i].gone)
			seg_release(b, &b->seg[i]);
	free(b->seg);
	kv_syms_free(b->syms);
	free(b);
}

static void event(struct kv_baseline *b, enum kv_ev_type t, const struct kim_desc *d,
		  uint32_t epoch, enum kv_verdict v, const char *detail)
{
	struct kv_event ev = { .type = t, .epoch = epoch, .verdict = v, .detail = detail };

	if (d)
		ev.desc = *d;
	b->events[t]++;
	if (b->cfg.on_event)
		b->cfg.on_event(&ev, b->cfg.arg);
}

/* Synthetic descriptor naming a whole segment (segment-level events). */
static void seg_desc(const struct kv_seg *s, uint32_t id, uint32_t epoch, struct kim_desc *d)
{
	memset(d, 0, sizeof(*d));
	d->base_address = s->base;
	d->segment_type = s->type;
	d->segment_id = id;
	d->seg_length = s->seg_length;
	d->scan_epoch = epoch;
	memcpy(d->name, s->name, sizeof(d->name));
}

static struct kv_seg *get_seg(struct kv_baseline *b, const struct kim_desc *d)
{
	struct kv_seg *s;

	if (d->segment_id >= b->nseg) {
		uint32_t n = b->nseg ? b->nseg : 512;
		struct kv_seg *v;

		while (n <= d->segment_id)
			n *= 2;
		v = realloc(b->seg, n * sizeof(*v));
		if (!v)
			return NULL;
		memset(v + b->nseg, 0, (n - b->nseg) * sizeof(*v));
		b->seg = v;
		b->nseg = n;
	}
	s = &b->seg[d->segment_id];
	if (s->gone)
		return NULL;                    /* ids are never reused by the kernel */
	if (s->used)
		return s->seg_length == d->seg_length ? s : NULL;

	s->nframes = (d->seg_length + KIM_FRAME_BYTES - 1) / KIM_FRAME_BYTES;
	s->fr = calloc(s->nframes, sizeof(*s->fr));
	if (b->cfg.keep_bytes) {
		s->bytes = malloc(d->seg_length);
		if (s->bytes)
			b->bytes_kept += d->seg_length;
	}
	if (!s->fr) {
		free(s->bytes);
		return NULL;
	}
	s->used = true;
	s->type = d->segment_type;
	s->seg_length = d->seg_length;
	s->base = d->base_address - d->seg_offset;
	memcpy(s->name, d->name, sizeof(s->name));
	b->segments++;
	if (b->checking) {
		struct kim_desc sd;

		seg_desc(s, d->segment_id, d->scan_epoch, &sd);
		event(b, KV_EV_NEW_SEGMENT, &sd, d->scan_epoch, KV_X_UNEXPLAINED,
		      "segment appeared after learning (trusted on first use)");
		b->syms_stale = true;
	}
	return s;
}

static void learn(struct kv_baseline *b, struct kv_seg *s, struct kv_frame *f,
		  const struct kim_desc *d, const uint8_t tag[16], const uint8_t *payload)
{
	if (f->state == F_UNSET)
		b->frames++;
	memcpy(f->tag, tag, 16);
	f->state = F_OK;
	f->streak = 0;
	if (s->bytes && payload)
		memcpy(s->bytes + d->seg_offset, payload, d->length);
}

static void confirm_change(struct kv_baseline *b, struct kv_seg *s, struct kv_frame *f,
			   const struct kim_desc *d, const uint8_t *payload)
{
	const uint8_t *old = s->bytes ? s->bytes + d->seg_offset : NULL;
	enum kv_verdict v;

	if (b->syms_stale) {                    /* new module code since the last read */
		kv_syms_free(b->syms);
		b->syms = kv_syms_load(b->cfg.kallsyms);
		b->syms_stale = false;
		b->syms_epoch = d->scan_epoch;
	}
	v = kv_explain_frame(b->syms, d, old, payload, b->detail, sizeof(b->detail));
	/* an unresolved address may be code created since kallsyms was read
	 * (ftrace/BPF trampolines): re-read once per epoch and explain again */
	if (strstr(b->detail, "=?") && b->syms_epoch != d->scan_epoch) {
		kv_syms_free(b->syms);
		b->syms = kv_syms_load(b->cfg.kallsyms);
		b->syms_epoch = d->scan_epoch;
		v = kv_explain_frame(b->syms, d, old, payload, b->detail, sizeof(b->detail));
	}
	if (f->state != F_CHANGED)
		b->changed++;
	f->state = F_CHANGED;
	event(b, KV_EV_CHANGED, d, d->scan_epoch, v, b->detail);
}

void kv_baseline_frame(struct kv_baseline *b, const struct kim_desc *d,
		       const uint8_t tag[16], const uint8_t *payload)
{
	struct kv_seg *s = get_seg(b, d);
	struct kv_frame *f;
	uint32_t idx;

	if (!s || d->seg_offset % KIM_FRAME_BYTES || d->seg_offset + d->length > s->seg_length)
		return;
	idx = d->seg_offset / KIM_FRAME_BYTES;
	f = &s->fr[idx];
	s->last_seen = d->scan_epoch;

	if ((d->flags & KIM_F_PTE_W) && !(f->alarms & A_WX)) {
		f->alarms |= A_WX;
		event(b, KV_EV_WX, d, d->scan_epoch, KV_X_UNEXPLAINED,
		      "writable page table entry on code / read-only data");
	}
	if ((d->flags & KIM_F_REMAP) && !(f->alarms & A_REMAP)) {
		f->alarms |= A_REMAP;
		event(b, KV_EV_REMAP, d, d->scan_epoch, KV_X_UNEXPLAINED,
		      "kernel text page maps to a different physical page than at load");
	}
	if ((d->flags & KIM_F_FAULT) && !(f->alarms & A_FAULT)) {
		f->alarms |= A_FAULT;
		event(b, KV_EV_FAULT, d, d->scan_epoch, KV_X_UNEXPLAINED,
		      "page not present or unreadable: frame zero-filled");
	}

	if (f->state == F_UNSET) {
		learn(b, s, f, d, tag, payload);
		return;
	}
	if (!b->checking) {
		if (memcmp(tag, f->tag, 16)) {
			if (!(f->alarms & A_UNSTABLE))
				event(b, KV_EV_UNSTABLE, d, d->scan_epoch, KV_X_UNEXPLAINED,
				      "frame changed while learning; latest content kept");
			f->alarms |= A_UNSTABLE;
			learn(b, s, f, d, tag, payload);
		}
		return;
	}

	if (!memcmp(tag, f->tag, 16)) {
		if (f->state == F_SUSPECT)
			event(b, KV_EV_TRANSIENT, d, d->scan_epoch, KV_X_UNEXPLAINED,
			      "differed on one scan, matches the baseline again");
		else if (f->state == F_CHANGED) {
			b->changed--;
			event(b, KV_EV_REVERTED, d, d->scan_epoch, KV_X_PATCH_LIKE,
			      "confirmed change is back to the baseline content");
		}
		f->state = F_OK;
		f->streak = 0;
		return;
	}

	if (f->streak < UINT16_MAX)
		f->streak++;
	if (f->state == F_CHANGED) {
		if (memcmp(tag, f->last, 16))   /* changed again, differently */
			confirm_change(b, s, f, d, payload);
	} else if (f->streak > b->cfg.confirm_epochs) {
		confirm_change(b, s, f, d, payload);
	} else {
		f->state = F_SUSPECT;
	}
	memcpy(f->last, tag, 16);
}

void kv_baseline_epoch_end(struct kv_baseline *b, uint32_t epoch, bool partial)
{
	uint32_t i;

	if (partial)
		return;
	if (!b->checking) {
		/* segments that disappeared while learning are simply dropped */
		for (i = 0; i < b->nseg; i++)
			if (b->seg[i].used && !b->seg[i].gone && b->seg[i].last_seen != epoch) {
				seg_release(b, &b->seg[i]);
				b->segments--;
			}
		if (++b->epochs_learned >= b->cfg.learn_epochs) {
			b->checking = true;
			snprintf(b->detail, sizeof(b->detail),
				 "%llu segments, %llu frames, %llu unstable, %.1f MiB of baseline bytes, %zu symbols",
				 (unsigned long long)b->segments, (unsigned long long)b->frames,
				 (unsigned long long)b->events[KV_EV_UNSTABLE], b->bytes_kept / 1048576.0,
				 kv_syms_count(b->syms));
			event(b, KV_EV_LEARNED, NULL, epoch, KV_X_PATCH_LIKE, b->detail);
		}
		return;
	}
	b->epochs_checked++;
	for (i = 0; i < b->nseg; i++) {
		struct kv_seg *s = &b->seg[i];
		struct kim_desc sd;

		if (!s->used || s->gone || s->last_seen == epoch)
			continue;
		seg_desc(s, i, epoch, &sd);
		seg_release(b, s);
		b->segments--;
		event(b, KV_EV_VANISHED, &sd, epoch, KV_X_UNEXPLAINED,
		      "segment no longer scanned (module unloaded?)");
	}
}

void kv_baseline_get_stats(const struct kv_baseline *b, struct kv_baseline_stats *st)
{
	memset(st, 0, sizeof(*st));
	st->checking = b->checking;
	st->epochs_learned = b->epochs_learned;
	st->epochs_checked = b->epochs_checked;
	st->segments = b->segments;
	st->frames = b->frames;
	st->bytes_kept = b->bytes_kept;
	st->frames_changed = b->changed;
	memcpy(st->events, b->events, sizeof(st->events));
	st->symbols = kv_syms_count(b->syms);
}
