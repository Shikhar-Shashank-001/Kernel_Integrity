/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kd_dispatcher.h - Module 2: cache-aware hybrid core dispatcher.
 *
 *   ring (kim_ctx) --peek_at--> reader thread --SPSC queues--> P/E workers
 *        ^                          |  ^                          | work fn fills
 *        +------ kim_consume -------+  +---- done[seq] (release) -+ kd_result
 *
 * One reader thread owns the device (single consumer). It cuts the ring into
 * chunks of beta_P / beta_E bytes, hands them to workers so that a fraction
 * alpha of each epoch's bytes goes to P-cores, then completes them strictly in
 * ring order: a slot is released to the kernel only after every frame before
 * it has been processed, so a worker never sees its slot reused.
 *
 * Results are per frame and delivered in ring order, so anything computed from
 * them is independent of alpha/beta and of worker timing.
 */
#ifndef KD_DISPATCHER_H
#define KD_DISPATCHER_H

#include <stdbool.h>
#include <stdint.h>

#include "ingestion_daemon.h"
#include "kd_topology.h"
#include "kd_power.h"

#define KD_MAX_WORKERS  64
#define KD_BETA_MIN     KIM_FRAME_BYTES             /*  16 KiB */
#define KD_BETA_MAX     (64u * KIM_FRAME_BYTES)     /*   1 MiB */

struct kd_params {
	double   alpha;           /* share of bytes given to P-cores [0,1]   */
	uint32_t beta_p, beta_e;  /* chunk bytes, multiples of the frame     */
};

/* One frame's outcome. The descriptor is a copy: the ring slot is reused by
 * the kernel as soon as it is consumed. */
struct kd_result {
	struct kim_desc desc;
	uint8_t  tag[32];         /* written by the work fn (Module 3 tag)   */
	uint16_t worker;
	uint8_t  cls;             /* enum kd_class                           */
	uint8_t  status;          /* work-fn defined, 0 = ok                 */
	uint32_t reserved0;
	const uint8_t *payload;   /* frame bytes in the ring: valid only until
				     on_result returns (slot not yet released) */
	uint32_t reserved[4];
} __attribute__((aligned(64)));

_Static_assert(sizeof(struct kd_result) == 128, "kd_result is two cache lines");

/*
 * Worker side: fill out[i].tag / status for each frame i < ck->nframes.
 * Frame i's payload is ck->data + i * KIM_FRAME_BYTES, out[i].desc.length
 * bytes long; out[i].desc is already filled in.
 */
typedef void (*kd_work_fn)(const struct kim_chunk *ck, struct kd_result *out, void *arg);

/* Reader side, ring order. */
typedef void (*kd_result_fn)(const struct kd_result *r, void *arg);

struct kd_epoch_stats {
	uint32_t         epoch;
	bool             partial;      /* dispatcher joined mid-epoch            */
	enum kd_power    power;
	struct kd_params params;
	uint64_t         frames, bytes, chunks;
	uint64_t         cls_bytes[KD_NCLASS];
	uint64_t         t_start_ns;   /* first frame dispatched                 */
	uint64_t         t_end_ns;     /* last frame completed                   */
	uint64_t         t_close_ns;   /* epoch end observed (energy window end) */
	double           joules;       /* package energy over [start, close], <0 n/a */
};

typedef void (*kd_epoch_fn)(const struct kd_epoch_stats *s, void *arg);

struct kd_worker_spec {
	int           cpu;        /* -1 = not pinned                         */
	enum kd_class cls;
};

struct kd_config {
	struct kd_params      params[KD_PWR_NSTATES];
	enum kd_power         power;          /* initial power state           */
	int                   nworkers;
	struct kd_worker_spec worker[KD_MAX_WORKERS];
	int                   reader_cpu;     /* -1 = not pinned               */
	unsigned int          spin;           /* idle polls before a worker sleeps */
	kd_work_fn            work;
	void                 *work_arg;
	kd_result_fn          on_result;      /* optional                      */
	kd_epoch_fn           on_epoch;       /* optional                      */
	void                 *cb_arg;
	const struct kd_rapl *rapl;           /* optional energy source        */
};

struct kd_totals {
	uint64_t frames, bytes, chunks, epochs;
	uint64_t cls_bytes[KD_NCLASS];
	uint64_t worker_bytes[KD_MAX_WORKERS];
	int      pin_failures;
	/* profile: where the time went (ns unless noted) */
	uint64_t run_ns;                          /* reader start -> stop        */
	uint64_t worker_busy_ns[KD_MAX_WORKERS];  /* inside cfg.work             */
	uint64_t reader_wait_work_ns;  /* chunks in flight, waiting for workers  */
	uint64_t reader_wait_ring_ns;  /* ring empty, waiting for the kernel     */
	uint64_t disp_no_queue;        /* dispatch stops: class queues full (#)  */
	uint64_t disp_window_full;     /* dispatch stops: a ring in flight (#)   */
};

void kd_config_defaults(struct kd_config *cfg);
int  kd_params_check(struct kd_params *p);  /* rounds betas to frames; -EINVAL */
/* P workers = one per physical P core (all siblings if smt), E workers = all
 * E CPUs; max_p/max_e < 0 = no limit. Reader goes to a spare SMT sibling or
 * another unused CPU. Returns the number of workers or -ENODEV. */
int  kd_config_from_topo(struct kd_config *cfg, const struct kd_topo *t, bool smt,
			 int max_p, int max_e);

struct kd_dispatcher;

/* Starts the reader and the workers; 'c' must stay open until kd_join(). */
int  kd_start(struct kd_dispatcher **out, struct kim_ctx *c, const struct kd_config *cfg);
void kd_set_power(struct kd_dispatcher *d, enum kd_power p); /* applied at next epoch */
void kd_request_stop(struct kd_dispatcher *d);               /* any thread, callbacks too */
/* Waits for the reader to finish in-flight chunks, joins all threads, frees d. */
void kd_join(struct kd_dispatcher *d, struct kd_totals *tot);

#endif /* KD_DISPATCHER_H */
