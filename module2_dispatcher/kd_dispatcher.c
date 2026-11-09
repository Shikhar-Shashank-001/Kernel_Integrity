// SPDX-License-Identifier: GPL-2.0
/*
 * kd_dispatcher.c - Module 2 pipeline (see kd_dispatcher.h)
 *
 * Ownership
 *   reader : disp_seq, comp_seq, pend_n[], scheduling and epoch state,
 *            queue heads, kim_consume()
 *   worker : its queue tail, res[] / done[] of the chunks it was given
 *
 * Ordering
 *   queue item  : reader release-stores q.head, worker acquire-loads it
 *   completion  : worker writes res[], release-stores done[slot] = seq + 1;
 *                 reader acquire-loads it before reading res[]
 *   sleep/wake  : eventcount (futex) with a seq_cst fence on both sides, so a
 *                 waker either sees the sleeper's flag or the sleeper sees the work
 */
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <linux/futex.h>
#include <sys/syscall.h>

#ifdef __x86_64__
# include <immintrin.h>
# define cpu_relax() _mm_pause()
#else
# define cpu_relax() __asm__ __volatile__("" ::: "memory")
#endif

#include "kd_dispatcher.h"

#define KD_QLEN        64u        /* per-worker queue, pow2 */
#define KD_READER_WAIT 200000     /* ns: completion wait while chunks in flight */
#define KD_WORKER_WAIT 10000000   /* ns: bounds the cost of any missed wakeup   */
#define KD_IDLE_MS     10         /* poll(2) timeout when the ring is empty     */

#define LOAD_ACQ(p)     __atomic_load_n((p), __ATOMIC_ACQUIRE)
#define STORE_REL(p, v) __atomic_store_n((p), (v), __ATOMIC_RELEASE)

struct kd_item {
	uint64_t         seq;
	struct kim_chunk ck;
};

struct kd_worker {
	uint64_t qhead __attribute__((aligned(64)));  /* reader writes          */
	uint64_t qtail __attribute__((aligned(64)));  /* worker writes          */
	uint32_t ev __attribute__((aligned(64)));     /* futex eventcount       */
	int      sleeping;
	struct kd_item item[KD_QLEN];

	struct kd_dispatcher *d;
	pthread_t     th;
	int           id, cpu, pin_err;
	enum kd_class cls;
	uint64_t      assigned;   /* reader: bytes handed out this epoch    */
	uint64_t      bytes;      /* worker: bytes processed                */
	uint64_t      busy_ns;    /* worker: time inside cfg.work           */
};

struct kd_ep_start {
	uint32_t         epoch;
	enum kd_power    power;
	struct kd_params params;
	uint64_t         t0, uj0;
	bool             have_uj;
};

struct kd_dispatcher {
	struct kim_ctx   *c;
	struct kd_config  cfg;
	uint32_t          nslots, mask;
	struct kd_result *res;          /* [nslots] by slot                     */
	uint64_t         *done;         /* [nslots] seq + 1 of completed chunk  */
	uint32_t         *pend_n;       /* [nslots] frames of chunk at slot     */
	uint64_t          disp_seq, comp_seq, start_tail;
	struct kd_worker *w;
	int               cw[KD_NCLASS][KD_MAX_WORKERS], ncw[KD_NCLASS];

	/* dispatch side */
	struct kd_params  cur;
	enum kd_power     cur_power;
	bool              disp_ep_valid;
	uint32_t          disp_ep;
	uint64_t          sched_bytes[KD_NCLASS];
	struct kd_ep_start *est;        /* FIFO [nslots]: epochs in flight      */
	uint32_t          est_head, est_tail;

	/* completion side */
	bool              ep_open, seen_first;
	struct kd_epoch_stats ep;
	struct kd_ep_start ep_start;
	uint64_t          last_emit_ns;

	/* cross-thread */
	uint32_t          rev __attribute__((aligned(64)));   /* reader eventcount */
	int               reader_sleeping;
	int               stop, workers_stop, power_req;
	pthread_t         reader;
	struct kd_totals  tot;
};

static long futex_wait(uint32_t *addr, uint32_t val, long ns)
{
	struct timespec ts = { ns / 1000000000L, ns % 1000000000L };

	return syscall(SYS_futex, addr, FUTEX_WAIT_PRIVATE, val, ns ? &ts : NULL, NULL, 0);
}

static void futex_wake(uint32_t *addr)
{
	syscall(SYS_futex, addr, FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0);
}

/* Waker half of the eventcount. */
static void ev_signal(uint32_t *ev, int *sleeping)
{
	__atomic_thread_fence(__ATOMIC_SEQ_CST);
	if (__atomic_load_n(sleeping, __ATOMIC_RELAXED)) {
		__atomic_fetch_add(ev, 1, __ATOMIC_RELEASE);
		futex_wake(ev);
	}
}

static int pin_self(int cpu)
{
	cpu_set_t set;

	if (cpu < 0)
		return 0;
	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	return pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
}

/* ------------------------------------------------------------------ */
/* Configuration                                                      */
/* ------------------------------------------------------------------ */
void kd_config_defaults(struct kd_config *cfg)
{
	memset(cfg, 0, sizeof(*cfg));
	/* Streamed-workload sweep (2026-11-02/03, SIV tags, drift-corrected):
	 * the pipeline is bound by the single kernel copy thread, so using both
	 * core classes costs power without adding throughput. P-only was the
	 * most efficient: AC 0.235 vs 0.212 GB/J for the Phase-1 hybrid optimum
	 * (0.80/256K, +11%, noise 2.9%); battery 0.351 vs 0.334 (within noise,
	 * same direction). beta_P 256K is within noise of the best on both;
	 * beta_E only matters when alpha < 1. See CLAUDE.md section 6. */
	cfg->params[KD_PWR_BATTERY] = (struct kd_params){ 1.0, 256u << 10, 16u << 10 };
	cfg->params[KD_PWR_AC]      = (struct kd_params){ 1.0, 256u << 10, 16u << 10 };
	cfg->power = KD_PWR_AC;
	cfg->reader_cpu = -1;
	cfg->spin = 512;
}

static uint32_t beta_round(uint32_t b)
{
	b -= b % KIM_FRAME_BYTES;
	return b < KD_BETA_MIN ? KD_BETA_MIN : b > KD_BETA_MAX ? KD_BETA_MAX : b;
}

int kd_params_check(struct kd_params *p)
{
	if (!(p->alpha >= 0.0 && p->alpha <= 1.0))     /* also rejects NaN */
		return -EINVAL;
	p->beta_p = beta_round(p->beta_p);
	p->beta_e = beta_round(p->beta_e);
	return 0;
}

int kd_config_from_topo(struct kd_config *cfg, const struct kd_topo *t, bool smt,
			int max_p, int max_e)
{
	cpu_set_t used, cores;
	int i, n[KD_NCLASS] = { 0, 0 }, lim[KD_NCLASS] = { max_p, max_e };

	CPU_ZERO(&used);
	CPU_ZERO(&cores);
	cfg->nworkers = 0;
	for (i = 0; i < t->ncpu && cfg->nworkers < KD_MAX_WORKERS; i++) {
		const struct kd_cpu *k = &t->cpus[i];

		if (lim[k->cls] >= 0 && n[k->cls] >= lim[k->cls])
			continue;
		if (!smt && CPU_ISSET(k->core, &cores))
			continue;               /* one thread per physical core */
		CPU_SET(k->core, &cores);
		CPU_SET(k->cpu, &used);
		cfg->worker[cfg->nworkers++] = (struct kd_worker_spec){ k->cpu, k->cls };
		n[k->cls]++;
	}
	if (!cfg->nworkers)
		return -ENODEV;

	/* Reader: idle sibling of a busy P core first, then any unused CPU. */
	cfg->reader_cpu = -1;
	for (i = t->ncpu - 1; i >= 0; i--) {
		const struct kd_cpu *k = &t->cpus[i];

		if (CPU_ISSET(k->cpu, &used))
			continue;
		if (CPU_ISSET(k->core, &cores)) {
			cfg->reader_cpu = k->cpu;
			break;
		}
		if (cfg->reader_cpu < 0)
			cfg->reader_cpu = k->cpu;
	}
	return cfg->nworkers;
}

/* ------------------------------------------------------------------ */
/* Workers                                                            */
/* ------------------------------------------------------------------ */
static void process(struct kd_worker *w, const struct kd_item *it)
{
	struct kd_dispatcher *d = w->d;
	uint32_t slot = (uint32_t)it->seq & d->mask, i;
	struct kd_result *out = &d->res[slot];         /* chunks never wrap */
	uint64_t t0;

	for (i = 0; i < it->ck.nframes; i++) {
		out[i].desc = it->ck.first[i];
		memset(out[i].tag, 0, sizeof(out[i].tag));
		out[i].worker = (uint16_t)w->id;
		out[i].cls = (uint8_t)w->cls;
		out[i].status = 0;
		out[i].payload = it->ck.data + (size_t)i * KIM_FRAME_BYTES;
	}
	t0 = kim_now_ns();
	d->cfg.work(&it->ck, out, d->cfg.work_arg);
	w->busy_ns += kim_now_ns() - t0;
	w->bytes += it->ck.bytes;

	STORE_REL(&d->done[slot], it->seq + 1);
	ev_signal(&d->rev, &d->reader_sleeping);
}

static void *worker_main(void *arg)
{
	struct kd_worker *w = arg;
	unsigned int idle = 0;

	w->pin_err = pin_self(w->cpu);
	for (;;) {
		uint64_t t = w->qtail;
		uint32_t ev;

		if (t != LOAD_ACQ(&w->qhead)) {
			process(w, &w->item[t & (KD_QLEN - 1)]);
			STORE_REL(&w->qtail, t + 1);
			idle = 0;
			continue;
		}
		if (LOAD_ACQ(&w->d->workers_stop))
			break;
		if (idle++ < w->d->cfg.spin) {
			cpu_relax();
			continue;
		}
		ev = LOAD_ACQ(&w->ev);
		__atomic_store_n(&w->sleeping, 1, __ATOMIC_SEQ_CST);
		__atomic_thread_fence(__ATOMIC_SEQ_CST);
		if (t == LOAD_ACQ(&w->qhead) && !LOAD_ACQ(&w->d->workers_stop))
			futex_wait(&w->ev, ev, KD_WORKER_WAIT);
		__atomic_store_n(&w->sleeping, 0, __ATOMIC_RELAXED);
		idle = 0;
	}
	return NULL;
}

/* ------------------------------------------------------------------ */
/* Reader: completion side                                            */
/* ------------------------------------------------------------------ */
static void close_epoch(struct kd_dispatcher *d)
{
	struct kd_epoch_stats *s = &d->ep;
	uint64_t uj;

	s->t_end_ns = d->last_emit_ns;
	s->t_close_ns = kim_now_ns();
	s->joules = -1.0;
	if (d->ep_start.have_uj && !kd_rapl_read(d->cfg.rapl, &uj))
		s->joules = kd_rapl_joules(d->cfg.rapl, d->ep_start.uj0, uj);
	if (!s->partial)
		d->tot.epochs++;
	if (d->cfg.on_epoch)
		d->cfg.on_epoch(s, d->cfg.cb_arg);
	d->ep_open = false;
}

static void open_epoch(struct kd_dispatcher *d, uint32_t epoch)
{
	/* pop the dispatch-side record of this epoch (FIFO, same order) */
	while (d->est_tail != d->est_head) {
		d->ep_start = d->est[d->est_tail++ & d->mask];
		if (d->ep_start.epoch == epoch)
			break;
	}
	memset(&d->ep, 0, sizeof(d->ep));
	d->ep.epoch = epoch;
	d->ep.power = d->ep_start.power;
	d->ep.params = d->ep_start.params;
	d->ep.t_start_ns = d->ep_start.t0;
	/* the first epoch is only complete if nothing was ever consumed before */
	d->ep.partial = !d->seen_first && d->start_tail != 0;
	d->seen_first = true;
	d->ep_open = true;
}

static void emit(struct kd_dispatcher *d, const struct kd_result *r)
{
	if (d->ep_open && r->desc.scan_epoch != d->ep.epoch)
		close_epoch(d);
	if (!d->ep_open)
		open_epoch(d, r->desc.scan_epoch);
	d->ep.frames++;
	d->ep.bytes += r->desc.length;
	d->ep.cls_bytes[r->cls] += r->desc.length;
	d->tot.frames++;
	d->tot.bytes += r->desc.length;
	d->tot.cls_bytes[r->cls] += r->desc.length;
	if (d->cfg.on_result)
		d->cfg.on_result(r, d->cfg.cb_arg);
}

/* Release every completed chunk at the head of the in-order window. */
static bool track(struct kd_dispatcher *d)
{
	uint64_t start = d->comp_seq;

	while (d->comp_seq != d->disp_seq) {
		uint32_t slot = (uint32_t)d->comp_seq & d->mask, n, k;

		if (LOAD_ACQ(&d->done[slot]) != d->comp_seq + 1)
			break;
		n = d->pend_n[slot];
		for (k = 0; k < n; k++)
			emit(d, &d->res[slot + k]);
		d->ep.chunks++;
		d->tot.chunks++;
		d->comp_seq += n;
	}
	if (d->comp_seq == start)
		return false;
	d->last_emit_ns = kim_now_ns();
	kim_consume(d->c, (uint32_t)(d->comp_seq - start));
	return true;
}

/* Everything published has been processed and the kernel moved to a later
 * epoch: the open epoch is complete even though no newer frame arrived yet. */
static void check_epoch_end(struct kd_dispatcher *d)
{
	const struct kim_hdr *h = d->c->hdr;
	uint32_t cur;

	if (!d->ep_open || d->comp_seq != d->disp_seq)
		return;
	/* The kernel stores hdr->epoch after the final head release of an epoch;
	 * on x86 (TSO, the module is x86_64 only) seeing the new epoch therefore
	 * implies the head load below sees all of that epoch's frames. */
	cur = (uint32_t)LOAD_ACQ(&h->epoch);
	if ((int32_t)(cur - d->ep.epoch) > 0 && LOAD_ACQ(&h->head) == d->comp_seq)
		close_epoch(d);
}

/* ------------------------------------------------------------------ */
/* Reader: dispatch side                                              */
/* ------------------------------------------------------------------ */
static void begin_dispatch_epoch(struct kd_dispatcher *d, uint32_t epoch)
{
	enum kd_power p = (enum kd_power)__atomic_load_n(&d->power_req, __ATOMIC_RELAXED);
	struct kd_ep_start *e = &d->est[d->est_head++ & d->mask];
	int i;

	if (p != d->cur_power) {        /* power changes take effect per epoch */
		d->cur_power = p;
		d->cur = d->cfg.params[p];
	}
	d->disp_ep = epoch;
	d->disp_ep_valid = true;
	d->sched_bytes[KD_P] = d->sched_bytes[KD_E] = 0;
	for (i = 0; i < d->cfg.nworkers; i++)
		d->w[i].assigned = 0;

	e->epoch = epoch;
	e->power = d->cur_power;
	e->params = d->cur;
	e->t0 = kim_now_ns();
	e->have_uj = d->cfg.rapl && !kd_rapl_read(d->cfg.rapl, &e->uj0);
}

/* Byte-credit split: P gets the next chunk while its share is <= alpha. */
static enum kd_class pick_class(const struct kd_dispatcher *d)
{
	double a = d->cur.alpha;

	if (!d->ncw[KD_E] || a >= 1.0)
		return KD_P;
	if (!d->ncw[KD_P] || a <= 0.0)
		return KD_E;
	return (double)d->sched_bytes[KD_P] * (1.0 - a) <=
	       (double)d->sched_bytes[KD_E] * a ? KD_P : KD_E;
}

/* Least-loaded worker of the class with queue space, or NULL. */
static struct kd_worker *pick_worker(struct kd_dispatcher *d, enum kd_class cls)
{
	struct kd_worker *best = NULL;
	int i;

	for (i = 0; i < d->ncw[cls]; i++) {
		struct kd_worker *w = &d->w[d->cw[cls][i]];

		if (w->qhead - LOAD_ACQ(&w->qtail) >= KD_QLEN)
			continue;
		if (!best || w->assigned < best->assigned)
			best = w;
	}
	return best;
}

static bool dispatch(struct kd_dispatcher *d)
{
	struct kim_ctx *c = d->c;
	bool progress = false;

	for (;;) {
		const struct kim_desc *d0;
		struct kd_worker *w;
		struct kd_item *it;
		struct kim_chunk ck;
		enum kd_class cls;
		uint32_t n;

		if (d->disp_seq >= LOAD_ACQ(&c->hdr->head))
			break;
		/* never more than one ring in flight: pend_n/done/res are per slot */
		if (d->disp_seq - d->comp_seq >= d->nslots) {
			d->tot.disp_window_full++;
			break;
		}
		d0 = &c->desc[d->disp_seq & d->mask];
		if (!d->disp_ep_valid || d0->scan_epoch != d->disp_ep)
			begin_dispatch_epoch(d, d0->scan_epoch);

		cls = pick_class(d);
		w = pick_worker(d, cls);
		if (!w) {
			d->tot.disp_no_queue++;
			break;          /* strict alpha: wait for that class */
		}
		n = kim_peek_chunk_at(c, d->disp_seq, cls == KD_P ? d->cur.beta_p : d->cur.beta_e, &ck);
		if (!n)
			break;

		d->pend_n[d->disp_seq & d->mask] = n;
		it = &w->item[w->qhead & (KD_QLEN - 1)];
		it->seq = d->disp_seq;
		it->ck = ck;
		STORE_REL(&w->qhead, w->qhead + 1);
		ev_signal(&w->ev, &w->sleeping);

		w->assigned += ck.bytes;
		d->sched_bytes[cls] += ck.bytes;
		d->disp_seq += n;
		progress = true;
	}
	return progress;
}

static void reader_wait(struct kd_dispatcher *d)
{
	uint64_t t0 = kim_now_ns();
	bool work = d->comp_seq != d->disp_seq;

	if (work) {
		uint32_t ev = LOAD_ACQ(&d->rev);
		uint32_t slot = (uint32_t)d->comp_seq & d->mask;

		__atomic_store_n(&d->reader_sleeping, 1, __ATOMIC_SEQ_CST);
		__atomic_thread_fence(__ATOMIC_SEQ_CST);
		if (LOAD_ACQ(&d->done[slot]) != d->comp_seq + 1)
			futex_wait(&d->rev, ev, KD_READER_WAIT);
		__atomic_store_n(&d->reader_sleeping, 0, __ATOMIC_RELAXED);
	} else if (d->c->fd >= 0) {
		kim_wait(d->c, KD_IDLE_MS);
	} else {
		struct timespec ts = { 0, 20000 };      /* mock ring: no fd */

		nanosleep(&ts, NULL);
	}
	if (work)
		d->tot.reader_wait_work_ns += kim_now_ns() - t0;
	else
		d->tot.reader_wait_ring_ns += kim_now_ns() - t0;
}

static void *reader_main(void *arg)
{
	struct kd_dispatcher *d = arg;
	uint64_t t0 = kim_now_ns();
	int i;

	if (pin_self(d->cfg.reader_cpu))
		d->tot.pin_failures++;
	while (!LOAD_ACQ(&d->stop)) {
		bool p = track(d);

		p |= dispatch(d);
		p |= track(d);
		check_epoch_end(d);
		if (!p)
			reader_wait(d);
	}
	/* drain what is in flight so every released slot was fully processed */
	while (d->comp_seq != d->disp_seq)
		if (!track(d))
			reader_wait(d);

	d->tot.run_ns = kim_now_ns() - t0;
	STORE_REL(&d->workers_stop, 1);
	for (i = 0; i < d->cfg.nworkers; i++) {
		__atomic_fetch_add(&d->w[i].ev, 1, __ATOMIC_RELEASE);
		futex_wake(&d->w[i].ev);
	}
	return NULL;
}

/* ------------------------------------------------------------------ */
/* Lifecycle                                                          */
/* ------------------------------------------------------------------ */
static void kd_free(struct kd_dispatcher *d)
{
	free(d->res);
	free(d->done);
	free(d->pend_n);
	free(d->est);
	free(d->w);
	free(d);
}

int kd_start(struct kd_dispatcher **out, struct kim_ctx *c, const struct kd_config *cfg)
{
	struct kd_dispatcher *d;
	int i, err, started = 0;

	if (!cfg->work || cfg->nworkers <= 0 || cfg->nworkers > KD_MAX_WORKERS)
		return -EINVAL;
	d = aligned_alloc(64, sizeof(*d));      /* has 64-byte aligned members */
	if (!d)
		return -ENOMEM;
	memset(d, 0, sizeof(*d));
	d->c = c;
	d->cfg = *cfg;
	for (i = 0; i < KD_PWR_NSTATES; i++)
		if (kd_params_check(&d->cfg.params[i])) {
			free(d);
			return -EINVAL;
		}
	d->nslots = c->hdr->nslots;
	d->mask = d->nslots - 1;
	d->res = aligned_alloc(64, (size_t)d->nslots * sizeof(*d->res));
	d->done = calloc(d->nslots, sizeof(*d->done));
	d->pend_n = calloc(d->nslots, sizeof(*d->pend_n));
	d->est = calloc(d->nslots, sizeof(*d->est));
	d->w = aligned_alloc(64, (size_t)cfg->nworkers * sizeof(*d->w));
	if (!d->res || !d->done || !d->pend_n || !d->est || !d->w) {
		kd_free(d);
		return -ENOMEM;
	}
	memset(d->w, 0, (size_t)cfg->nworkers * sizeof(*d->w));
	d->cur_power = cfg->power;
	d->power_req = cfg->power;
	d->cur = d->cfg.params[cfg->power];
	d->disp_seq = d->comp_seq = d->start_tail = c->tail;

	for (i = 0; i < cfg->nworkers; i++) {
		struct kd_worker *w = &d->w[i];

		w->d = d;
		w->id = i;
		w->cpu = cfg->worker[i].cpu;
		w->cls = cfg->worker[i].cls;
		d->cw[w->cls][d->ncw[w->cls]++] = i;
		err = pthread_create(&w->th, NULL, worker_main, w);
		if (err)
			goto fail;
		started++;
	}
	err = pthread_create(&d->reader, NULL, reader_main, d);
	if (err)
		goto fail;
	*out = d;
	return 0;
fail:
	STORE_REL(&d->workers_stop, 1);
	for (i = 0; i < started; i++) {
		__atomic_fetch_add(&d->w[i].ev, 1, __ATOMIC_RELEASE);
		futex_wake(&d->w[i].ev);
		pthread_join(d->w[i].th, NULL);
	}
	kd_free(d);
	return -err;
}

void kd_set_power(struct kd_dispatcher *d, enum kd_power p)
{
	__atomic_store_n(&d->power_req, (int)p, __ATOMIC_RELAXED);
}

void kd_request_stop(struct kd_dispatcher *d)
{
	STORE_REL(&d->stop, 1);
	__atomic_fetch_add(&d->rev, 1, __ATOMIC_RELEASE);
	futex_wake(&d->rev);
}

void kd_join(struct kd_dispatcher *d, struct kd_totals *tot)
{
	int i;

	pthread_join(d->reader, NULL);
	for (i = 0; i < d->cfg.nworkers; i++) {
		pthread_join(d->w[i].th, NULL);
		d->tot.worker_bytes[i] = d->w[i].bytes;
		d->tot.worker_busy_ns[i] = d->w[i].busy_ns;
		if (d->w[i].pin_err)
			d->tot.pin_failures++;
	}
	if (tot)
		*tot = d->tot;
	kd_free(d);
}
