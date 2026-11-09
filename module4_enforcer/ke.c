// SPDX-License-Identifier: GPL-2.0
/*
 * ke.c - Module 4 policy: classification, rate limiting, summaries and
 * action planning (see ke.h). Side effects only go through cfg.backend.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "ke.h"

#define KE_MAX_NEW     128      /* modules seen loading after the baseline  */
#define KE_MAX_PENDING 32       /* panics waiting for confirmation          */
#define KE_MAX_DONE    32       /* modules already unloaded                 */
#define KE_NAME        (KIM_NAME_LEN + 1)

struct bucket {
	double   tokens;
	uint64_t last_ns;
};

struct pending {
	bool     used;
	uint32_t seg, off, epoch, type;
};

struct ke {
	struct ke_config  cfg;
	struct ke_backend be;
	struct bucket     bk[KE_NSEV];          /* INFO uses the NOTICE bucket */
	uint64_t          period_ns;            /* summary period start        */
	uint64_t          p_sev[KE_NSEV], p_ev[KV_EV_NTYPES], p_suppressed;
	char              newmod[KE_MAX_NEW][KE_NAME];
	int               nnew;
	char              unloaded[KE_MAX_DONE][KE_NAME];
	int               nunloaded;
	struct pending    pend[KE_MAX_PENDING];
	bool              did_lockdown, did_modules, did_panic;  /* done or (dry-run) described */
	struct ke_stats   st;
	char              line[1024];
};

static const char *const SEV_NAMES[KE_NSEV] = { "info", "notice", "warn", "crit", "emerg" };

const char *ke_sev_name(enum ke_sev s)
{
	return s < KE_NSEV ? SEV_NAMES[s] : "?";
}

static uint64_t mono_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

void ke_config_defaults(struct ke_config *cfg)
{
	memset(cfg, 0, sizeof(*cfg));
	cfg->actions = KE_ACT_DEFAULT;
	cfg->panic_confirm = 3;
	cfg->burst = 20;
	cfg->per_min = 10;
	cfg->summary_s = 60;
}

struct ke *ke_new(const struct ke_config *cfg)
{
	struct ke *k = calloc(1, sizeof(*k));
	int i;

	if (!k)
		return NULL;
	k->cfg = *cfg;
	if (!k->cfg.now_ns)
		k->cfg.now_ns = mono_ns;
	k->be = cfg->backend ? *cfg->backend : ke_backend_real;
	k->period_ns = k->cfg.now_ns();
	for (i = 0; i < KE_NSEV; i++) {
		k->bk[i].tokens = k->cfg.burst;
		k->bk[i].last_ns = k->period_ns;
	}
	return k;
}

void ke_free(struct ke *k)
{
	free(k);
}

/* Is name (as truncated in descriptors) in the comma separated list? */
static bool in_list(const char *list, const char *name)
{
	size_t n = strnlen(name, KIM_NAME_LEN);

	while (list && *list) {
		const char *e = strchr(list, ',');
		size_t l = e ? (size_t)(e - list) : strlen(list);

		if (l >= KIM_NAME_LEN)          /* descriptor names are truncated */
			l = KIM_NAME_LEN - 1;
		if (l == n && !strncmp(list, name, n))
			return true;
		list = e ? e + 1 : NULL;
	}
	return false;
}

static void name_of(const struct kim_desc *d, char out[KE_NAME])
{
	memcpy(out, d->name, KIM_NAME_LEN);
	out[KIM_NAME_LEN] = '\0';
}

enum ke_sev ke_classify(const struct ke *k, const struct kv_event *ev, unsigned int *actions)
{
	const unsigned int contain = KE_ACT_LOCKDOWN | KE_ACT_MODULES_OFF | KE_ACT_UNLOAD;
	char name[KE_NAME];

	*actions = 0;
	name_of(&ev->desc, name);
	switch (ev->type) {
	case KV_EV_LEARNED:
	case KV_EV_REVERTED:
		return KE_INFO;
	case KV_EV_TRANSIENT:
		return KE_NOTICE;
	case KV_EV_NEW_SEGMENT:
	case KV_EV_VANISHED:
		return in_list(k->cfg.allow_new, name) ? KE_INFO : KE_WARN;
	case KV_EV_UNSTABLE:
	case KV_EV_FAULT:
		return KE_WARN;
	case KV_EV_WX:
	case KV_EV_REMAP:
		*actions = KE_ACT_LOCKDOWN | KE_ACT_MODULES_OFF;
		return KE_CRIT;
	case KV_EV_CHANGED:
		switch (ev->desc.segment_type) {
		case KIM_SEG_SYSCALL_TABLE:
		case KIM_SEG_COMPAT_TABLE:
			*actions = contain | KE_ACT_PANIC;
			return KE_EMERG;
		case KIM_SEG_MOD_RODATA:
			*actions = contain;
			return KE_CRIT;
		default:
			break;
		}
		if (ev->verdict == KV_X_PATCH_LIKE)
			return in_list(k->cfg.allow_change, name) ? KE_INFO : KE_NOTICE;
		if (ev->verdict == KV_X_NO_BYTES)
			return KE_WARN;
		*actions = contain;
		return KE_CRIT;
	default:
		return KE_WARN;
	}
}

/* ------------------------------------------------------------------ */
/* Delivery                                                           */
/* ------------------------------------------------------------------ */
static bool take_token(struct ke *k, enum ke_sev sev)
{
	struct bucket *b = &k->bk[sev <= KE_NOTICE ? KE_NOTICE : sev];
	uint64_t now = k->cfg.now_ns();

	b->tokens += (double)(now - b->last_ns) / 60e9 * k->cfg.per_min;
	if (b->tokens > k->cfg.burst)
		b->tokens = k->cfg.burst;
	b->last_ns = now;
	if (b->tokens < 1.0)
		return false;
	b->tokens -= 1.0;
	return true;
}

static void deliver(struct ke *k, enum ke_sev sev, enum ke_kind kind, const char *line,
		    const char *detail)
{
	struct ke_alert a = { sev, kind, line, detail ? detail : "" };
	int i;

	for (i = 0; i < k->cfg.nsinks; i++) {
		const struct ke_sink *s = &k->cfg.sinks[i];

		if ((s->kinds & kind) && sev >= s->min_sev)
			s->fn(&a, s->arg);
	}
}

/* First line of a multi-line explanation, quote-safe, for one-line records. */
static void short_detail(const char *d, char *out, size_t n)
{
	size_t o = 0;

	while (*d == '\n' || *d == ' ')
		d++;
	for (; *d && *d != '\n' && o + 1 < n; d++)
		out[o++] = (*d == '"' || *d == '\'') ? '`' : *d;
	out[o] = '\0';
}

static const char *seg_type_name(uint32_t t)
{
	static const char *const n[] = { "?", "ktext", "syscall_table", "compat_table",
					 "mod_text", "mod_rodata" };

	return t < sizeof(n) / sizeof(n[0]) ? n[t] : "?";
}

/* ------------------------------------------------------------------ */
/* Actions                                                            */
/* ------------------------------------------------------------------ */
static void action_line(struct ke *k, enum ke_sev sev, const char *act, const char *target,
			const char *result, int err, const struct kv_event *ev)
{
	char name[KE_NAME];

	name_of(&ev->desc, name);
	snprintf(k->line, sizeof(k->line),
		 "kim_action=%s target=%s result=%s%s%s trigger=%s seg=%s name=%s off=0x%x epoch=%u mode=%s",
		 act, target, result, err ? " errno=" : "", err ? strerror(-err) : "",
		 kv_ev_name(ev->type), seg_type_name(ev->desc.segment_type), name,
		 ev->desc.seg_offset, ev->epoch, k->cfg.enforce ? "enforce" : "dry-run");
	deliver(k, sev, KE_K_ACTION, k->line, NULL);
}

/* Run (or, in dry-run, describe) one action. Returns true if it took effect
 * or would have. */
static bool act(struct ke *k, enum ke_sev sev, unsigned int bit, const char *name,
		const char *target, const struct kv_event *ev)
{
	int r = 0;

	if (!(k->cfg.actions & bit)) {
		k->st.not_enabled++;
		action_line(k, sev, name, target, "not-enabled", 0, ev);
		return false;
	}
	if (!k->cfg.enforce) {
		k->st.would++;
		action_line(k, sev, name, target, "would", 0, ev);
		return true;
	}
	switch (bit) {
	case KE_ACT_LOCKDOWN:    r = k->be.lockdown(k->be.ctx, target); break;
	case KE_ACT_MODULES_OFF: r = k->be.modules_off(k->be.ctx); break;
	case KE_ACT_UNLOAD:      r = k->be.unload(k->be.ctx, target); break;
	case KE_ACT_PANIC:       r = k->be.panic(k->be.ctx); break;
	}
	if (r < 0) {
		k->st.failed++;
		action_line(k, sev, name, target, "failed", r, ev);
		return false;
	}
	k->st.acted++;
	action_line(k, sev, name, target, r == 1 ? "already" : "done", 0, ev);
	return true;
}

static bool is_new_module(const struct ke *k, const char *name)
{
	int i;

	for (i = 0; i < k->nnew; i++)
		if (!strcmp(k->newmod[i], name))
			return true;
	return false;
}

static bool was_unloaded(const struct ke *k, const char *name)
{
	int i;

	for (i = 0; i < k->nunloaded; i++)
		if (!strcmp(k->unloaded[i], name))
			return true;
	return false;
}

/* Suspects: "[module]" annotations in the explanation that name a module
 * loaded after the baseline and not allow-listed. */
static void unload_suspects(struct ke *k, enum ke_sev sev, const struct kv_event *ev)
{
	const char *p = ev->detail;
	int found = 0;

	while (p && (p = strchr(p, '['))) {
		const char *e = strchr(p, ']');
		char name[KE_NAME];
		size_t l;

		if (!e)
			break;
		l = (size_t)(e - p - 1);
		if (l > KIM_NAME_LEN - 1)
			l = KIM_NAME_LEN - 1;   /* compare as descriptors store it */
		memcpy(name, p + 1, l);
		name[l] = '\0';
		p = e + 1;
		if (!is_new_module(k, name) || was_unloaded(k, name))
			continue;
		found++;
		if (act(k, sev, KE_ACT_UNLOAD, "unload", name, ev) && k->nunloaded < KE_MAX_DONE) {
			snprintf(k->unloaded[k->nunloaded++], KE_NAME, "%s", name);
			k->st.unloaded += k->cfg.enforce;
		}
	}
	if (!found)
		action_line(k, sev, "unload", "-", "no-suspect", 0, ev);
}

static void schedule_panic(struct ke *k, enum ke_sev sev, const struct kv_event *ev)
{
	int i;

	if (!(k->cfg.actions & KE_ACT_PANIC)) {
		k->st.not_enabled++;
		action_line(k, sev, "panic", "sysrq-c", "not-enabled", 0, ev);
		return;
	}
	for (i = 0; i < KE_MAX_PENDING; i++)
		if (k->pend[i].used && k->pend[i].seg == ev->desc.segment_id &&
		    k->pend[i].off == ev->desc.seg_offset)
			return;                 /* already waiting for this frame */
	for (i = 0; i < KE_MAX_PENDING; i++)
		if (!k->pend[i].used) {
			k->pend[i] = (struct pending){ true, ev->desc.segment_id,
						       ev->desc.seg_offset, ev->epoch,
						       ev->desc.segment_type };
			k->st.panics_pending++;
			action_line(k, sev, "panic", "sysrq-c", "pending-confirmation", 0, ev);
			return;
		}
}

static void plan(struct ke *k, enum ke_sev sev, unsigned int acts, const struct kv_event *ev)
{
	/* one-shot actions are taken (or described) once per run */
	if ((acts & KE_ACT_LOCKDOWN) && !k->did_lockdown) {
		k->did_lockdown = act(k, sev, KE_ACT_LOCKDOWN, "lockdown", "confidentiality", ev);
		k->st.lockdown_raised = k->did_lockdown && k->cfg.enforce;
	}
	/* unload before modules_disabled: delete_module() is EPERM after it */
	if (acts & KE_ACT_UNLOAD)
		unload_suspects(k, sev, ev);
	if ((acts & KE_ACT_MODULES_OFF) && !k->did_modules) {
		k->did_modules = act(k, sev, KE_ACT_MODULES_OFF, "modules_disabled", "1", ev);
		k->st.modules_disabled = k->did_modules && k->cfg.enforce;
	}
	if ((acts & KE_ACT_PANIC) && !k->did_panic)
		schedule_panic(k, sev, ev);
}

/* ------------------------------------------------------------------ */
void ke_event(struct ke *k, const struct kv_event *ev)
{
	char name[KE_NAME], sd[256];
	unsigned int acts;
	enum ke_sev sev = ke_classify(k, ev, &acts);
	int i;

	name_of(&ev->desc, name);
	k->st.by_sev[sev]++;
	k->p_sev[sev]++;
	if (ev->type < KV_EV_NTYPES)
		k->p_ev[ev->type]++;

	if (ev->type == KV_EV_NEW_SEGMENT && sev > KE_INFO && !is_new_module(k, name) &&
	    k->nnew < KE_MAX_NEW)
		memcpy(k->newmod[k->nnew++], name, KE_NAME);
	if (ev->type == KV_EV_REVERTED)
		for (i = 0; i < KE_MAX_PENDING; i++)
			if (k->pend[i].used && k->pend[i].seg == ev->desc.segment_id &&
			    k->pend[i].off == ev->desc.seg_offset) {
				k->pend[i].used = false;
				k->st.panics_pending--;
				action_line(k, KE_EMERG, "panic", "sysrq-c", "cancelled-reverted", 0, ev);
			}

	short_detail(ev->detail ? ev->detail : "", sd, sizeof(sd));
	snprintf(k->line, sizeof(k->line),
		 "kim_event=%s sev=%s epoch=%u seg=%s name=%s off=0x%x verdict=%s detail=\"%s\"",
		 kv_ev_name(ev->type), ke_sev_name(sev), ev->epoch,
		 seg_type_name(ev->desc.segment_type), name, ev->desc.seg_offset,
		 ev->type == KV_EV_CHANGED ? kv_verdict_name(ev->verdict) : "-", sd);
	if (take_token(k, sev)) {
		deliver(k, sev, KE_K_EVENT, k->line, ev->detail);
	} else {
		k->st.suppressed++;
		k->p_suppressed++;
	}
	if (acts)
		plan(k, sev, acts, ev);
}

static void summary(struct ke *k, uint64_t now)
{
	uint64_t total = 0;
	enum ke_sev top = KE_INFO;
	int i;

	for (i = 0; i < KE_NSEV; i++) {
		total += k->p_sev[i];
		if (k->p_sev[i])
			top = (enum ke_sev)i;
	}
	if (total || k->p_suppressed) {
		snprintf(k->line, sizeof(k->line),
			 "kim_summary period_s=%.0f events=%llu info=%llu notice=%llu warn=%llu crit=%llu emerg=%llu"
			 " suppressed=%llu changed=%llu reverted=%llu transient=%llu new=%llu vanished=%llu",
			 (now - k->period_ns) / 1e9, (unsigned long long)total,
			 (unsigned long long)k->p_sev[KE_INFO], (unsigned long long)k->p_sev[KE_NOTICE],
			 (unsigned long long)k->p_sev[KE_WARN], (unsigned long long)k->p_sev[KE_CRIT],
			 (unsigned long long)k->p_sev[KE_EMERG], (unsigned long long)k->p_suppressed,
			 (unsigned long long)k->p_ev[KV_EV_CHANGED],
			 (unsigned long long)k->p_ev[KV_EV_REVERTED],
			 (unsigned long long)k->p_ev[KV_EV_TRANSIENT],
			 (unsigned long long)k->p_ev[KV_EV_NEW_SEGMENT],
			 (unsigned long long)k->p_ev[KV_EV_VANISHED]);
		deliver(k, top, KE_K_SUMMARY, k->line, NULL);
	}
	memset(k->p_sev, 0, sizeof(k->p_sev));
	memset(k->p_ev, 0, sizeof(k->p_ev));
	k->p_suppressed = 0;
	k->period_ns = now;
}

void ke_epoch_end(struct ke *k, uint32_t epoch)
{
	uint64_t now = k->cfg.now_ns();
	int i;

	for (i = 0; i < KE_MAX_PENDING; i++) {
		struct pending *p = &k->pend[i];
		struct kv_event ev;

		if (!p->used || (int32_t)(epoch - p->epoch) < (int32_t)k->cfg.panic_confirm)
			continue;
		/* still changed after panic_confirm more complete epochs */
		memset(&ev, 0, sizeof(ev));
		ev.type = KV_EV_CHANGED;
		ev.epoch = epoch;
		ev.desc.segment_id = p->seg;
		ev.desc.seg_offset = p->off;
		ev.desc.segment_type = p->type;
		p->used = false;
		k->st.panics_pending--;
		if (!k->did_panic && act(k, KE_EMERG, KE_ACT_PANIC, "panic", "sysrq-c", &ev)) {
			k->did_panic = true;
			k->st.panicked = k->cfg.enforce;
		}
	}
	if (now - k->period_ns >= (uint64_t)k->cfg.summary_s * 1000000000ull)
		summary(k, now);
}

void ke_flush(struct ke *k)
{
	summary(k, k->cfg.now_ns());
}

void ke_get_stats(const struct ke *k, struct ke_stats *st)
{
	*st = k->st;
}
