/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ke.h - Module 4: classify integrity events, alert, and (optionally) act.
 *
 * Input: kv_event from the Module-3 baseline (CHANGED, REVERTED, NEW_SEGMENT...).
 *
 * Severity policy (ke_classify):
 *   EMERG   CHANGED in a syscall table (read-only data that is never patched)
 *   CRIT    CHANGED code that the explainer could not match to a legitimate
 *           patch, CHANGED module rodata, writable PTE on code/read-only data
 *   WARN    module loaded/unloaded after learning (unless allow-listed),
 *           unreadable page, unstable while learning, change without bytes
 *   NOTICE  patch-like code change (jump label, ftrace, static call), transient
 *   INFO    revert, allow-listed changes, learning finished
 *
 * Actions (only with enforce; dry-run logs what would happen):
 *   KE_ACT_LOCKDOWN    CRIT+  raise /sys/kernel/security/lockdown to confidentiality
 *   KE_ACT_MODULES_OFF CRIT+  kernel.modules_disabled = 1 (no further module loads)
 *   KE_ACT_UNLOAD      CRIT+  delete_module() of SUSPECT modules: loaded after the
 *                             baseline AND named as a branch target of the change.
 *                             Can crash the kernel if their hooks are still live.
 *   KE_ACT_PANIC       EMERG  sysrq 'c' once the change persisted panic_confirm
 *                             more complete epochs; cancelled by REVERTED.
 * Lockdown and modules_disabled are one-way until reboot but not destructive:
 * they are the default enforcement set. Unload and panic must be asked for.
 *
 * Alerts are single-line key=value records delivered to sinks (console,
 * syslog/journald, auditd). WARN+ are rate limited per severity, INFO/NOTICE
 * share one bucket and are also folded into a periodic summary. Action and
 * summary records are never rate limited. Single-threaded, like kv_baseline.
 */
#ifndef KE_H
#define KE_H

#include <stdbool.h>
#include <stdint.h>

#include "kv_baseline.h"

enum ke_sev { KE_INFO = 0, KE_NOTICE, KE_WARN, KE_CRIT, KE_EMERG, KE_NSEV };

enum {
	KE_ACT_LOCKDOWN    = 1u << 0,
	KE_ACT_MODULES_OFF = 1u << 1,
	KE_ACT_UNLOAD      = 1u << 2,
	KE_ACT_PANIC       = 1u << 3,
	KE_ACT_ALL         = 0xfu,
	KE_ACT_DEFAULT     = KE_ACT_LOCKDOWN | KE_ACT_MODULES_OFF,
};

/* What the actions do; tests plug in a mock. Return 0, 1 (already in that
 * state, nothing done) or -errno. */
struct ke_backend {
	int  (*lockdown)(void *ctx, const char *level);
	int  (*modules_off)(void *ctx);
	int  (*unload)(void *ctx, const char *module);
	int  (*panic)(void *ctx);
	void *ctx;
};

extern const struct ke_backend ke_backend_real;

enum ke_kind { KE_K_EVENT = 1, KE_K_ACTION = 2, KE_K_SUMMARY = 4, KE_K_ALL = 7 };

struct ke_alert {
	enum ke_sev  sev;
	enum ke_kind kind;
	const char  *line;       /* "kim_event=CHANGED sev=crit ..." */
	const char  *detail;     /* multi-line explanation or ""     */
};

typedef void (*ke_sink_fn)(const struct ke_alert *a, void *arg);

struct ke_sink {
	ke_sink_fn   fn;
	void        *arg;
	enum ke_sev  min_sev;    /* events below this are not delivered      */
	unsigned int kinds;      /* KE_K_* mask                              */
};

#define KE_MAX_SINKS 4

struct ke_config {
	bool         enforce;          /* false = dry-run                          */
	unsigned int actions;          /* KE_ACT_* allowed (default KE_ACT_DEFAULT) */
	unsigned int panic_confirm;    /* complete epochs after CHANGED      (3)    */
	unsigned int burst, per_min;   /* rate limit per severity bucket (20, 10)   */
	unsigned int summary_s;        /* INFO/NOTICE summary period, s      (60)   */
	const char  *allow_new;        /* "dummy,usb_storage": expected modules     */
	const char  *allow_change;     /* "ktext,kvm": patch-like changes -> INFO   */
	const struct ke_backend *backend;   /* NULL = ke_backend_real              */
	struct ke_sink sinks[KE_MAX_SINKS];
	int          nsinks;
	uint64_t   (*now_ns)(void);    /* NULL = CLOCK_MONOTONIC                    */
};

struct ke_stats {
	uint64_t by_sev[KE_NSEV];      /* events classified                        */
	uint64_t suppressed;           /* alerts dropped by the rate limit         */
	uint64_t acted, would, failed, not_enabled;
	bool     lockdown_raised, modules_disabled, panicked;
	unsigned int panics_pending, unloaded;
};

struct ke;

const char *ke_sev_name(enum ke_sev s);
void        ke_config_defaults(struct ke_config *cfg);
struct ke  *ke_new(const struct ke_config *cfg);
void        ke_free(struct ke *k);

/* Policy only (no side effects): severity and recommended KE_ACT_* bits. */
enum ke_sev ke_classify(const struct ke *k, const struct kv_event *ev, unsigned int *actions);

void ke_event(struct ke *k, const struct kv_event *ev);
void ke_epoch_end(struct ke *k, uint32_t epoch);   /* deferred panics, summary */
void ke_flush(struct ke *k);                       /* final summary            */
void ke_get_stats(const struct ke *k, struct ke_stats *st);

/* Sinks (ke_io.c). console: arg = FILE*. audit: arg = &fd from ke_audit_open(). */
void ke_sink_console(const struct ke_alert *a, void *arg);
void ke_sink_syslog(const struct ke_alert *a, void *arg);
void ke_sink_audit(const struct ke_alert *a, void *arg);
int  ke_audit_open(void);                          /* fd or -errno (needs root) */
int  ke_lockdown_current(char *buf, size_t n);     /* "integrity" etc.          */

#endif /* KE_H */
