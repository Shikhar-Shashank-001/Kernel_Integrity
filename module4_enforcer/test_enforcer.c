// SPDX-License-Identifier: GPL-2.0
/*
 * test_enforcer.c - Module 4 tests. No root; every action goes to a mock
 * backend and time comes from a fake clock, so nothing on the host changes.
 *
 *   E1 severity / action policy for every event kind
 *   E2 dry-run: actions described once, backend never called
 *   E3 enforce: lockdown + modules_disabled once, failures reported
 *   E4 unload only suspects (loaded after baseline AND named as hook target)
 *   E5 panic deferred by panic_confirm epochs, cancelled by REVERTED
 *   E6 rate limiting per severity, actions never rate limited
 *   E7 periodic summary, sink severity/kind filters, allow-lists
 *   E8 real backend, read-only: current lockdown level of this machine
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ke.h"

static int g_fail, g_pass;
#define PASS(...) do { g_pass++; printf("  [PASS] "); printf(__VA_ARGS__); putchar('\n'); } while (0)
#define FAIL(...) do { g_fail++; printf("  [FAIL] "); printf(__VA_ARGS__); putchar('\n'); } while (0)
#define CHECK(c, ...) do { if (c) PASS(__VA_ARGS__); else FAIL(__VA_ARGS__); } while (0)

/* ---------------- mocks ---------------- */
static uint64_t g_now = 1000000000ull;
static uint64_t fake_now(void) { return g_now; }

struct mock {
	int  lockdown, modules, unload, panic;
	char lockdown_level[32], unloaded[8][32];
	int  fail_lockdown;
};
static struct mock M;

static int m_lockdown(void *c, const char *l)
{
	(void)c;
	M.lockdown++;
	snprintf(M.lockdown_level, sizeof(M.lockdown_level), "%s", l);
	return M.fail_lockdown ? -EPERM : 0;
}
static int m_modules(void *c) { (void)c; M.modules++; return 0; }
static int m_unload(void *c, const char *m)
{
	(void)c;
	if (M.modules)          /* as the kernel: delete_module() is EPERM once
				   kernel.modules_disabled=1 */
		return -EPERM;
	if (M.unload < 8)
		snprintf(M.unloaded[M.unload], 32, "%s", m);
	M.unload++;
	return 0;
}
static int m_panic(void *c) { (void)c; M.panic++; return 0; }
static const struct ke_backend MOCK = { m_lockdown, m_modules, m_unload, m_panic, NULL };

struct cap { enum ke_sev sev; enum ke_kind kind; char line[1024]; };
static struct cap g_cap[512];
static int g_ncap;

static void sink_cap(const struct ke_alert *a, void *arg)
{
	(void)arg;
	if (g_ncap < 512) {
		g_cap[g_ncap].sev = a->sev;
		g_cap[g_ncap].kind = a->kind;
		snprintf(g_cap[g_ncap].line, sizeof(g_cap[0].line), "%s", a->line);
		g_ncap++;
	}
	if (getenv("KE_VERBOSE"))
		printf("      > [%s] %s\n", ke_sev_name(a->sev), a->line);
}

static int ncap(enum ke_kind kind, const char *needle)
{
	int i, n = 0;

	for (i = 0; i < g_ncap; i++)
		n += (g_cap[i].kind & kind) && (!needle || strstr(g_cap[i].line, needle));
	return n;
}

static void reset(void)
{
	memset(&M, 0, sizeof(M));
	g_ncap = 0;
	g_now = 1000000000ull;
}

static struct ke_config cfg_base(bool enforce, unsigned int actions)
{
	struct ke_config c;

	ke_config_defaults(&c);
	c.enforce = enforce;
	c.actions = actions;
	c.backend = &MOCK;
	c.now_ns = fake_now;
	c.sinks[0] = (struct ke_sink){ sink_cap, NULL, KE_INFO, KE_K_ALL };
	c.nsinks = 1;
	return c;
}

static struct kv_event mk(enum kv_ev_type t, uint32_t segtype, const char *name, uint32_t id,
			  uint32_t off, enum kv_verdict v, const char *detail, uint32_t epoch)
{
	struct kv_event e;

	memset(&e, 0, sizeof(e));
	e.type = t;
	e.epoch = epoch;
	e.verdict = v;
	e.detail = detail;
	e.desc.segment_type = segtype;
	e.desc.segment_id = id;
	e.desc.seg_offset = off;
	e.desc.scan_epoch = epoch;
	snprintf(e.desc.name, sizeof(e.desc.name), "%s", name);
	return e;
}

#define CHG_PATCH(ep)  mk(KV_EV_CHANGED, KIM_SEG_KTEXT, "ktext", 1, 0x4000, KV_X_PATCH_LIKE, \
			  "\n  +0x4010 f+0x10/0x100 (3 B): 0f1f44 -> e92b00 nop5->jmp", (ep))
#define CHG_EVIL(ep)   mk(KV_EV_CHANGED, KIM_SEG_KTEXT, "ktext", 1, 0x8000, KV_X_UNEXPLAINED, \
			  "\n  +0x8020 f+0x20/0x100 (5 B): 0f1f440000 -> e8dbffff3e nop5->call " \
			  "target=evil_hook+0x0/0x100 [rootkit] (implausible target)" \
			  "\n  +0x8100 g+0x0/0x80 (5 B): ... was=kvm_x+0x0/0x10 [kvm]", (ep))
#define CHG_SCT(ep)    mk(KV_EV_CHANGED, KIM_SEG_SYSCALL_TABLE, "sys_call_table", 2, 0, \
			  KV_X_UNEXPLAINED, "\n  sys_call_table[0]: __x64_sys_read -> " \
			  "evil_hook+0x0/0x100 [rootkit]", (ep))
#define NEWSEG(n, ep)  mk(KV_EV_NEW_SEGMENT, KIM_SEG_MOD_TEXT, (n), 50, 0, KV_X_UNEXPLAINED, \
			  "segment appeared after learning", (ep))

/* ------------------------------------------------------------------ */
static void t_policy(void)
{
	struct ke_config c = cfg_base(false, KE_ACT_DEFAULT);
	struct ke *k;
	unsigned int a;
	struct kv_event e;

	puts("E1 severity / action policy");
	k = ke_new(&c);
#define SEV(ev, s, acts, msg) do { struct kv_event _e = (ev); \
	CHECK(ke_classify(k, &_e, &a) == (s) && a == (acts), msg " -> %s", ke_sev_name(s)); } while (0)
	SEV(CHG_PATCH(5), KE_NOTICE, 0u, "patch-like ktext change");
	SEV(CHG_EVIL(5), KE_CRIT, KE_ACT_LOCKDOWN | KE_ACT_MODULES_OFF | KE_ACT_UNLOAD,
	    "unexplained ktext change");
	SEV(CHG_SCT(5), KE_EMERG, KE_ACT_ALL, "syscall table change");
	e = CHG_PATCH(5);
	e.desc.segment_type = KIM_SEG_MOD_RODATA;
	SEV(e, KE_CRIT, KE_ACT_LOCKDOWN | KE_ACT_MODULES_OFF | KE_ACT_UNLOAD,
	    "module rodata change, even if patch-like");
	e = CHG_PATCH(5);
	e.verdict = KV_X_NO_BYTES;
	SEV(e, KE_WARN, 0u, "change without baseline bytes");
	SEV(mk(KV_EV_WX, KIM_SEG_KTEXT, "ktext", 1, 0, 0, "", 5), KE_CRIT,
	    KE_ACT_LOCKDOWN | KE_ACT_MODULES_OFF, "writable PTE on text");
	SEV(mk(KV_EV_REMAP, KIM_SEG_KTEXT, "ktext", 1, 0, 0, "", 5), KE_CRIT,
	    KE_ACT_LOCKDOWN | KE_ACT_MODULES_OFF, "kernel text page remapped");
	SEV(NEWSEG("dummy", 5), KE_WARN, 0u, "module loaded after learning");
	SEV(mk(KV_EV_REVERTED, KIM_SEG_KTEXT, "ktext", 1, 0, 0, "", 5), KE_INFO, 0u, "revert");
	SEV(mk(KV_EV_TRANSIENT, KIM_SEG_KTEXT, "ktext", 1, 0, 0, "", 5), KE_NOTICE, 0u, "transient");
	SEV(mk(KV_EV_FAULT, KIM_SEG_KTEXT, "ktext", 1, 0, 0, "", 5), KE_WARN, 0u, "fault");
	ke_free(k);

	c.allow_new = "usb_storage,dummy";
	c.allow_change = "ktext";
	k = ke_new(&c);
	SEV(NEWSEG("dummy", 5), KE_INFO, 0u, "allow-listed module load");
	SEV(CHG_PATCH(5), KE_INFO, 0u, "allow-listed patch-like change");
	SEV(CHG_EVIL(5), KE_CRIT, KE_ACT_LOCKDOWN | KE_ACT_MODULES_OFF | KE_ACT_UNLOAD,
	    "allow-list never downgrades an unexplained change");
	ke_free(k);
	c.allow_new = "snd_soc_skl_hda_dsp_generic";    /* longer than descriptor names */
	k = ke_new(&c);
	SEV(NEWSEG("snd_soc_skl_hda_dsp_generic", 5), KE_INFO, 0u,
	    "allow-list matches names truncated to 19 chars");
#undef SEV
	ke_free(k);
}

static void t_dryrun(void)
{
	struct ke_config c = cfg_base(false, KE_ACT_DEFAULT);
	struct ke *k = ke_new(&c);
	struct kv_event e = CHG_EVIL(7), e2 = CHG_EVIL(8);
	struct ke_stats st;

	puts("E2 dry-run");
	reset();
	ke_event(k, &e);
	ke_event(k, &e2);
	ke_get_stats(k, &st);
	CHECK(M.lockdown == 0 && M.modules == 0 && M.unload == 0 && M.panic == 0,
	      "backend never called");
	CHECK(ncap(KE_K_ACTION, "kim_action=lockdown target=confidentiality result=would") == 1 &&
	      ncap(KE_K_ACTION, "kim_action=modules_disabled target=1 result=would") == 1,
	      "lockdown and modules_disabled described once ('would'), not per event");
	CHECK(ncap(KE_K_ACTION, "kim_action=unload target=- result=no-suspect") == 2 &&
	      ncap(KE_K_ACTION, "mode=dry-run") == 4, "unload: no suspect (module not new)");
	CHECK(ncap(KE_K_EVENT, "kim_event=CHANGED sev=crit") == 2 && st.would == 2,
	      "both CHANGED events alerted");
	ke_free(k);
}

static void t_enforce(void)
{
	struct ke_config c = cfg_base(true, KE_ACT_DEFAULT);
	struct ke *k;
	struct kv_event e = CHG_EVIL(7), e2 = CHG_EVIL(9);
	struct ke_stats st;

	puts("E3 enforce");
	reset();
	k = ke_new(&c);
	ke_event(k, &e);
	ke_event(k, &e2);
	ke_get_stats(k, &st);
	CHECK(M.lockdown == 1 && !strcmp(M.lockdown_level, "confidentiality") && M.modules == 1,
	      "lockdown(confidentiality) and modules_disabled executed exactly once");
	CHECK(M.unload == 0 && M.panic == 0 && st.lockdown_raised && st.modules_disabled,
	      "unload/panic untouched (not in the default action set)");
	ke_free(k);

	reset();
	M.fail_lockdown = 1;
	k = ke_new(&c);
	ke_event(k, &e);
	ke_get_stats(k, &st);
	CHECK(st.failed == 1 && ncap(KE_K_ACTION, "result=failed errno=Operation not permitted") == 1 &&
	      !st.lockdown_raised, "backend failure reported with errno");
	ke_free(k);
}

static void t_unload(void)
{
	struct ke_config c = cfg_base(true, KE_ACT_DEFAULT | KE_ACT_UNLOAD);
	struct ke *k;
	struct kv_event n = NEWSEG("rootkit", 6), e = CHG_EVIL(7), e2 = CHG_EVIL(9);

	puts("E4 unload suspects");
	reset();
	k = ke_new(&c);
	ke_event(k, &n);
	ke_event(k, &e);
	ke_event(k, &e2);
	CHECK(M.unload == 1 && !strcmp(M.unloaded[0], "rootkit"),
	      "only 'rootkit' unloaded (new + hook target); 'kvm' (old) left alone; once");
	ke_free(k);

	reset();
	c.allow_new = "rootkit";
	k = ke_new(&c);
	ke_event(k, &n);
	ke_event(k, &e);
	CHECK(M.unload == 0 && ncap(KE_K_ACTION, "result=no-suspect") == 1,
	      "allow-listed module is never a suspect");
	ke_free(k);
}

static void t_panic(void)
{
	struct ke_config c = cfg_base(true, KE_ACT_ALL);
	struct ke *k;
	struct kv_event e = CHG_SCT(10), rv;
	struct ke_stats st;

	puts("E5 deferred panic");
	reset();
	k = ke_new(&c);
	ke_event(k, &e);
	ke_epoch_end(k, 10);
	ke_epoch_end(k, 11);
	ke_epoch_end(k, 12);
	CHECK(M.panic == 0 && ncap(KE_K_ACTION, "result=pending-confirmation") == 1,
	      "not before panic_confirm (3) more epochs");
	ke_epoch_end(k, 13);
	ke_epoch_end(k, 14);
	ke_get_stats(k, &st);
	CHECK(M.panic == 1 && st.panicked && st.panics_pending == 0,
	      "panic exactly once after the change persisted 3 epochs");
	ke_free(k);

	reset();
	k = ke_new(&c);
	ke_event(k, &e);
	rv = mk(KV_EV_REVERTED, KIM_SEG_SYSCALL_TABLE, "sys_call_table", 2, 0, 0, "", 11);
	ke_event(k, &rv);
	ke_epoch_end(k, 13);
	CHECK(M.panic == 0 && ncap(KE_K_ACTION, "result=cancelled-reverted") == 1,
	      "REVERTED before confirmation cancels the panic");
	ke_free(k);

	reset();
	c.enforce = false;
	k = ke_new(&c);
	ke_event(k, &e);
	ke_epoch_end(k, 13);
	CHECK(M.panic == 0 && ncap(KE_K_ACTION, "kim_action=panic target=sysrq-c result=would") == 1,
	      "dry-run: 'would panic', backend untouched");
	ke_free(k);

	reset();
	c = cfg_base(true, KE_ACT_DEFAULT);
	k = ke_new(&c);
	ke_event(k, &e);
	ke_epoch_end(k, 20);
	CHECK(M.panic == 0 && ncap(KE_K_ACTION, "kim_action=panic target=sysrq-c result=not-enabled") == 1,
	      "panic not in the action set: reported as not-enabled, never pending");
	ke_free(k);
}

static void t_ratelimit(void)
{
	struct ke_config c = cfg_base(false, KE_ACT_DEFAULT);
	struct ke *k;
	struct ke_stats st;
	int i;

	puts("E6 rate limiting");
	reset();
	c.burst = 5;
	c.per_min = 10;
	k = ke_new(&c);
	for (i = 0; i < 20; i++) {
		struct kv_event e = NEWSEG("mod", 5);

		ke_event(k, &e);
	}
	ke_get_stats(k, &st);
	CHECK(ncap(KE_K_EVENT, NULL) == 5 && st.suppressed == 15, "burst 5: 5 delivered, 15 suppressed");
	g_now += 60ull * 1000000000ull;
	for (i = 0; i < 20; i++) {
		struct kv_event e = NEWSEG("mod", 6);

		ke_event(k, &e);
	}
	CHECK(ncap(KE_K_EVENT, NULL) == 10, "after a minute the bucket refills (capped at burst)");
	for (i = 0; i < 10; i++) {
		struct kv_event e = CHG_EVIL(7);

		ke_event(k, &e);
	}
	CHECK(ncap(KE_K_EVENT, "sev=crit") == 5 && ncap(KE_K_ACTION, NULL) == 12,
	      "CRIT has its own bucket; action records are never suppressed");
	ke_flush(k);
	CHECK(ncap(KE_K_SUMMARY, "suppressed=35") == 1, "summary reports all 35 suppressed (30 WARN + 5 CRIT)");
	ke_free(k);
}

static void t_summary(void)
{
	struct ke_config c = cfg_base(false, KE_ACT_DEFAULT);
	struct ke *k;
	int i;

	puts("E7 summaries and sink filters");
	reset();
	c.summary_s = 60;
	c.sinks[1] = (struct ke_sink){ sink_cap, NULL, KE_WARN, KE_K_EVENT };
	c.nsinks = 2;
	k = ke_new(&c);
	for (i = 0; i < 4; i++) {
		struct kv_event a = CHG_PATCH(5), b = mk(KV_EV_REVERTED, KIM_SEG_KTEXT, "ktext", 1,
							 0x4000, 0, "", 6);

		ke_event(k, &a);
		ke_event(k, &b);
	}
	CHECK(ncap(KE_K_EVENT, NULL) == 8, "WARN-only sink got none of the 8 NOTICE/INFO events");
	g_now += 30ull * 1000000000ull;
	ke_epoch_end(k, 6);
	CHECK(ncap(KE_K_SUMMARY, NULL) == 0, "no summary before the period ends");
	g_now += 31ull * 1000000000ull;
	ke_epoch_end(k, 7);
	CHECK(ncap(KE_K_SUMMARY, "events=8 info=4 notice=4") == 1 &&
	      ncap(KE_K_SUMMARY, "changed=4 reverted=4") == 1, "periodic summary with counts");
	g_now += 61ull * 1000000000ull;
	ke_epoch_end(k, 8);
	CHECK(ncap(KE_K_SUMMARY, NULL) == 1, "quiet period: no empty summary");
	ke_free(k);
}

static void t_real_readonly(void)
{
	char lvl[32];
	int err = ke_lockdown_current(lvl, sizeof(lvl));

	puts("E8 real backend (read-only)");
	CHECK(!err && (!strcmp(lvl, "none") || !strcmp(lvl, "integrity") ||
		       !strcmp(lvl, "confidentiality")), "current lockdown level: %s", err ? "?" : lvl);
}

int main(void)
{
	t_policy();
	t_dryrun();
	t_enforce();
	t_unload();
	t_panic();
	t_ratelimit();
	t_summary();
	t_real_readonly();
	printf("\n%d passed, %d failed\n", g_pass, g_fail);
	return g_fail ? 1 : 0;
}
