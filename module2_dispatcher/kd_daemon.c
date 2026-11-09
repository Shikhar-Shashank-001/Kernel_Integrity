// SPDX-License-Identifier: GPL-2.0
/*
 * kd_daemon.c - Module 2 driver: kernel ring -> hybrid P/E pipeline.
 *
 * Each worker computes the Module-3 frame tag (AES-256-GCM-SIV, -T siv, the
 * default) or the AVX2 xor checksum (-T xor). Tags are folded in ring order
 * into a per-epoch digest, which must not change with alpha/beta/thread
 * counts for the same key and kernel text: pass -k to fix the key when
 * comparing runs (the default key is random per run).
 *
 * With the SIV tag the daemon learns an in-memory baseline over the first -L
 * complete epochs, then checks every scan against it (Module 3 kv_baseline):
 * confirmed changes, reverts, transients, module load/unload, W^X and faults
 * are printed as [EVENT] lines, changed frames with a byte-level explanation.
 *
 * Module 4 (ke) classifies every event, alerts to syslog/journald and auditd
 * (rate limited, with periodic summaries) and plans actions: dry-run by
 * default, -e to enforce (lockdown + modules_disabled; -A adds unload/panic).
 *
 *   sudo insmod ../kernel_extractor.ko scan_interval_ms=0
 *   sudo ./kd_daemon -t 10
 */
#include <dirent.h>
#include <errno.h>
#include <sched.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/random.h>

#include "kd_dispatcher.h"
#include "kv_tag.h"
#include "kv_baseline.h"
#include "ke.h"

static volatile sig_atomic_t g_stop;
static struct kd_dispatcher *g_disp;
static int g_power = -1;
static int g_quiet;
static uint64_t g_digest;
static uint64_t g_copied;        /* payload bytes of copied (non-direct) frames */
static struct kv_key g_key;      /* mlock()ed, wiped at exit */
static struct kv_baseline *g_base;
static struct ke *g_ke;
static int g_audit_fd = -1;

static void on_sig(int s) { (void)s; g_stop = 1; }

static inline uint64_t mix64(uint64_t x)
{
	x += 0x9e3779b97f4a7c15ull;
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ull;
	x = (x ^ (x >> 27)) * 0x94d049bb133111ebull;
	return x ^ (x >> 31);
}

static void xor_work(const struct kim_chunk *ck, struct kd_result *out, void *arg)
{
	uint32_t i;

	(void)arg;
	for (i = 0; i < ck->nframes; i++) {
		uint64_t t = kim_xor_checksum(ck->data + (size_t)i * KIM_FRAME_BYTES,
					      out[i].desc.length);

		memcpy(out[i].tag, &t, sizeof(t));
	}
}

static void siv_work(const struct kim_chunk *ck, struct kd_result *out, void *arg)
{
	const struct kv_key *k = arg;
	uint32_t i;

	for (i = 0; i < ck->nframes; i++)
		kv_frame_tag(k, &out[i].desc, ck->data + (size_t)i * KIM_FRAME_BYTES, out[i].tag);
}

/* -k: 32 or 64 hex digits; otherwise a random 256-bit key. */
static int load_key(const char *hex)
{
	uint8_t raw[32];
	size_t n = 32, i;
	int err;

	if (hex) {
		n = strlen(hex) / 2;
		if ((n != 16 && n != 32) || strlen(hex) != 2 * n)
			return -EINVAL;
		for (i = 0; i < n; i++) {
			unsigned int v;

			if (sscanf(hex + 2 * i, "%2x", &v) != 1)
				return -EINVAL;
			raw[i] = (uint8_t)v;
		}
	} else if (getrandom(raw, sizeof(raw), 0) != (ssize_t)sizeof(raw)) {
		return -errno;
	}
	if (mlock(&g_key, sizeof(g_key)))
		perror("mlock (key may be swapped)");
	err = kv_key_init(&g_key, raw, n, NULL, KV_IMPL_AUTO);
	explicit_bzero(raw, sizeof(raw));
	return err;
}

/*
 * Profile of the kernel producer thread (kim_extractor): /proc/<pid>/schedstat
 * gives its on-CPU and runqueue-wait time, /proc/<pid>/stat field 39 the CPU it
 * last ran on (sampled every 100 ms). In free-run mode the rest is sleep, i.e.
 * the ring-full back-off.
 */
struct kprof {
	int      pid;
	uint64_t run0, wait0;
	uint32_t hits[KD_MAX_CPUS], samples;
};

static int kprof_find(void)
{
	DIR *dir = opendir("/proc");
	struct dirent *e;
	int pid = -1;

	if (!dir)
		return -1;
	while (pid < 0 && (e = readdir(dir))) {
		char p[300], comm[32];
		FILE *f;

		if (e->d_name[0] < '1' || e->d_name[0] > '9')
			continue;
		snprintf(p, sizeof(p), "/proc/%s/comm", e->d_name);
		f = fopen(p, "r");
		if (!f)
			continue;
		if (fgets(comm, sizeof(comm), f) && !strcmp(comm, "kim_extractor\n"))
			pid = atoi(e->d_name);
		fclose(f);
	}
	closedir(dir);
	return pid;
}

static int kprof_schedstat(int pid, uint64_t *run, uint64_t *wait)
{
	char p[64];
	FILE *f;
	int ok;

	snprintf(p, sizeof(p), "/proc/%d/schedstat", pid);
	f = fopen(p, "r");
	if (!f)
		return -1;
	ok = fscanf(f, "%" SCNu64 " %" SCNu64, run, wait) == 2;
	fclose(f);
	return ok ? 0 : -1;
}

static void kprof_sample(struct kprof *k)
{
	char p[64], buf[1024], *s;
	FILE *f;
	int i, cpu;

	if (k->pid < 0)
		return;
	snprintf(p, sizeof(p), "/proc/%d/stat", k->pid);
	f = fopen(p, "r");
	if (!f)
		return;
	if (fgets(buf, sizeof(buf), f) && (s = strrchr(buf, ')'))) {
		s += 2;                         /* field 3 */
		for (i = 3; i < 39 && s; i++)
			if ((s = strchr(s, ' ')))
				s++;
		cpu = s ? atoi(s) : -1;
		if (cpu >= 0 && cpu < KD_MAX_CPUS) {
			k->hits[cpu]++;
			k->samples++;
		}
	}
	fclose(f);
}

/*
 * The kernel copy thread is the pipeline's limit (CLAUDE.md 4.8, profile round 2):
 * on an SMT sibling of a busy worker it copies ~12% slower. Reserve the last P
 * core for it. Returns a CPU of a P core no worker uses, or -1.
 */
static int kthread_core_pick(const struct kd_topo *t, const struct kd_config *cfg)
{
	int i, w;

	for (i = t->ncpu - 1; i >= 0; i--) {
		const struct kd_cpu *k = &t->cpus[i];
		bool used = false;

		if (k->cls != KD_P)
			continue;
		for (w = 0; w < cfg->nworkers && !used; w++) {
			int j;

			for (j = 0; j < t->ncpu; j++)
				if (t->cpus[j].cpu == cfg->worker[w].cpu)
					used = t->cpus[j].core == k->core;
		}
		if (!used)
			return k->core;         /* lowest CPU of that core */
	}
	return -1;
}

static int core_of(const struct kd_topo *t, int cpu)
{
	int i;

	for (i = 0; i < t->ncpu; i++)
		if (t->cpus[i].cpu == cpu)
			return t->cpus[i].core;
	return -1;
}

/* Pin the (unbound) kim_extractor kthread; *saved gets its old mask for kthread_unpin(). */
static int kthread_pin(int pid, int cpu, cpu_set_t *saved)
{
	cpu_set_t set;

	if (sched_getaffinity(pid, sizeof(*saved), saved))
		return -errno;
	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	return sched_setaffinity(pid, sizeof(set), &set) ? -errno : 0;
}

static void kprof_start(struct kprof *k)
{
	memset(k, 0, sizeof(*k));
	k->pid = kprof_find();
	if (k->pid >= 0 && kprof_schedstat(k->pid, &k->run0, &k->wait0))
		k->pid = -1;
}

static void kprof_print(struct kprof *k, const struct kd_topo *t, uint64_t wall_ns)
{
	uint64_t run, wait;
	int i, j, shown = 0;

	if (k->pid < 0 || kprof_schedstat(k->pid, &run, &wait) || !wall_ns) {
		printf("kernel thread: no profile (kim_extractor not found)\n");
		return;
	}
	run -= k->run0;
	wait -= k->wait0;
	printf("kernel thread: on CPU %.0f%% | runnable, waiting for a CPU %.0f%% | asleep %.0f%% "
	       "(ring-full back-off) | ran on:",
	       100.0 * run / wall_ns, 100.0 * wait / wall_ns,
	       100.0 * (wall_ns > run + wait ? wall_ns - run - wait : 0) / wall_ns);
	for (j = 0; j < 4 && k->samples; j++) {        /* top CPUs by samples */
		int best = -1;

		for (i = 0; i < KD_MAX_CPUS; i++)
			if (k->hits[i] && (best < 0 || k->hits[i] > k->hits[best]))
				best = i;
		if (best < 0)
			break;
		for (i = 0; i < t->ncpu && t->cpus[i].cpu != best; i++)
			;
		printf(" cpu%d(%s) %.0f%%", best,
		       i < t->ncpu ? kd_class_name(t->cpus[i].cls) : "?",
		       100.0 * k->hits[best] / k->samples);
		k->hits[best] = 0;
		shown++;
	}
	printf("%s\n", shown ? "" : " ?");
}

static void on_result(const struct kd_result *r, void *arg)
{
	uint64_t t;

	(void)arg;
	memcpy(&t, r->tag, sizeof(t));
	if (!(r->desc.flags & KIM_F_DIRECT))
		g_copied += r->desc.length;
	g_digest = mix64(g_digest ^ ((uint64_t)r->desc.segment_type << 32 | r->desc.seg_offset));
	g_digest = mix64(g_digest ^ t);
	if (g_base)
		kv_baseline_frame(g_base, &r->desc, r->tag, r->payload);
}

static const char *seg_type_name(uint32_t t)
{
	static const char *const n[] = { "?", "ktext", "syscall_table", "compat_table",
					 "mod_text", "mod_rodata" };

	return t < sizeof(n) / sizeof(n[0]) ? n[t] : "?";
}

static void on_kv_event(const struct kv_event *ev, void *arg)
{
	const char *d = ev->detail ? ev->detail : "";

	(void)arg;
	if (ev->type == KV_EV_LEARNED) {
		printf("[EVENT] LEARNED epoch %u: baseline of %s; checking from now on\n", ev->epoch, d);
	} else {
		printf("[EVENT] %s epoch %u %s %.*s +0x%x", kv_ev_name(ev->type), ev->epoch,
		       seg_type_name(ev->desc.segment_type), (int)sizeof(ev->desc.name),
		       ev->desc.name, ev->desc.seg_offset);
		if (ev->type == KV_EV_CHANGED)
			printf(" (%s)%s\n", kv_verdict_name(ev->verdict), d);
		else
			printf(": %s\n", d);
	}
	fflush(stdout);
	if (g_ke)
		ke_event(g_ke, ev);
}

/* "lockdown,modules,unload,panic" / "none" -> KE_ACT_* bits, or -1 */
static int parse_actions(const char *s)
{
	static const struct { const char *n; unsigned int bit; } tbl[] = {
		{ "lockdown", KE_ACT_LOCKDOWN }, { "modules", KE_ACT_MODULES_OFF },
		{ "unload", KE_ACT_UNLOAD }, { "panic", KE_ACT_PANIC }, { "all", KE_ACT_ALL },
		{ "none", 0 },
	};
	int bits = 0;

	while (*s) {
		size_t l = strcspn(s, ","), i;

		for (i = 0; i < sizeof(tbl) / sizeof(tbl[0]); i++)
			if (strlen(tbl[i].n) == l && !strncmp(s, tbl[i].n, l))
				break;
		if (i == sizeof(tbl) / sizeof(tbl[0]))
			return -1;
		bits |= (int)tbl[i].bit;
		s += l + (s[l] == ',');
	}
	return bits;
}

/* -X: push one synthetic event of each serious kind through the real sinks
 * (always dry-run), so syslog/journald and auditd delivery can be checked. */
static int self_test(struct ke_config kc)
{
	static const char *hook =
		"\n  +0x20 kim_selftest_site+0x20/0x100 (5 B): 0f1f440000 -> e8dbffff3e nop5->call "
		"target=kim_selftest_hook+0x0/0x100 [kim_selftest] (implausible target)";
	struct kv_event ev;
	struct ke *k;

	kc.enforce = false;
	k = ke_new(&kc);
	if (!k)
		return 1;
	memset(&ev, 0, sizeof(ev));
	ev.epoch = 1;
	ev.desc.segment_id = 999999;
	snprintf(ev.desc.name, sizeof(ev.desc.name), "kim_selftest");

	ev.type = KV_EV_NEW_SEGMENT;                    /* WARN */
	ev.desc.segment_type = KIM_SEG_MOD_TEXT;
	ev.detail = "SELF-TEST: synthetic module load";
	ke_event(k, &ev);
	ev.type = KV_EV_CHANGED;                        /* CRIT + would-actions */
	ev.desc.segment_type = KIM_SEG_KTEXT;
	ev.verdict = KV_X_UNEXPLAINED;
	ev.detail = hook;
	ke_event(k, &ev);
	ev.desc.segment_type = KIM_SEG_SYSCALL_TABLE;   /* EMERG */
	ev.detail = "\n  SELF-TEST: synthetic sys_call_table[0] change";
	ke_event(k, &ev);
	ke_epoch_end(k, 1 + kc.panic_confirm);
	ke_flush(k);
	ke_free(k);
	printf("self-test sent (dry-run). Check: journalctl -t kim-integrity -n 20 ; "
	       "sudo ausearch -m TRUSTED_APP -ts recent\n");
	return 0;
}

static void on_epoch(const struct kd_epoch_stats *s, void *arg)
{
	double dt = (s->t_end_ns - s->t_start_ns) / 1e9;
	double win = (s->t_close_ns - s->t_start_ns) / 1e9;

	(void)arg;
	if (!g_quiet) {
		printf("epoch %5u%s | %6.1f MiB %5llu fr %4llu ch | %7.2f ms %6.2f GB/s | %-7s a=%.2f bP=%3uK bE=%3uK | P %5.1f%%",
		       s->epoch, s->partial ? "*" : " ", s->bytes / 1048576.0,
		       (unsigned long long)s->frames, (unsigned long long)s->chunks, dt * 1e3,
		       dt > 0 ? s->bytes / dt / 1e9 : 0.0, kd_power_name(s->power),
		       s->params.alpha, s->params.beta_p >> 10, s->params.beta_e >> 10,
		       s->bytes ? 100.0 * s->cls_bytes[KD_P] / s->bytes : 0.0);
		if (s->joules > 0 && win > 0)
			printf(" | %6.2f W %6.3f GB/J", s->joules / win, s->bytes / 1e9 / s->joules);
		printf(" | %016llx\n", (unsigned long long)g_digest);
	}
	g_digest = 0;
	if (g_base)
		kv_baseline_epoch_end(g_base, s->epoch, s->partial);
	if (g_ke)
		ke_epoch_end(g_ke, s->epoch);
}

static void on_power(enum kd_power p, void *arg)
{
	struct kd_dispatcher *d = __atomic_load_n(&g_disp, __ATOMIC_ACQUIRE);

	(void)arg;
	__atomic_store_n(&g_power, (int)p, __ATOMIC_RELEASE);
	if (d) {
		kd_set_power(d, p);
		fprintf(stderr, "power: %s (applies from the next epoch)\n", kd_power_name(p));
	}
}

static void usage(const char *a0)
{
	fprintf(stderr,
		"usage: %s [-d dev] [-a alpha] [-P beta_P_KiB] [-E beta_E_KiB] [-n maxP] [-m maxE]\n"
		"          [-s] [-r reader_cpu] [-f ac|bat] [-i interval_ms] [-t seconds] [-q]\n"
		"          [-T siv|xor] [-k hexkey] [-L learn_epochs] [-C confirm_epochs] [-B]\n"
		"          [-e] [-A actions] [-N allow_new] [-W allow_change] [-S] [-U] [-X] [-K cpu]\n"
		"  -a/-P/-E override both power states (default both: 1.0/256K/16K = P-cores only)\n"
		"  -s  use both SMT threads of each P core     -f  fix the power state (no listener)\n"
		"  -i  set the kernel scan interval (0 = back-to-back epochs)\n"
		"  -T  frame tag: siv = AES-GCM-SIV (default), xor = checksum baseline\n"
		"  -k  fixed 128/256-bit key in hex, to compare digests across runs\n"
		"  -L  epochs to learn the baseline from (default 3, 0 = no checking)\n"
		"  -C  extra scans a change must persist before CHANGED (default 1)\n"
		"  -B  do not keep baseline bytes (no byte-level explanations, ~40 MiB less)\n"
		"  -e  ENFORCE actions (default: dry-run, actions are only logged)\n"
		"  -A  actions allowed: lockdown,modules,unload,panic,all,none (default lockdown,modules)\n"
		"  -N  modules expected to load/unload (comma list): NEW_SEGMENT/VANISHED -> info\n"
		"  -W  segments whose patch-like changes are expected (e.g. ktext): -> info\n"
		"  -S  no syslog/journald alerts      -U  no auditd alerts\n"
		"  -X  send synthetic self-test alerts (dry-run) and exit\n"
		"  -K  CPU for the kernel copy thread; -1 = leave it to the scheduler. Default\n"
		"      (no -n/-s/-r): the last P core is kept free for it (one worker fewer)\n", a0);
}

int main(int argc, char **argv)
{
	const char *dev = KIM_DEV_PATH;
	double alpha = -1;
	int beta_p = 0, beta_e = 0, max_p = -1, max_e = -1, reader = -2, secs = 0, kcpu = -2;
	int kpid = -1;
	cpu_set_t kmask;
	int forced = -1, have_interval = 0, smt = 0, use_xor = 0, opt, err, i;
	const char *key_hex = NULL;
	int learn = 3, confirm = 1, keep_bytes = 1;
	int enforce = 0, actions = KE_ACT_DEFAULT, use_syslog = 1, use_audit = 1, selftest = 0;
	const char *allow_new = NULL, *allow_change = NULL;
	struct ke_config kc;
	uint32_t interval = 0;
	struct kd_power_mon mon;
	struct kd_config cfg;
	struct kd_totals tot;
	struct kprof kp;
	struct kd_rapl rapl;
	struct kd_topo topo;
	struct kim_ctx c;
	uint64_t t0, t1, full0, fault0, bad0, direct0, remap0, pte0, pteo0, cns0, dns0, uj0 = 0, uj1 = 0;
	bool have_uj = false;

	setvbuf(stdout, NULL, _IOLBF, 0);       /* journald/pipes: one record per line, now */
	while ((opt = getopt(argc, argv, "d:a:P:E:n:m:sr:f:i:t:qT:k:L:C:BeA:N:W:SUXK:h")) != -1) {
		switch (opt) {
		case 'd': dev = optarg; break;
		case 'a': alpha = atof(optarg); break;
		case 'P': beta_p = atoi(optarg); break;
		case 'E': beta_e = atoi(optarg); break;
		case 'n': max_p = atoi(optarg); break;
		case 'm': max_e = atoi(optarg); break;
		case 's': smt = 1; break;
		case 'r': reader = atoi(optarg); break;
		case 'f': forced = optarg[0] == 'a' ? KD_PWR_AC : KD_PWR_BATTERY; break;
		case 'i': interval = (uint32_t)atoi(optarg); have_interval = 1; break;
		case 't': secs = atoi(optarg); break;
		case 'q': g_quiet = 1; break;
		case 'T': use_xor = !strcmp(optarg, "xor"); break;
		case 'k': key_hex = optarg; break;
		case 'L': learn = atoi(optarg); break;
		case 'C': confirm = atoi(optarg); break;
		case 'B': keep_bytes = 0; break;
		case 'e': enforce = 1; break;
		case 'A':
			actions = parse_actions(optarg);
			if (actions < 0) {
				usage(argv[0]);
				return 2;
			}
			break;
		case 'N': allow_new = optarg; break;
		case 'W': allow_change = optarg; break;
		case 'S': use_syslog = 0; break;
		case 'U': use_audit = 0; break;
		case 'X': selftest = 1; break;
		case 'K': kcpu = atoi(optarg); break;
		default:  usage(argv[0]); return 2;
		}
	}

	/* Module 4 configuration: sinks and policy */
	ke_config_defaults(&kc);
	kc.enforce = enforce;
	kc.actions = (unsigned int)actions;
	kc.allow_new = allow_new;
	kc.allow_change = allow_change;
	kc.sinks[kc.nsinks++] = (struct ke_sink){ ke_sink_console, stdout, KE_INFO,
						  KE_K_ACTION | KE_K_SUMMARY };
	if (use_syslog)
		kc.sinks[kc.nsinks++] = (struct ke_sink){ ke_sink_syslog, NULL, KE_INFO, KE_K_ALL };
	if (use_audit) {
		g_audit_fd = ke_audit_open();
		if (g_audit_fd < 0)
			fprintf(stderr, "audit: %s (no auditd alerts; root needed)\n",
				strerror(-g_audit_fd));
		else
			kc.sinks[kc.nsinks++] = (struct ke_sink){ ke_sink_audit, &g_audit_fd,
								  KE_WARN, KE_K_ALL };
	}
	if (selftest)
		return self_test(kc);
	if (enforce && (use_xor || learn <= 0)) {
		fprintf(stderr, "-e needs the SIV tag and a baseline (-L > 0)\n");
		return 2;
	}

	err = kd_topo_discover(&topo, NULL);
	if (err) {
		fprintf(stderr, "topology: %s\n", strerror(-err));
		return 1;
	}
	kd_topo_print(&topo);

	kd_config_defaults(&cfg);
	for (i = 0; i < KD_PWR_NSTATES; i++) {
		if (alpha >= 0)
			cfg.params[i].alpha = alpha;
		if (beta_p > 0)
			cfg.params[i].beta_p = (uint32_t)beta_p << 10;
		if (beta_e > 0)
			cfg.params[i].beta_e = (uint32_t)beta_e << 10;
		if (kd_params_check(&cfg.params[i])) {
			fprintf(stderr, "alpha must be within [0,1]\n");
			return 2;
		}
	}
	/* default: keep one P core for the kernel thread when the user did not
	 * place workers/reader by hand and there is a P core to spare */
	if (kcpu == -2 && max_p < 0 && !smt && reader < -1 && topo.ncores[KD_P] >= 2)
		max_p = topo.ncores[KD_P] - 1;
	else if (kcpu == -2)
		kcpu = -1;
	if (kd_config_from_topo(&cfg, &topo, smt, max_p, max_e) < 0) {
		fprintf(stderr, "no usable CPUs\n");
		return 1;
	}
	if (reader >= -1)
		cfg.reader_cpu = reader;
	if (kcpu == -2) {
		kcpu = kthread_core_pick(&topo, &cfg);
		/* the reader must not share the reserved core: any other idle CPU */
		if (kcpu >= 0 && core_of(&topo, cfg.reader_cpu) == kcpu) {
			cfg.reader_cpu = -1;
			for (i = topo.ncpu - 1; i >= 0 && cfg.reader_cpu < 0; i--) {
				int w, busy = topo.cpus[i].core == kcpu;

				for (w = 0; w < cfg.nworkers && !busy; w++)
					busy = cfg.worker[w].cpu == topo.cpus[i].cpu;
				if (!busy)
					cfg.reader_cpu = topo.cpus[i].cpu;
			}
		}
	}
	printf("workers:");
	for (i = 0; i < cfg.nworkers; i++)
		printf(" %s%d", kd_class_name(cfg.worker[i].cls), cfg.worker[i].cpu);
	printf(" | reader cpu %d\n", cfg.reader_cpu);

	if (forced >= 0) {
		g_power = forced;
	} else if ((err = kd_power_mon_start(&mon, NULL, 5000, on_power, NULL))) {
		fprintf(stderr, "power listener: %s (assuming AC)\n", strerror(-err));
		g_power = KD_PWR_AC;
		forced = KD_PWR_AC;
	}
	cfg.power = (enum kd_power)__atomic_load_n(&g_power, __ATOMIC_ACQUIRE);
	printf("power: %s%s\n", kd_power_name(cfg.power), forced >= 0 ? " (fixed)" : "");

	if (kd_rapl_open(&rapl, NULL))
		fprintf(stderr, "RAPL energy unavailable (root needed): no W / GB/J columns\n");
	else
		cfg.rapl = &rapl;

	if (use_xor) {
		printf("tag: xor checksum (baseline, not an integrity tag)\n");
	} else if ((err = load_key(key_hex))) {
		fprintf(stderr, "key: %s\n", strerror(-err));
		return 2;
	} else {
		printf("tag: AES-%d-GCM-SIV [%s], %s key\n", g_key.rounds == 14 ? 256 : 128,
		       kv_impl_name(g_key.impl), key_hex ? "fixed" : "random per-run");
	}

	if (!use_xor && learn > 0) {
		struct kv_baseline_cfg bc = {
			.learn_epochs = (unsigned int)learn,
			.confirm_epochs = confirm > 0 ? (unsigned int)confirm : 0,
			.keep_bytes = keep_bytes, .on_event = on_kv_event,
		};

		g_base = kv_baseline_new(&bc);
		if (!g_base) {
			fprintf(stderr, "baseline: out of memory\n");
			return 1;
		}
		printf("baseline: learn %d complete epochs, confirm after %d more scan(s), %s\n",
		       learn, confirm, keep_bytes ? "bytes kept for explanations" : "tags only");

		g_ke = ke_new(&kc);
		if (!g_ke) {
			fprintf(stderr, "enforcer: out of memory\n");
			return 1;
		}
		{
			char lvl[32] = "?";

			ke_lockdown_current(lvl, sizeof(lvl));
			printf("enforcer: %s | actions%s%s%s%s%s | lockdown now %s | alerts: console%s%s\n",
			       enforce ? "ENFORCING" : "dry-run (use -e to enforce)",
			       actions & KE_ACT_LOCKDOWN ? " lockdown" : "",
			       actions & KE_ACT_MODULES_OFF ? " modules_disabled" : "",
			       actions & KE_ACT_UNLOAD ? " unload" : "",
			       actions & KE_ACT_PANIC ? " panic" : "", actions ? "" : " none", lvl,
			       use_syslog ? " syslog" : "", g_audit_fd >= 0 ? " auditd" : "");
		}
	}

	err = kim_ctx_open(&c, dev);
	if (err) {
		fprintf(stderr, "open %s: %s (root? module loaded?)\n", dev, strerror(-err));
		return 1;
	}
	if (have_interval && ioctl(c.fd, KIM_IOC_SET_INTERVAL, &interval))
		perror("KIM_IOC_SET_INTERVAL");

	cfg.work = use_xor ? xor_work : siv_work;
	cfg.work_arg = &g_key;
	cfg.on_result = on_result;
	cfg.on_epoch = on_epoch;
	signal(SIGINT, on_sig);
	signal(SIGTERM, on_sig);

	if (kcpu >= 0) {
		kpid = kprof_find();
		err = kpid < 0 ? -ESRCH : kthread_pin(kpid, kcpu, &kmask);
		if (err) {
			printf("kernel thread: not pinned to cpu %d (%s%s)\n", kcpu, strerror(-err),
			       err == -EINVAL ? "; module loaded with worker_cpu=" : "");
			kpid = -1;
		} else {
			printf("kernel thread: pinned to cpu %d (own P core)\n", kcpu);
		}
	}

	err = kd_start(&g_disp, &c, &cfg);
	if (err) {
		fprintf(stderr, "kd_start: %s\n", strerror(-err));
		return 1;
	}
	/* a change between the first read and kd_start() is not lost */
	kd_set_power(g_disp, (enum kd_power)__atomic_load_n(&g_power, __ATOMIC_ACQUIRE));

	full0 = c.hdr->ring_full_events;   /* kernel counters are cumulative since insmod */
	fault0 = c.hdr->fault_pages;
	bad0 = c.hdr->bad_tail_events;
	direct0 = c.hdr->direct_frames;
	remap0 = c.hdr->remap_frames;
	pte0 = c.hdr->pte_rechecks;
	pteo0 = c.hdr->pte_overruled;
	cns0 = c.hdr->copy_ns;
	dns0 = c.hdr->direct_ns;
	have_uj = cfg.rapl && !kd_rapl_read(&rapl, &uj0);
	kprof_start(&kp);
	t0 = kim_now_ns();
	while (!g_stop && (!secs || kim_now_ns() - t0 < (uint64_t)secs * 1000000000ull)) {
		usleep(100000);
		kprof_sample(&kp);
	}
	t1 = kim_now_ns();
	have_uj = have_uj && !kd_rapl_read(&rapl, &uj1);

	kd_request_stop(g_disp);
	if (forced < 0)
		kd_power_mon_stop(&mon);
	kd_join(g_disp, &tot);

	printf("total: %llu complete epochs, %.1f MiB, %llu frames, %llu chunks | P %.1f%% | pin failures %d\n",
	       (unsigned long long)tot.epochs, tot.bytes / 1048576.0,
	       (unsigned long long)tot.frames, (unsigned long long)tot.chunks,
	       tot.bytes ? 100.0 * tot.cls_bytes[KD_P] / tot.bytes : 0.0, tot.pin_failures);
	{
		/* one machine-readable line per run (used by sweep.sh) */
		const struct kd_params *pp = &cfg.params[cfg.power];
		double secs_run = (t1 - t0) / 1e9, j = have_uj ? kd_rapl_joules(&rapl, uj0, uj1) : -1;
		int nw[KD_NCLASS] = { 0, 0 };

		for (i = 0; i < cfg.nworkers; i++)
			nw[cfg.worker[i].cls]++;

		printf("result: power=%s alpha=%.2f beta_p_kib=%u beta_e_kib=%u workers_p=%d workers_e=%d"
		       " tag=%s epochs=%llu bytes=%llu seconds=%.3f gbps=%.4f joules=%.2f watts=%.2f gbpj=%.5f\n",
		       kd_power_name(cfg.power), pp->alpha, pp->beta_p >> 10, pp->beta_e >> 10,
		       nw[KD_P], nw[KD_E],
		       use_xor ? "xor" : "siv", (unsigned long long)tot.epochs,
		       (unsigned long long)tot.bytes, secs_run, tot.bytes / secs_run / 1e9, j,
		       j > 0 ? j / secs_run : -1.0, j > 0 ? tot.bytes / 1e9 / j : -1.0);
	}
	for (i = 0; i < cfg.nworkers; i++)
		printf("  worker %2d %s cpu %2d: %8.1f MiB\n", i, kd_class_name(cfg.worker[i].cls),
		       cfg.worker[i].cpu, tot.worker_bytes[i] / 1048576.0);
	printf("kernel (this run): ring_full %llu | fault_pages %llu | bad_tail %llu | segments %llu"
	       " | direct %llu | remap %llu (text window %s) | pte rechecks %llu, overruled %llu\n",
	       (unsigned long long)(c.hdr->ring_full_events - full0),
	       (unsigned long long)(c.hdr->fault_pages - fault0),
	       (unsigned long long)(c.hdr->bad_tail_events - bad0),
	       (unsigned long long)c.hdr->n_segments,
	       (unsigned long long)(c.hdr->direct_frames - direct0),
	       (unsigned long long)(c.hdr->remap_frames - remap0),
	       c.hdr->text_win_len ? "on" : "off",
	       (unsigned long long)(c.hdr->pte_rechecks - pte0),
	       (unsigned long long)(c.hdr->pte_overruled - pteo0));
	if (tot.run_ns) {
		/* per class, over the workers that got any work (alpha may idle a class) */
		double sum[KD_NCLASS] = { 0, 0 };
		int nb[KD_NCLASS] = { 0, 0 };

		for (i = 0; i < cfg.nworkers; i++) {
			if (!tot.worker_bytes[i])
				continue;
			sum[cfg.worker[i].cls] += 100.0 * tot.worker_busy_ns[i] / tot.run_ns;
			nb[cfg.worker[i].cls]++;
		}
		printf("profile: reader waits for workers %.0f%%, for the kernel (ring empty) %.0f%%, "
		       "works %.0f%% | dispatch stops: queues full %llu, ring in flight %llu | "
		       "workers busy P %.0f%% x%d, E %.0f%% x%d\n",
		       100.0 * tot.reader_wait_work_ns / tot.run_ns,
		       100.0 * tot.reader_wait_ring_ns / tot.run_ns,
		       100.0 - 100.0 * (tot.reader_wait_work_ns + tot.reader_wait_ring_ns) / tot.run_ns,
		       (unsigned long long)tot.disp_no_queue, (unsigned long long)tot.disp_window_full,
		       nb[KD_P] ? sum[KD_P] / nb[KD_P] : 0.0, nb[KD_P],
		       nb[KD_E] ? sum[KD_E] / nb[KD_E] : 0.0, nb[KD_E]);
	}
	kprof_print(&kp, &topo, t1 - t0);
	if (kpid >= 0 && sched_setaffinity(kpid, sizeof(kmask), &kmask))
		perror("kernel thread: restoring its CPU mask");
	{
		/* where the producer's CPU time goes (old modules leave both at 0) */
		uint64_t cns = c.hdr->copy_ns - cns0, dns = c.hdr->direct_ns - dns0;
		uint64_t wall = t1 - t0;

		if (cns + dns && wall)
			printf("kernel frames: copied %.0f%% of wall (%.2f GB/s while copying) | direct %.0f%% "
			       "of wall | ring %u slots (%.0f MiB)\n",
			       100.0 * cns / wall, cns ? (double)g_copied / (double)cns : 0.0,
			       100.0 * dns / wall, c.hdr->nslots,
			       KIM_RING_BYTES_N(c.hdr->nslots) / 1048576.0);
	}
	kd_rapl_close(&rapl);
	kim_ctx_close(&c);
	if (g_base) {
		struct kv_baseline_stats bs;

		kv_baseline_get_stats(g_base, &bs);
		printf("baseline: %s | %u learned + %u checked epochs | %llu segments, %llu frames, %llu in CHANGED"
		       " | events: changed %llu, transient %llu, reverted %llu, new %llu, vanished %llu,"
		       " wx %llu, fault %llu, remap %llu, unstable %llu | %zu symbols\n",
		       bs.checking ? "checking" : "still learning", bs.epochs_learned, bs.epochs_checked,
		       (unsigned long long)bs.segments, (unsigned long long)bs.frames,
		       (unsigned long long)bs.frames_changed,
		       (unsigned long long)bs.events[KV_EV_CHANGED],
		       (unsigned long long)bs.events[KV_EV_TRANSIENT],
		       (unsigned long long)bs.events[KV_EV_REVERTED],
		       (unsigned long long)bs.events[KV_EV_NEW_SEGMENT],
		       (unsigned long long)bs.events[KV_EV_VANISHED],
		       (unsigned long long)bs.events[KV_EV_WX], (unsigned long long)bs.events[KV_EV_FAULT],
		       (unsigned long long)bs.events[KV_EV_REMAP],
		       (unsigned long long)bs.events[KV_EV_UNSTABLE], bs.symbols);
		kv_baseline_free(g_base);
	}
	if (g_ke) {
		struct ke_stats ks;

		ke_flush(g_ke);
		ke_get_stats(g_ke, &ks);
		printf("enforcer: events info %llu notice %llu warn %llu crit %llu emerg %llu | suppressed %llu"
		       " | actions done %llu, would %llu, failed %llu, not-enabled %llu\n",
		       (unsigned long long)ks.by_sev[KE_INFO], (unsigned long long)ks.by_sev[KE_NOTICE],
		       (unsigned long long)ks.by_sev[KE_WARN], (unsigned long long)ks.by_sev[KE_CRIT],
		       (unsigned long long)ks.by_sev[KE_EMERG], (unsigned long long)ks.suppressed,
		       (unsigned long long)ks.acted, (unsigned long long)ks.would,
		       (unsigned long long)ks.failed, (unsigned long long)ks.not_enabled);
		ke_free(g_ke);
	}
	if (g_audit_fd >= 0)
		close(g_audit_fd);
	kv_key_wipe(&g_key);
	return 0;
}
