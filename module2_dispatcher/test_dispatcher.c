// SPDX-License-Identifier: GPL-2.0
/*
 * test_dispatcher.c - Module 2 tests. No root, no kernel module needed.
 *
 *   U1 cpulist / cache-size parsing
 *   U2 topology from mock sysfs trees (hybrid 12450H-like, uniform SMT, offline CPUs)
 *   U3 worker/reader placement from topology
 *   U4 power state rules (Mains, USB-C, peripheral batteries, desktop)
 *   U5 power listener follows plug/unplug in a polled mock tree
 *   U6 alpha/beta parameter validation
 *   P1 pipeline against a mock kernel producer that follows the ring protocol of
 *      kernel_extractor.c: per-epoch digests must equal a reference computed from
 *      the generator for every alpha/beta/worker mix (bit-exact), every frame must
 *      still hold its own content after a random worker delay (no early slot
 *      reuse), the P/E byte split must track alpha, power switches apply per epoch
 *   L  live topology / power / RAPL of this machine (informational)
 */
#include <errno.h>
#include <ftw.h>
#include <math.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#include "kd_dispatcher.h"
#include "kim_cpu.h"

static int g_fail, g_pass;
#define PASS(...) do { g_pass++; printf("  [PASS] "); printf(__VA_ARGS__); putchar('\n'); } while (0)
#define FAIL(...) do { g_fail++; printf("  [FAIL] "); printf(__VA_ARGS__); putchar('\n'); } while (0)
#define CHECK(c, ...) do { if (c) PASS(__VA_ARGS__); else FAIL(__VA_ARGS__); } while (0)

#define KiB 1024u
#define FRAME KIM_FRAME_BYTES

static void sleep_us(long us)
{
	struct timespec ts = { us / 1000000, (us % 1000000) * 1000 };

	nanosleep(&ts, NULL);
}

/* ------------------------------------------------------------------ */
/* Mock sysfs                                                         */
/* ------------------------------------------------------------------ */
static char *mkroot(void)
{
	const char *tmp = getenv("TMPDIR");
	char *p;

	if (asprintf(&p, "%s/kd_sysfs.XXXXXX", tmp ? tmp : "/tmp") < 0 || !mkdtemp(p)) {
		perror("mkdtemp");
		exit(2);
	}
	return p;
}

static void put(const char *root, const char *rel, const char *content)
{
	char path[512], *p;
	FILE *f;

	snprintf(path, sizeof(path), "%s/%s", root, rel);
	for (p = path + strlen(root) + 1; (p = strchr(p, '/')); p++) {
		*p = '\0';
		mkdir(path, 0755);
		*p = '/';
	}
	f = fopen(path, "w");
	if (!f) {
		perror(path);
		exit(2);
	}
	fprintf(f, "%s\n", content);
	fclose(f);
}

static void putf(const char *root, const char *content, const char *fmt, ...)
{
	char rel[256];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(rel, sizeof(rel), fmt, ap);
	va_end(ap);
	put(root, rel, content);
}

static int rm_cb(const char *p, const struct stat *sb, int flag, struct FTW *f)
{
	(void)sb; (void)flag; (void)f;
	return remove(p);
}

static void rmroot(char *root)
{
	nftw(root, rm_cb, 16, FTW_DEPTH | FTW_PHYS);
	free(root);
}

static void put_cache(const char *root, int cpu, int idx, int level, const char *type,
		      const char *size, const char *shared)
{
	char lv[8];

	snprintf(lv, sizeof(lv), "%d", level);
	putf(root, lv, "devices/system/cpu/cpu%d/cache/index%d/level", cpu, idx);
	putf(root, type, "devices/system/cpu/cpu%d/cache/index%d/type", cpu, idx);
	putf(root, size, "devices/system/cpu/cpu%d/cache/index%d/size", cpu, idx);
	putf(root, shared, "devices/system/cpu/cpu%d/cache/index%d/shared_cpu_list", cpu, idx);
}

/* i5-12450H as seen on the development machine. */
static char *mock_12450h(const char *online)
{
	char *r = mkroot(), sib[16];
	int cpu;

	put(r, "devices/system/cpu/online", online);
	put(r, "devices/cpu_core/cpus", "0-7");
	put(r, "devices/cpu_atom/cpus", "8-11");
	for (cpu = 0; cpu < 12; cpu++) {
		if (cpu < 8) {
			snprintf(sib, sizeof(sib), "%d-%d", cpu & ~1, cpu | 1);
			put_cache(r, cpu, 0, 1, "Data", "48K", sib);
			put_cache(r, cpu, 1, 1, "Instruction", "32K", sib);
			put_cache(r, cpu, 2, 2, "Unified", "1280K", sib);
		} else {
			snprintf(sib, sizeof(sib), "%d", cpu);
			put_cache(r, cpu, 0, 1, "Data", "32K", sib);
			put_cache(r, cpu, 1, 1, "Instruction", "64K", sib);
			put_cache(r, cpu, 2, 2, "Unified", "2048K", "8-11");
		}
		put_cache(r, cpu, 3, 3, "Unified", "12288K", "0-11");
		putf(r, sib, "devices/system/cpu/cpu%d/topology/thread_siblings_list", cpu);
	}
	return r;
}

/* ------------------------------------------------------------------ */
/* U1-U3                                                              */
/* ------------------------------------------------------------------ */
static void t_cpu(void)
{
	puts("U0 supported-CPU gate (Intel 12th gen and newer)");
	CHECK(kim_cpu_model_ok(6, 0x9a) && kim_cpu_model_ok(6, 0x97), "Alder Lake (-L) accepted");
	CHECK(kim_cpu_model_ok(6, 0xbf) && kim_cpu_model_ok(6, 0xaa) && kim_cpu_model_ok(6, 0xc6) &&
	      kim_cpu_model_ok(6, 0xbd) && kim_cpu_model_ok(6, 0xcc) && kim_cpu_model_ok(18, 0x01),
	      "Raptor/Meteor/Arrow/Lunar/Panther/Nova Lake accepted");
	CHECK(!kim_cpu_model_ok(6, 0x8c) && !kim_cpu_model_ok(6, 0x7e) && !kim_cpu_model_ok(6, 0x9e),
	      "Tiger Lake, Ice Lake, Coffee Lake (11th gen and older) refused");
	CHECK(!kim_cpu_model_ok(6, 0x8f) && !kim_cpu_model_ok(19, 0x01) && !kim_cpu_model_ok(25, 0x21),
	      "server parts and other families refused");
}

static void t_parse(void)
{
	cpu_set_t s;
	uint32_t b = 0;

	puts("U1 cpulist / size parsing");
	CHECK(!kd_cpulist_parse("0-3,8,10-11\n", &s) && CPU_COUNT(&s) == 7 &&
	      CPU_ISSET(8, &s) && CPU_ISSET(11, &s) && !CPU_ISSET(9, &s), "\"0-3,8,10-11\" -> 7 CPUs");
	CHECK(!kd_cpulist_parse("", &s) && CPU_COUNT(&s) == 0, "empty list -> empty set");
	CHECK(kd_cpulist_parse("3-1", &s) == -EINVAL && kd_cpulist_parse("1-", &s) == -EINVAL &&
	      kd_cpulist_parse("x", &s) == -EINVAL, "malformed lists rejected");
	CHECK(!kd_size_parse("1280K", &b) && b == 1280 * KiB && !kd_size_parse("2M", &b) &&
	      b == 2048 * KiB && kd_size_parse("12Q", &b) == -EINVAL, "cache sizes 1280K, 2M, bad suffix");
}

static int worker_cpus(const struct kd_config *c, enum kd_class cls, char *buf, size_t n)
{
	int i, k = 0, o = 0;

	buf[0] = '\0';
	for (i = 0; i < c->nworkers; i++)
		if (c->worker[i].cls == cls) {
			o += snprintf(buf + o, n - o, "%s%d", k++ ? "," : "", c->worker[i].cpu);
		}
	return k;
}

static void t_topology(void)
{
	struct kd_topo t;
	struct kd_config cfg;
	char *r, p[64], e[64];

	puts("U2 topology from mock sysfs");
	r = mock_12450h("0-11");
	CHECK(!kd_topo_discover(&t, r) && t.hybrid && !strcmp(t.source, "sysfs-pmu"),
	      "12450H: hybrid via PMU cpu lists");
	CHECK(t.nlogical[KD_P] == 8 && t.ncores[KD_P] == 4 && t.nlogical[KD_E] == 4 &&
	      t.ncores[KD_E] == 4, "8 P threads on 4 cores, 4 E cores");
	CHECK(t.cache[KD_P].l1d == 48 * KiB && t.cache[KD_P].l2 == 1280 * KiB &&
	      t.cache[KD_P].l2_share == 2 && t.cache[KD_E].l1d == 32 * KiB &&
	      t.cache[KD_E].l2 == 2048 * KiB && t.cache[KD_E].l2_share == 4 &&
	      t.cache[KD_E].l3 == 12288 * KiB, "caches: P 48K/1280K, E 32K/2M shared by 4");

	puts("U3 placement");
	kd_config_defaults(&cfg);
	kd_config_from_topo(&cfg, &t, false, -1, -1);
	worker_cpus(&cfg, KD_P, p, sizeof(p));
	worker_cpus(&cfg, KD_E, e, sizeof(e));
	CHECK(!strcmp(p, "0,2,4,6") && !strcmp(e, "8,9,10,11") && cfg.reader_cpu == 7,
	      "one thread per core: P %s, E %s, reader on spare sibling %d", p, e, cfg.reader_cpu);
	kd_config_from_topo(&cfg, &t, true, -1, -1);
	CHECK(cfg.nworkers == 12 && cfg.reader_cpu == -1, "SMT on: 12 workers, reader unpinned");
	kd_config_from_topo(&cfg, &t, false, 2, 1);
	worker_cpus(&cfg, KD_P, p, sizeof(p));
	worker_cpus(&cfg, KD_E, e, sizeof(e));
	CHECK(!strcmp(p, "0,2") && !strcmp(e, "8") && cfg.reader_cpu == 3,
	      "limits 2P/1E: P %s, E %s, reader %d", p, e, cfg.reader_cpu);
	rmroot(r);

	puts("U2 topology: offline CPUs");
	r = mock_12450h("1-5,8-9");
	CHECK(!kd_topo_discover(&t, r) && t.ncpu == 7 && t.ncores[KD_P] == 3 &&
	      t.nlogical[KD_E] == 2, "online 1-5,8-9: 5 P threads / 3 cores, 2 E");
	kd_config_from_topo(&cfg, &t, false, -1, -1);
	worker_cpus(&cfg, KD_P, p, sizeof(p));
	CHECK(!strcmp(p, "1,2,4"), "core whose first sibling is offline still gets a worker (P %s)", p);
	rmroot(r);

	puts("U2 topology: uniform CPU");
	r = mkroot();
	put(r, "devices/system/cpu/online", "0-3");
	put(r, "devices/system/cpu/cpu0/topology/thread_siblings_list", "0,2");
	put(r, "devices/system/cpu/cpu2/topology/thread_siblings_list", "0,2");
	put(r, "devices/system/cpu/cpu1/topology/thread_siblings_list", "1,3");
	put(r, "devices/system/cpu/cpu3/topology/thread_siblings_list", "1,3");
	CHECK(!kd_topo_discover(&t, r) && !t.hybrid && !strcmp(t.source, "uniform") &&
	      t.nlogical[KD_P] == 4 && t.ncores[KD_P] == 2 && !t.nlogical[KD_E],
	      "no PMU lists: all P, interleaved siblings -> 2 cores");
	kd_config_from_topo(&cfg, &t, false, -1, -1);
	worker_cpus(&cfg, KD_P, p, sizeof(p));
	CHECK(!strcmp(p, "0,1") && cfg.reader_cpu == 3, "workers %s, reader %d", p, cfg.reader_cpu);
	rmroot(r);

	r = mkroot();
	CHECK(kd_topo_discover(&t, r) == -ENOENT, "missing cpu/online -> -ENOENT");
	rmroot(r);
}

/* ------------------------------------------------------------------ */
/* U4-U6                                                              */
/* ------------------------------------------------------------------ */
static void supply(const char *r, const char *name, const char *type, const char *online,
		   const char *scope)
{
	putf(r, type, "class/power_supply/%s/type", name);
	if (online)
		putf(r, online, "class/power_supply/%s/online", name);
	if (scope)
		putf(r, scope, "class/power_supply/%s/scope", name);
}

static enum kd_power pstate(const char *r, struct kd_power_info *pi)
{
	return kd_power_read(r, pi) ? (enum kd_power)-1 : pi->state;
}

static void t_power(void)
{
	struct kd_power_info pi;
	char *r;

	puts("U4 power state");
	r = mkroot();
	supply(r, "ADP1", "Mains", "1", NULL);
	supply(r, "BAT0", "Battery", NULL, NULL);
	CHECK(pstate(r, &pi) == KD_PWR_AC && !strcmp(pi.source, "ADP1"), "ADP1 online -> AC");
	supply(r, "ADP1", "Mains", "0", NULL);
	supply(r, "ucsi-source-psy-USBC000:001", "USB", "0", "System");
	CHECK(pstate(r, &pi) == KD_PWR_BATTERY && pi.n_usb == 1, "ADP1 + USB-C offline -> battery");
	supply(r, "ucsi-source-psy-USBC000:001", "USB", "1", "System");
	CHECK(pstate(r, &pi) == KD_PWR_AC && !strncmp(pi.source, "ucsi", 4),
	      "USB-C PD charger online -> AC");
	rmroot(r);

	r = mkroot();
	supply(r, "ACAD", "Mains", "1", NULL);
	CHECK(pstate(r, &pi) == KD_PWR_AC, "ACAD (other vendor name) online -> AC");
	rmroot(r);

	r = mkroot();
	supply(r, "BAT1", "Battery", NULL, NULL);
	supply(r, "hidpp_battery_0", "Battery", "1", "Device");
	CHECK(pstate(r, &pi) == KD_PWR_BATTERY && pi.n_battery == 1,
	      "battery only -> battery; mouse battery (scope Device) ignored");
	rmroot(r);

	r = mkroot();
	supply(r, "hidpp_battery_0", "Battery", "1", "Device");
	CHECK(pstate(r, &pi) == KD_PWR_AC, "desktop with only a peripheral battery -> AC");
	rmroot(r);

	r = mkroot();
	CHECK(pstate(r, &pi) == KD_PWR_AC, "no power_supply class at all -> AC");
	rmroot(r);
}

static int g_mon_hist[16], g_mon_n;

static void mon_cb(enum kd_power st, void *arg)
{
	int n = __atomic_load_n(&g_mon_n, __ATOMIC_ACQUIRE);

	(void)arg;
	if (n < 16) {
		g_mon_hist[n] = st;
		__atomic_store_n(&g_mon_n, n + 1, __ATOMIC_RELEASE);
	}
}

static bool wait_mon(int n)
{
	int i;

	for (i = 0; i < 400 && __atomic_load_n(&g_mon_n, __ATOMIC_ACQUIRE) < n; i++)
		sleep_us(5000);
	return __atomic_load_n(&g_mon_n, __ATOMIC_ACQUIRE) >= n;
}

static void t_power_monitor(void)
{
	struct kd_power_mon m;
	char *r = mkroot();
	int err;

	puts("U5 power listener (polled mock tree)");
	supply(r, "ADP1", "Mains", "0", NULL);
	supply(r, "BAT0", "Battery", NULL, NULL);
	err = kd_power_mon_start(&m, r, 10, mon_cb, NULL);
	CHECK(!err && wait_mon(1) && g_mon_hist[0] == KD_PWR_BATTERY, "initial callback: battery");
	supply(r, "ADP1", "Mains", "1", NULL);
	CHECK(wait_mon(2) && g_mon_hist[1] == KD_PWR_AC, "plug in -> AC callback");
	supply(r, "ADP1", "Mains", "0", NULL);
	CHECK(wait_mon(3) && g_mon_hist[2] == KD_PWR_BATTERY, "unplug -> battery callback");
	sleep_us(50000);
	CHECK(g_mon_n == 3, "no duplicate callbacks without a change");
	if (!err)
		kd_power_mon_stop(&m);
	rmroot(r);
}

static void t_params(void)
{
	struct kd_params p = { 0.8, 48 * KiB + 100, 0 };

	puts("U6 parameters");
	CHECK(!kd_params_check(&p) && p.beta_p == 48 * KiB && p.beta_e == KD_BETA_MIN,
	      "betas rounded down to frames, min one frame");
	p = (struct kd_params){ 0.8, 4096 * KiB, 16 * KiB };
	CHECK(!kd_params_check(&p) && p.beta_p == KD_BETA_MAX, "beta capped at %u KiB", KD_BETA_MAX / KiB);
	p.alpha = 1.2;
	CHECK(kd_params_check(&p) == -EINVAL, "alpha > 1 rejected");
	p.alpha = NAN;
	CHECK(kd_params_check(&p) == -EINVAL, "alpha NaN rejected");
}

/* ------------------------------------------------------------------ */
/* Mock kernel producer                                               */
/* ------------------------------------------------------------------ */
static inline uint64_t mix64(uint64_t x)
{
	x += 0x9e3779b97f4a7c15ull;
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ull;
	x = (x ^ (x >> 27)) * 0x94d049bb133111ebull;
	return x ^ (x >> 31);
}

/* Frame content depends on (segment, epoch, offset): any stale or reused slot
 * holds different bytes. Kernel text (id 1) is static like the real one, so a
 * mock text window can serve it for direct_text configs. */
static void gen(uint8_t *dst, uint32_t id, uint32_t epoch, uint32_t off, uint32_t len)
{
	uint64_t seed = mix64(((uint64_t)id << 32) ^ (id == 1 ? 0 : epoch));
	uint32_t i;

	for (i = 0; i < len; i += 8) {
		uint64_t w = mix64(seed ^ (off + i));

		memcpy(dst + i, &w, len - i < 8 ? len - i : 8);
	}
}

struct mseg { uint32_t id, type, len, stop_at; const char *name; };

/* Segment table per epoch, mirroring what the kernel can do between scans:
 * module 4 is unloaded in the middle of epoch 3 (FIRST without LAST) and
 * module 6 appears from epoch 3 on. */
static int seg_list(uint32_t epoch, struct mseg *s)
{
	int n = 0;

	s[n++] = (struct mseg){ 1, KIM_SEG_KTEXT, 4u * 1024 * 1024 + 3 * 4096 + 100, 0, "ktext" };
	s[n++] = (struct mseg){ 2, KIM_SEG_SYSCALL_TABLE, 472 * 8, 0, "sys_call_table" };
	s[n++] = (struct mseg){ 3, KIM_SEG_MOD_TEXT, 300000, 0, "modA" };
	if (epoch < 3)
		s[n++] = (struct mseg){ 4, KIM_SEG_MOD_RODATA, 70000, 0, "modB" };
	else if (epoch == 3)
		s[n++] = (struct mseg){ 4, KIM_SEG_MOD_RODATA, 70000, 2 * FRAME, "modB" };
	s[n++] = (struct mseg){ 5, KIM_SEG_MOD_TEXT, 3 * FRAME, 0, "modC" };
	if (epoch >= 3)
		s[n++] = (struct mseg){ 6, KIM_SEG_MOD_TEXT, 123457, 0, "modD" };
	return n;
}

struct mock {
	struct kim_hdr  *hdr;
	struct kim_cons *cons;
	struct kim_desc *desc;
	uint8_t         *data;
	uint8_t         *text;      /* direct_text: static ktext window      */
	uint64_t         text_base;
	uint32_t         nslots;
	uint32_t         nepochs;
	int              gap_us;
	uint64_t         head_priv, head_pub, full, bad_tail;
	int              stop;
	pthread_t        th;
};

static void m_publish(struct mock *m)
{
	if (m->head_priv == m->head_pub)
		return;
	m->head_pub = m->head_priv;
	__atomic_store_n(&m->hdr->head, m->head_pub, __ATOMIC_RELEASE);
}

/* Same backpressure and publish rules as kim_emit_next_locked()/kim_scan_batch(). */
static void *producer(void *arg)
{
	struct mock *m = arg;
	struct mseg s[8];
	uint32_t epoch;

	for (epoch = 1; epoch <= m->nepochs; epoch++) {
		int ns = seg_list(epoch, s), i;

		for (i = 0; i < ns; i++) {
			uint32_t lim = s[i].stop_at ? s[i].stop_at : s[i].len, off;

			for (off = 0; off < lim; off += FRAME) {
				uint32_t n = s[i].len - off < FRAME ? s[i].len - off : FRAME, slot;
				struct kim_desc *d;
				uint64_t tail;
				bool direct;

				for (;;) {
					if (__atomic_load_n(&m->stop, __ATOMIC_ACQUIRE))
						return NULL;
					tail = __atomic_load_n(&m->cons->tail, __ATOMIC_ACQUIRE);
					if (tail > m->head_pub)
						m->bad_tail++;
					else if (m->head_priv - tail < m->nslots)
						break;
					else
						m->full++;
					m_publish(m);
					sleep_us(20);
				}
				slot = (uint32_t)m->head_priv & (m->nslots - 1);
				d = &m->desc[slot];
				/* direct_text: text frames stay in the window (slot
				 * poisoned), every 7th falls back to a copy (REMAP) */
				direct = m->text && s[i].type == KIM_SEG_KTEXT && (off / FRAME) % 7 != 3;
				if (direct) {
					memset(m->data + (size_t)slot * FRAME, 0xa5, FRAME);
				} else {
					gen(m->data + (size_t)slot * FRAME, s[i].id, epoch, off, n);
					memset(m->data + (size_t)slot * FRAME + n, 0, FRAME - n);
				}
				memset(d, 0, sizeof(*d));
				d->base_address = 0xffffffff81000000ull + ((uint64_t)s[i].id << 28) + off;
				d->timestamp_ns = kim_now_ns();
				d->segment_type = s[i].type;
				d->segment_id = s[i].id;
				d->length = n;
				d->seg_length = s[i].len;
				d->seg_offset = off;
				d->scan_epoch = epoch;
				d->flags = (off == 0 ? KIM_F_FIRST : 0) |
					   (off + n >= s[i].len ? KIM_F_LAST : 0);
				if (m->text && s[i].type == KIM_SEG_KTEXT)
					d->flags |= direct ? KIM_F_DIRECT : KIM_F_REMAP;
				snprintf(d->name, sizeof(d->name), "%s", s[i].name);
				m->head_priv++;
				if (!(m->head_priv % 64))
					m_publish(m);
			}
		}
		m_publish(m);
		__atomic_store_n(&m->hdr->epoch, epoch + 1, __ATOMIC_RELAXED);
		__atomic_store_n(&m->hdr->epochs_done, m->hdr->epochs_done + 1, __ATOMIC_RELEASE);
		if (m->gap_us)
			sleep_us(m->gap_us);
	}
	return NULL;
}

static void mock_init(struct mock *m, struct kim_ctx *c, uint32_t nslots, bool direct)
{
	memset(m, 0, sizeof(*m));
	m->nslots = nslots;
	m->hdr = aligned_alloc(4096, 4096);
	m->cons = aligned_alloc(4096, 4096);
	m->desc = aligned_alloc(64, (size_t)nslots * sizeof(*m->desc));
	m->data = aligned_alloc(64 * KiB, (size_t)nslots * FRAME);
	memset(m->hdr, 0, 4096);
	memset(m->cons, 0, 4096);
	memset(m->desc, 0, (size_t)nslots * sizeof(*m->desc));
	m->hdr->magic = KIM_MAGIC;
	m->hdr->abi_version = KIM_ABI_VERSION;
	m->hdr->nslots = nslots;
	m->hdr->frame_bytes = FRAME;
	m->hdr->desc_size = KIM_DESC_SIZE;
	m->hdr->epoch = 1;

	memset(c, 0, sizeof(*c));
	c->fd = -1;
	c->hdr = m->hdr;
	c->cons = m->cons;
	c->desc = m->desc;
	c->data = m->data;
	c->mask = nslots - 1;
	c->frame_bytes = FRAME;

	if (direct) {           /* text window holding segment 1 (ktext) */
		struct mseg sl[8];
		uint32_t len, off;

		seg_list(1, sl);
		len = (sl[0].len + FRAME - 1) & ~(FRAME - 1);
		m->text = aligned_alloc(4096, len);
		for (off = 0; off < sl[0].len; off += FRAME)
			gen(m->text + off, 1, 1, off,
			    sl[0].len - off < FRAME ? sl[0].len - off : FRAME);
		m->text_base = 0xffffffff81000000ull + (1ull << 28);
		m->hdr->text_win_base = m->text_base;
		m->hdr->text_win_len = (sl[0].len + 4095) & ~4095u;
		c->text = m->text;
		c->text_len = m->hdr->text_win_len;
		c->text_base = m->text_base;
	}
}

static void mock_free(struct mock *m)
{
	free(m->hdr);
	free(m->cons);
	free(m->desc);
	free(m->data);
	free(m->text);
}

/* ------------------------------------------------------------------ */
/* Work fn, result/epoch sinks, reference digest                      */
/* ------------------------------------------------------------------ */
#define NEPOCHS 6

struct pcfg {
	const char *name;
	double      alpha;
	uint32_t    beta_p, beta_e;
	int         np, ne;
	uint32_t    nslots;
	bool        delays;
	int         gap_us;
	unsigned    spin;
	int         switch_after;   /* >0: switch AC -> battery after this many epochs */
	bool        direct;         /* ktext via a text window (KIM_F_DIRECT)          */
};

struct ptest {
	const struct pcfg *pc;
	uint64_t h;                                /* reader thread only */
	uint64_t digest[NEPOCHS + 2], frames[NEPOCHS + 2];
	struct kd_epoch_stats st[NEPOCHS + 2];
	int      seen;                             /* epochs closed (atomic) */
	int      corrupt, desc_changed;            /* atomic */
	int      payload_bad;                      /* reader thread only */
	uint64_t n_direct, n_remap;                /* reader thread only */
};

static uint64_t frame_tag(const uint8_t *p, uint32_t len)
{
	uint64_t t = kim_xor_checksum(p, len);
	uint32_t i;

	for (i = len & ~7u; i < len; i++)          /* kim_xor_checksum skips the tail */
		t ^= (uint64_t)p[i] << (8 * (i & 7));
	return mix64(t);
}

static uint64_t fold(uint64_t h, uint32_t id, uint32_t off, uint32_t len, uint32_t flags,
		     uint64_t tag)
{
	h = mix64(h ^ id);
	h = mix64(h ^ ((uint64_t)off << 32 | len));
	h = mix64(h ^ flags);
	return mix64(h ^ tag);
}

static uint64_t reference_digest(uint32_t epoch, uint64_t *frames)
{
	static uint8_t buf[FRAME];
	struct mseg s[8];
	int ns = seg_list(epoch, s), i;
	uint64_t h = 0;

	*frames = 0;
	for (i = 0; i < ns; i++) {
		uint32_t lim = s[i].stop_at ? s[i].stop_at : s[i].len, off;

		for (off = 0; off < lim; off += FRAME) {
			uint32_t n = s[i].len - off < FRAME ? s[i].len - off : FRAME;
			uint32_t fl = (off == 0 ? KIM_F_FIRST : 0) | (off + n >= s[i].len ? KIM_F_LAST : 0);

			gen(buf, s[i].id, epoch, off, n);
			h = fold(h, s[i].id, off, n, fl, frame_tag(buf, n));
			(*frames)++;
		}
	}
	return h;
}

static __thread uint64_t t_rng;

static uint64_t rnd(void)
{
	if (!t_rng)
		t_rng = mix64((uint64_t)pthread_self() ^ kim_now_ns());
	t_rng ^= t_rng << 13;
	t_rng ^= t_rng >> 7;
	t_rng ^= t_rng << 17;
	return t_rng;
}

static void test_work(const struct kim_chunk *ck, struct kd_result *out, void *arg)
{
	static __thread uint8_t want[FRAME];
	struct ptest *pt = arg;
	uint32_t i;

	for (i = 0; i < ck->nframes; i++) {
		uint64_t tag = frame_tag(ck->data + (size_t)i * FRAME, out[i].desc.length);

		memcpy(out[i].tag, &tag, sizeof(tag));
	}
	if (pt->pc->delays) {
		uint64_t r = rnd();

		if ((r & 3) == 0)
			sleep_us((long)(r >> 8) % 300);
		else
			for (i = 0; i < (r >> 8) % 20000; i++)
				__asm__ __volatile__("" ::: "memory");
	}
	/* After the delay the slot must still hold this frame. */
	for (i = 0; i < ck->nframes; i++) {
		const struct kim_desc *d = &out[i].desc;

		gen(want, d->segment_id, d->scan_epoch, d->seg_offset, d->length);
		if (memcmp(want, ck->data + (size_t)i * FRAME, d->length))
			__atomic_fetch_add(&pt->corrupt, 1, __ATOMIC_RELAXED);
		if (memcmp(&ck->first[i], d, sizeof(*d)))
			__atomic_fetch_add(&pt->desc_changed, 1, __ATOMIC_RELAXED);
	}
}

static void on_result(const struct kd_result *r, void *arg)
{
	struct ptest *pt = arg;
	uint64_t tag;

	static uint8_t want[FRAME];

	/* the ring slot must still hold this frame while on_result runs */
	gen(want, r->desc.segment_id, r->desc.scan_epoch, r->desc.seg_offset, r->desc.length);
	if (!r->payload || memcmp(want, r->payload, r->desc.length))
		pt->payload_bad++;
	pt->n_direct += !!(r->desc.flags & KIM_F_DIRECT);
	pt->n_remap += !!(r->desc.flags & KIM_F_REMAP);
	memcpy(&tag, r->tag, sizeof(tag));
	pt->h = fold(pt->h, r->desc.segment_id, r->desc.seg_offset, r->desc.length,
		     r->desc.flags & (KIM_F_FIRST | KIM_F_LAST), tag);
}

static void on_epoch(const struct kd_epoch_stats *s, void *arg)
{
	struct ptest *pt = arg;

	if (s->epoch >= 1 && s->epoch <= NEPOCHS) {
		pt->digest[s->epoch] = pt->h;
		pt->frames[s->epoch] = s->frames;
		pt->st[s->epoch] = *s;
	}
	pt->h = 0;
	__atomic_fetch_add(&pt->seen, 1, __ATOMIC_RELEASE);
}

/* ------------------------------------------------------------------ */
/* P1                                                                 */
/* ------------------------------------------------------------------ */
static const struct pcfg PC[] = {
	/* name                  alpha  beta_P    beta_E   nP nE  slots delays gap  spin sw direct */
	{ "battery defaults",    0.75, 128 * KiB, 16 * KiB, 3, 2, 1024, false, 0,    512, 0, false },
	{ "AC defaults",         0.80, 256 * KiB, 16 * KiB, 3, 2, 1024, false, 0,    512, 0, false },
	{ "beta 512K/32K",       0.80, 512 * KiB, 32 * KiB, 2, 2, 1024, true,  0,    0,   0, false },
	{ "64-slot ring+delays", 0.50,  16 * KiB, 16 * KiB, 3, 3,   64, true,  0,    0,   0, false },
	{ "1 frame, idle gaps",  0.60,  16 * KiB, 16 * KiB, 1, 1,   64, true,  3000, 0,   0, false },
	{ "P only",              1.00,  64 * KiB, 16 * KiB, 2, 0,   64, true,  0,    64,  0, false },
	{ "E only",              0.00,  64 * KiB, 32 * KiB, 0, 3,  128, true,  0,    64,  0, false },
	{ "12 workers",          0.75,  64 * KiB, 16 * KiB, 8, 4,   64, true,  500,  0,   0, false },
	{ "AC->battery switch",  0.80, 256 * KiB, 32 * KiB, 2, 2,  256, false, 2000, 64,  2, false },
	{ "direct text",         1.00, 256 * KiB, 16 * KiB, 4, 0, 1024, false, 0,    512, 0, true },
	{ "direct+delays",       0.70, 128 * KiB, 32 * KiB, 2, 2,   64, true,  500,  0,   0, true },
};

static uint64_t g_ref[NEPOCHS + 1], g_ref_frames[NEPOCHS + 1];

static void run_pipeline(const struct pcfg *pc)
{
	static struct ptest pt;
	struct kd_dispatcher *d;
	struct kd_config cfg;
	struct kd_totals tot;
	struct kim_ctx c;
	struct mock m;
	uint64_t t0, exp_frames = 0;
	int i, err, bad_digest = 0, bad_share = 0, ep;
	bool switched = false;
	double worst = 0, tol;

	memset(&pt, 0, sizeof(pt));
	pt.pc = pc;
	mock_init(&m, &c, pc->nslots, pc->direct);
	m.nepochs = NEPOCHS;
	m.gap_us = pc->gap_us;

	kd_config_defaults(&cfg);
	cfg.params[KD_PWR_AC] = (struct kd_params){ pc->alpha, pc->beta_p, pc->beta_e };
	if (pc->switch_after)
		cfg.params[KD_PWR_BATTERY] = (struct kd_params){ 0.25, 16 * KiB, 16 * KiB };
	else
		cfg.params[KD_PWR_BATTERY] = cfg.params[KD_PWR_AC];
	cfg.power = KD_PWR_AC;
	for (i = 0; i < pc->np + pc->ne; i++)
		cfg.worker[i] = (struct kd_worker_spec){ -1, i < pc->np ? KD_P : KD_E };
	cfg.nworkers = pc->np + pc->ne;
	cfg.spin = pc->spin;
	cfg.work = test_work;
	cfg.work_arg = &pt;
	cfg.on_result = on_result;
	cfg.on_epoch = on_epoch;
	cfg.cb_arg = &pt;

	printf("P1 %-20s a=%.2f bP=%3uK bE=%2uK %dP+%dE slots=%u%s%s\n", pc->name, pc->alpha,
	       pc->beta_p / KiB, pc->beta_e / KiB, pc->np, pc->ne, pc->nslots,
	       pc->delays ? " delays" : "", pc->direct ? " direct" : "");
	err = kd_start(&d, &c, &cfg);
	if (err) {
		FAIL("kd_start: %s", strerror(-err));
		mock_free(&m);
		return;
	}
	pthread_create(&m.th, NULL, producer, &m);

	t0 = kim_now_ns();
	while (__atomic_load_n(&pt.seen, __ATOMIC_ACQUIRE) < NEPOCHS &&
	       kim_now_ns() - t0 < 30000000000ull) {
		if (pc->switch_after && !switched &&
		    __atomic_load_n(&pt.seen, __ATOMIC_ACQUIRE) >= pc->switch_after) {
			kd_set_power(d, KD_PWR_BATTERY);
			switched = true;
		}
		sleep_us(1000);
	}
	kd_request_stop(d);
	kd_join(d, &tot);
	__atomic_store_n(&m.stop, 1, __ATOMIC_RELEASE);
	pthread_join(m.th, NULL);

	for (ep = 1; ep <= NEPOCHS; ep++) {
		const struct kd_epoch_stats *s = &pt.st[ep];
		double share;

		exp_frames += g_ref_frames[ep];
		if (pt.digest[ep] != g_ref[ep] || pt.frames[ep] != g_ref_frames[ep] || s->partial)
			bad_digest++;
		if (!s->bytes)
			continue;
		share = (double)s->cls_bytes[KD_P] / s->bytes;
		tol = (double)(s->params.beta_p > s->params.beta_e ? s->params.beta_p : s->params.beta_e) /
		      s->bytes + 0.01;
		if (fabs(share - s->params.alpha) > tol)
			bad_share++;
		if (fabs(share - s->params.alpha) > worst)
			worst = fabs(share - s->params.alpha);
	}
	CHECK(pt.seen == NEPOCHS && !bad_digest, "%d/%d epochs bit-exact vs reference (%llu frames)",
	      NEPOCHS - bad_digest, NEPOCHS, (unsigned long long)tot.frames);
	CHECK(!pt.corrupt && !pt.desc_changed && !m.bad_tail && tot.frames == exp_frames &&
	      c.tail == m.head_priv,
	      "no slot reused under a worker (corrupt=%d desc=%d bad_tail=%llu), all consumed",
	      pt.corrupt, pt.desc_changed, (unsigned long long)m.bad_tail);
	CHECK(!bad_share, "P share tracks alpha per epoch (worst |share-alpha| = %.3f)", worst);
	CHECK(!pt.payload_bad, "result payload pointer valid inside on_result (bad=%d)", pt.payload_bad);
	if (pc->switch_after) {
		int first_bat = 0;

		for (ep = 1; ep <= NEPOCHS; ep++)
			if (pt.st[ep].power == KD_PWR_BATTERY && !first_bat)
				first_bat = ep;
		CHECK(first_bat > pc->switch_after && pt.st[NEPOCHS].power == KD_PWR_BATTERY &&
		      pt.st[NEPOCHS].params.alpha == 0.25 && pt.st[1].params.alpha == pc->alpha,
		      "power switch applied from epoch %d on (whole epochs only)", first_bat);
	}
	if (!pc->np || !pc->ne)
		CHECK(tot.cls_bytes[pc->np ? KD_E : KD_P] == 0, "single class: other class got 0 bytes");
	if (pc->direct)
		CHECK(pt.n_direct && pt.n_remap,
		      "text window and copied text frames both used (direct %llu, copied %llu)",
		      (unsigned long long)pt.n_direct, (unsigned long long)pt.n_remap);
	else
		CHECK(!pt.n_direct, "no DIRECT frames without a text window");
	printf("       ring_full=%llu chunks=%llu\n", (unsigned long long)m.full,
	       (unsigned long long)tot.chunks);
	mock_free(&m);
}

static void t_pipeline(void)
{
	size_t i;
	int ep;

	for (ep = 1; ep <= NEPOCHS; ep++)
		g_ref[ep] = reference_digest(ep, &g_ref_frames[ep]);
	for (i = 0; i < sizeof(PC) / sizeof(PC[0]); i++)
		run_pipeline(&PC[i]);
}

/* ------------------------------------------------------------------ */
/* Live system (informational)                                        */
/* ------------------------------------------------------------------ */
static void t_live(void)
{
	struct kd_power_info pi;
	struct kd_config cfg;
	struct kd_rapl rapl;
	struct kd_topo t;
	char p[128], e[128];
	int err;

	puts("L  live system");
	err = kd_topo_discover(&t, NULL);
	CHECK(!err, "live topology discovered");
	if (!err) {
		kd_topo_print(&t);
		kd_config_defaults(&cfg);
		kd_config_from_topo(&cfg, &t, false, -1, -1);
		worker_cpus(&cfg, KD_P, p, sizeof(p));
		worker_cpus(&cfg, KD_E, e, sizeof(e));
		printf("  placement: P workers %s | E workers %s | reader %d\n", p, e, cfg.reader_cpu);
	}
	CHECK(!kd_power_read(NULL, &pi), "live power state: %s%s%s", kd_power_name(pi.state),
	      pi.source[0] ? " via " : "", pi.source);
	err = kd_rapl_open(&rapl, NULL);
	printf("  RAPL package energy: %s\n", err ? strerror(-err) : "readable");
	kd_rapl_close(&rapl);
}

int main(void)
{
	t_cpu();
	t_parse();
	t_topology();
	t_power();
	t_power_monitor();
	t_params();
	t_pipeline();
	t_live();
	printf("\n%d passed, %d failed\n", g_pass, g_fail);
	return g_fail ? 1 : 0;
}
