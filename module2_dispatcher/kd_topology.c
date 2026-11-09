// SPDX-License-Identifier: GPL-2.0
/*
 * kd_topology.c - P/E core, SMT sibling and cache discovery (see kd_topology.h)
 */
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <cpuid.h>

#include "kd_topology.h"

const char *kd_class_name(enum kd_class c)
{
	return c == KD_P ? "P" : "E";
}

/* Read a small sysfs attribute, trailing whitespace stripped. */
static int read_attr(const char *sysroot, const char *rel, char *buf, size_t n)
{
	char path[512];
	ssize_t r;
	int fd;

	snprintf(path, sizeof(path), "%s/%s", sysroot ? sysroot : "/sys", rel);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	r = read(fd, buf, n - 1);
	close(fd);
	if (r < 0)
		return -errno;
	while (r > 0 && isspace((unsigned char)buf[r - 1]))
		r--;
	buf[r] = '\0';
	return 0;
}

/* Kernel cpulist format: "0-7", "0-3,8,10-11", "" (empty set). */
int kd_cpulist_parse(const char *s, cpu_set_t *set)
{
	CPU_ZERO(set);
	while (*s) {
		char *end;
		long a, b;

		while (isspace((unsigned char)*s) || *s == ',')
			s++;
		if (!*s)
			break;
		if (!isdigit((unsigned char)*s))
			return -EINVAL;
		a = strtol(s, &end, 10);
		b = a;
		if (*end == '-') {
			if (!isdigit((unsigned char)end[1]))
				return -EINVAL;
			b = strtol(end + 1, &end, 10);
		}
		if (b < a || b >= CPU_SETSIZE)
			return -EINVAL;
		if (*end && *end != ',' && !isspace((unsigned char)*end))
			return -EINVAL;
		for (; a <= b; a++)
			CPU_SET(a, set);
		s = end;
	}
	return 0;
}

int kd_cpulist_read(const char *sysroot, const char *rel, cpu_set_t *set)
{
	char buf[1024];
	int err = read_attr(sysroot, rel, buf, sizeof(buf));

	return err ? err : kd_cpulist_parse(buf, set);
}

/* sysfs cache sizes: "48K", "1280K", "12288K"; also accepts M/G and bare bytes. */
int kd_size_parse(const char *s, uint32_t *bytes)
{
	unsigned long long v;
	char *end;

	if (!isdigit((unsigned char)*s))
		return -EINVAL;
	v = strtoull(s, &end, 10);
	switch (toupper((unsigned char)*end)) {
	case 'G': v <<= 30; end++; break;
	case 'M': v <<= 20; end++; break;
	case 'K': v <<= 10; end++; break;
	}
	if (*end || v > UINT32_MAX)
		return -EINVAL;
	*bytes = (uint32_t)v;
	return 0;
}

/* CPUID.07H:EDX[15] = hybrid part; leaf 1AH EAX[31:24]: 0x20 Atom, 0x40 Core. */
static bool cpuid_is_hybrid(void)
{
	unsigned int a, b, c, d;

	if (!__get_cpuid_count(7, 0, &a, &b, &c, &d))
		return false;
	return (d >> 15) & 1;
}

static int cpuid_core_type_on(int cpu)
{
	unsigned int a = 0, b, c, d;
	cpu_set_t one;

	CPU_ZERO(&one);
	CPU_SET(cpu, &one);
	if (sched_setaffinity(0, sizeof(one), &one))
		return -errno;
	if (__get_cpuid_max(0, NULL) < 0x1a || !__get_cpuid_count(0x1a, 0, &a, &b, &c, &d))
		return -ENOTSUP;
	return (int)(a >> 24);
}

static void read_caches(const char *sysroot, int cpu, struct kd_cache *k)
{
	char rel[128], buf[64];
	int i;

	for (i = 0; i < 16; i++) {
		uint32_t size;
		int level;
		cpu_set_t shared;

		snprintf(rel, sizeof(rel), "devices/system/cpu/cpu%d/cache/index%d/level", cpu, i);
		if (read_attr(sysroot, rel, buf, sizeof(buf)))
			break;
		level = atoi(buf);
		snprintf(rel, sizeof(rel), "devices/system/cpu/cpu%d/cache/index%d/size", cpu, i);
		if (read_attr(sysroot, rel, buf, sizeof(buf)) || kd_size_parse(buf, &size))
			continue;
		snprintf(rel, sizeof(rel), "devices/system/cpu/cpu%d/cache/index%d/type", cpu, i);
		if (read_attr(sysroot, rel, buf, sizeof(buf)))
			continue;
		if (level == 1 && !strcmp(buf, "Data")) {
			k->l1d = size;
		} else if (level == 2 && strcmp(buf, "Instruction")) {
			k->l2 = size;
			snprintf(rel, sizeof(rel),
				 "devices/system/cpu/cpu%d/cache/index%d/shared_cpu_list", cpu, i);
			if (!kd_cpulist_read(sysroot, rel, &shared))
				k->l2_share = (uint32_t)CPU_COUNT(&shared);
		} else if (level == 3 && strcmp(buf, "Instruction")) {
			k->l3 = size;
		}
	}
}

int kd_topo_discover(struct kd_topo *t, const char *sysroot)
{
	cpu_set_t online, pset, eset, cores[KD_NCLASS];
	bool have_p, have_e, use_cpuid = false;
	cpu_set_t saved;
	int cpu, i, err;

	memset(t, 0, sizeof(*t));
	err = kd_cpulist_read(sysroot, "devices/system/cpu/online", &online);
	if (err)
		return err;
	if (!sysroot) {
		cpu_set_t allowed;

		if (!sched_getaffinity(0, sizeof(allowed), &allowed))
			CPU_AND(&online, &online, &allowed);
	}

	have_p = !kd_cpulist_read(sysroot, "devices/cpu_core/cpus", &pset);
	have_e = !kd_cpulist_read(sysroot, "devices/cpu_atom/cpus", &eset);
	if (!have_e)
		CPU_ZERO(&eset);
	if (have_p || have_e) {
		t->source = "sysfs-pmu";
	} else if (!sysroot && cpuid_is_hybrid()) {
		t->source = "cpuid";
		use_cpuid = !sched_getaffinity(0, sizeof(saved), &saved);
	} else {
		t->source = "uniform";
	}

	CPU_ZERO(&cores[KD_P]);
	CPU_ZERO(&cores[KD_E]);
	for (cpu = 0; cpu < CPU_SETSIZE && t->ncpu < KD_MAX_CPUS; cpu++) {
		struct kd_cpu *k;
		cpu_set_t sib;
		char rel[128];

		if (!CPU_ISSET(cpu, &online))
			continue;
		k = &t->cpus[t->ncpu++];
		k->cpu = cpu;
		k->cls = CPU_ISSET(cpu, &eset) ? KD_E : KD_P;
		if (use_cpuid && cpuid_core_type_on(cpu) == 0x20)
			k->cls = KD_E;

		k->core = cpu;
		snprintf(rel, sizeof(rel), "devices/system/cpu/cpu%d/topology/thread_siblings_list", cpu);
		if (kd_cpulist_read(sysroot, rel, &sib)) {
			snprintf(rel, sizeof(rel), "devices/system/cpu/cpu%d/topology/core_cpus_list", cpu);
			if (kd_cpulist_read(sysroot, rel, &sib))
				CPU_ZERO(&sib);
		}
		for (i = 0; i < cpu; i++)
			if (CPU_ISSET(i, &sib)) {
				k->core = i;
				break;
			}
		t->nlogical[k->cls]++;
		if (!CPU_ISSET(k->core, &cores[k->cls])) {
			CPU_SET(k->core, &cores[k->cls]);
			t->ncores[k->cls]++;
		}
	}
	if (use_cpuid)
		sched_setaffinity(0, sizeof(saved), &saved);
	if (!t->ncpu)
		return -ENODEV;
	t->hybrid = t->nlogical[KD_P] && t->nlogical[KD_E];

	for (i = 0; i < KD_NCLASS; i++)
		for (cpu = 0; cpu < t->ncpu; cpu++)
			if (t->cpus[cpu].cls == (enum kd_class)i) {
				read_caches(sysroot, t->cpus[cpu].cpu, &t->cache[i]);
				break;
			}
	return 0;
}

void kd_topo_print(const struct kd_topo *t)
{
	int i, c;

	printf("topology: %s, %s, %d CPUs\n", t->hybrid ? "hybrid" : "uniform",
	       t->source, t->ncpu);
	for (c = 0; c < KD_NCLASS; c++) {
		if (!t->nlogical[c])
			continue;
		printf("  %s: %d logical / %d cores | L1D %u K, L2 %u K (shared by %u), L3 %u K | cpus",
		       kd_class_name(c), t->nlogical[c], t->ncores[c],
		       t->cache[c].l1d >> 10, t->cache[c].l2 >> 10, t->cache[c].l2_share,
		       t->cache[c].l3 >> 10);
		for (i = 0; i < t->ncpu; i++)
			if (t->cpus[i].cls == (enum kd_class)c)
				printf(" %d", t->cpus[i].cpu);
		putchar('\n');
	}
}
