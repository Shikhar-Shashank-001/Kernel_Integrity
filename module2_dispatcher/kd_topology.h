/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kd_topology.h - hybrid CPU topology for the Module-2 dispatcher.
 *
 * Classes come from the perf PMU cpu lists (devices/cpu_core = P,
 * devices/cpu_atom = E); if those are missing on a hybrid part, CPUID leaf
 * 0x1A is asked on each CPU. A non-hybrid machine reports every CPU as P.
 *
 * All sysfs reads take a 'sysroot' prefix: NULL means the live "/sys",
 * anything else is a mock tree (unit tests). CPUID and the affinity mask are
 * only consulted for the live system.
 */
#ifndef KD_TOPOLOGY_H
#define KD_TOPOLOGY_H

#include <stdbool.h>
#include <stdint.h>
#include <sched.h>

#define KD_MAX_CPUS 256

enum kd_class { KD_P = 0, KD_E = 1, KD_NCLASS = 2 };

struct kd_cpu {
	int           cpu;        /* logical CPU number                      */
	int           core;       /* lowest CPU of its SMT sibling group     */
	enum kd_class cls;
};

struct kd_cache {
	uint32_t l1d, l2, l3;     /* bytes, 0 = unknown                      */
	uint32_t l2_share;        /* logical CPUs sharing that L2            */
};

struct kd_topo {
	int             ncpu;     /* usable CPUs (online, and allowed if live) */
	struct kd_cpu   cpus[KD_MAX_CPUS];   /* sorted by cpu number          */
	int             nlogical[KD_NCLASS];
	int             ncores[KD_NCLASS];   /* physical cores per class      */
	struct kd_cache cache[KD_NCLASS];
	bool            hybrid;
	const char     *source;   /* "sysfs-pmu", "cpuid" or "uniform"         */
};

int  kd_cpulist_parse(const char *s, cpu_set_t *set);          /* 0 / -EINVAL */
int  kd_cpulist_read(const char *sysroot, const char *rel, cpu_set_t *set);
int  kd_size_parse(const char *s, uint32_t *bytes);            /* "48K" etc.  */
int  kd_topo_discover(struct kd_topo *t, const char *sysroot); /* 0 / -errno */
void kd_topo_print(const struct kd_topo *t);
const char *kd_class_name(enum kd_class c);

#endif /* KD_TOPOLOGY_H */
