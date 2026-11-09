/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kd_power.h - AC/battery state, change listener and RAPL package energy.
 *
 * State rule (class/power_supply, supplies with scope "Device" are ignored,
 * e.g. a wireless mouse battery):
 *   any Mains or USB* supply with online == 1  -> AC
 *   else any Mains supply or Battery present   -> BATTERY
 *   else (no supplies: desktop/VM)             -> AC
 *
 * As in kd_topology.h, 'sysroot' NULL means the live /sys; the uevent socket
 * is only used for the live system, mock trees are polled.
 */
#ifndef KD_POWER_H
#define KD_POWER_H

#include <pthread.h>
#include <stdint.h>

enum kd_power { KD_PWR_BATTERY = 0, KD_PWR_AC = 1, KD_PWR_NSTATES = 2 };

struct kd_power_info {
	enum kd_power state;
	int  n_mains, n_usb, n_battery;
	char source[32];          /* supply that decided "AC", if any        */
};

const char *kd_power_name(enum kd_power p);
int  kd_power_read(const char *sysroot, struct kd_power_info *pi);   /* 0 / -errno */

typedef void (*kd_power_cb)(enum kd_power st, void *arg);

struct kd_power_mon {
	pthread_t     th;
	const char   *sysroot;
	int           poll_ms;    /* re-read period; uevents wake it earlier */
	int           ufd;        /* NETLINK_KOBJECT_UEVENT, -1 if unused    */
	int           stopfd[2];
	enum kd_power state;
	kd_power_cb   cb;
	void         *arg;
};

/* Calls cb(state) once at start, then on every change, from its own thread. */
int  kd_power_mon_start(struct kd_power_mon *m, const char *sysroot, int poll_ms,
			kd_power_cb cb, void *arg);
void kd_power_mon_stop(struct kd_power_mon *m);

/* intel-rapl:0 (package) energy counter; root-only on current kernels. */
struct kd_rapl {
	int      fd;
	uint64_t max_uj;          /* wrap point                              */
};

int    kd_rapl_open(struct kd_rapl *r, const char *sysroot);         /* 0 / -errno */
int    kd_rapl_read(const struct kd_rapl *r, uint64_t *uj);
double kd_rapl_joules(const struct kd_rapl *r, uint64_t from_uj, uint64_t to_uj);
void   kd_rapl_close(struct kd_rapl *r);

#endif /* KD_POWER_H */
