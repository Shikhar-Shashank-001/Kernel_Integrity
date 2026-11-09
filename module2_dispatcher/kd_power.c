// SPDX-License-Identifier: GPL-2.0
/*
 * kd_power.c - power-state detection and listener (see kd_power.h)
 */
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#include "kd_power.h"

const char *kd_power_name(enum kd_power p)
{
	return p == KD_PWR_AC ? "AC" : "battery";
}

static int read_path(const char *path, char *buf, size_t n)
{
	ssize_t r;
	int fd = open(path, O_RDONLY | O_CLOEXEC);

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

static int read_supply(const char *dir, const char *name, const char *attr,
		       char *buf, size_t n)
{
	char path[1024];

	snprintf(path, sizeof(path), "%s/%s/%s", dir, name, attr);
	return read_path(path, buf, n);
}

int kd_power_read(const char *sysroot, struct kd_power_info *pi)
{
	char dir[384], type[32], val[32];
	struct dirent *de;
	DIR *d;

	memset(pi, 0, sizeof(*pi));
	pi->state = KD_PWR_AC;
	snprintf(dir, sizeof(dir), "%s/class/power_supply", sysroot ? sysroot : "/sys");
	d = opendir(dir);
	if (!d)
		return errno == ENOENT ? 0 : -errno;    /* no supplies: desktop */

	while ((de = readdir(d))) {
		bool charger;

		if (de->d_name[0] == '.')
			continue;
		if (read_supply(dir, de->d_name, "type", type, sizeof(type)))
			continue;
		if (!read_supply(dir, de->d_name, "scope", val, sizeof(val)) &&
		    !strcmp(val, "Device"))
			continue;                       /* peripheral battery */
		if (!strcmp(type, "Battery")) {
			pi->n_battery++;
			continue;
		}
		charger = !strcmp(type, "Mains");
		if (charger)
			pi->n_mains++;
		else if (!strncmp(type, "USB", 3))
			pi->n_usb++;
		else
			continue;
		if (!read_supply(dir, de->d_name, "online", val, sizeof(val)) &&
		    atoi(val) > 0 && !pi->source[0])
			snprintf(pi->source, sizeof(pi->source), "%.31s", de->d_name);
	}
	closedir(d);

	if (!pi->source[0] && (pi->n_mains || pi->n_battery))
		pi->state = KD_PWR_BATTERY;
	return 0;
}

/* ------------------------------------------------------------------ */
/* Listener                                                           */
/* ------------------------------------------------------------------ */
static int uevent_open(void)
{
	struct sockaddr_nl sa = { .nl_family = AF_NETLINK, .nl_groups = 1 };
	int fd = socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
			NETLINK_KOBJECT_UEVENT);

	if (fd < 0)
		return -1;
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa))) {
		close(fd);
		return -1;
	}
	return fd;
}

/* Drain pending uevents; true if any concerned a power supply. */
static bool uevent_drain(int fd)
{
	char buf[8192];
	bool hit = false;
	ssize_t r;

	while ((r = recv(fd, buf, sizeof(buf) - 1, 0)) > 0) {
		buf[r] = '\0';
		/* "action@devpath\0KEY=VAL\0..." : devpath contains the class */
		if (strstr(buf, "power_supply"))
			hit = true;
	}
	return hit;
}

static void *mon_main(void *arg)
{
	struct kd_power_mon *m = arg;

	for (;;) {
		struct pollfd p[2] = {
			{ .fd = m->stopfd[0], .events = POLLIN },
			{ .fd = m->ufd,       .events = POLLIN },
		};
		struct kd_power_info pi;
		int r = poll(p, m->ufd >= 0 ? 2 : 1, m->poll_ms);

		if (r < 0 && errno != EINTR)
			break;
		if (p[0].revents)
			break;
		if (r > 0 && p[1].revents && !uevent_drain(m->ufd))
			continue;               /* unrelated device event */
		if (!kd_power_read(m->sysroot, &pi) && pi.state != m->state) {
			m->state = pi.state;
			m->cb(pi.state, m->arg);
		}
	}
	return NULL;
}

int kd_power_mon_start(struct kd_power_mon *m, const char *sysroot, int poll_ms,
		       kd_power_cb cb, void *arg)
{
	struct kd_power_info pi;
	int err;

	memset(m, 0, sizeof(*m));
	m->sysroot = sysroot;
	m->poll_ms = poll_ms > 0 ? poll_ms : 5000;
	m->cb = cb;
	m->arg = arg;
	err = kd_power_read(sysroot, &pi);
	if (err)
		return err;
	m->state = pi.state;
	if (pipe2(m->stopfd, O_CLOEXEC))
		return -errno;
	m->ufd = sysroot ? -1 : uevent_open();
	cb(m->state, arg);
	err = pthread_create(&m->th, NULL, mon_main, m);
	if (err) {
		close(m->stopfd[0]);
		close(m->stopfd[1]);
		if (m->ufd >= 0)
			close(m->ufd);
		return -err;
	}
	return 0;
}

void kd_power_mon_stop(struct kd_power_mon *m)
{
	if (write(m->stopfd[1], "x", 1) < 0)
		perror("kd_power_mon_stop");
	pthread_join(m->th, NULL);
	close(m->stopfd[0]);
	close(m->stopfd[1]);
	if (m->ufd >= 0)
		close(m->ufd);
}

/* ------------------------------------------------------------------ */
/* RAPL                                                               */
/* ------------------------------------------------------------------ */
int kd_rapl_open(struct kd_rapl *r, const char *sysroot)
{
	const char *root = sysroot ? sysroot : "/sys";
	char path[384], buf[32];

	r->fd = -1;
	r->max_uj = 0;
	snprintf(path, sizeof(path), "%s/class/powercap/intel-rapl:0/max_energy_range_uj", root);
	if (!read_path(path, buf, sizeof(buf)))
		r->max_uj = strtoull(buf, NULL, 10);
	snprintf(path, sizeof(path), "%s/class/powercap/intel-rapl:0/energy_uj", root);
	r->fd = open(path, O_RDONLY | O_CLOEXEC);
	return r->fd < 0 ? -errno : 0;
}

int kd_rapl_read(const struct kd_rapl *r, uint64_t *uj)
{
	char buf[32];
	ssize_t n;

	if (r->fd < 0)
		return -EBADF;
	n = pread(r->fd, buf, sizeof(buf) - 1, 0);
	if (n <= 0)
		return n < 0 ? -errno : -EIO;
	buf[n] = '\0';
	*uj = strtoull(buf, NULL, 10);
	return 0;
}

double kd_rapl_joules(const struct kd_rapl *r, uint64_t from_uj, uint64_t to_uj)
{
	uint64_t d = to_uj >= from_uj ? to_uj - from_uj
				      : r->max_uj - from_uj + to_uj;   /* wrapped */

	return d / 1e6;
}

void kd_rapl_close(struct kd_rapl *r)
{
	if (r->fd >= 0)
		close(r->fd);
	r->fd = -1;
}
