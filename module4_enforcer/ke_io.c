// SPDX-License-Identifier: GPL-2.0
/*
 * ke_io.c - Module 4 side effects: alert sinks and the real action backend.
 *
 * auditd: AUDIT_TRUSTED_APP (1121, "trusted app msg - freestyle text") user
 * messages over NETLINK_AUDIT, as libaudit's audit_log_user_message() sends
 * them; needs CAP_AUDIT_WRITE. Records appear in /var/log/audit/audit.log
 * (ausearch -m TRUSTED_APP) or, without auditd, in the kernel log.
 */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <linux/netlink.h>

#include "ke.h"

#define KE_AUDIT_TRUSTED_APP 1121       /* libaudit.h; not in the uapi header */
#define KE_AUDIT_MAX         2048
#define KE_DETAIL_LINES      12         /* explanation lines sent to syslog */

/* ------------------------------------------------------------------ */
/* Sinks                                                              */
/* ------------------------------------------------------------------ */
void ke_sink_console(const struct ke_alert *a, void *arg)
{
	FILE *f = arg ? arg : stdout;

	fprintf(f, "[KE %-6s] %s\n", ke_sev_name(a->sev), a->line);
	fflush(f);
}

void ke_sink_syslog(const struct ke_alert *a, void *arg)
{
	static const int pri[KE_NSEV] = { LOG_INFO, LOG_NOTICE, LOG_WARNING, LOG_CRIT, LOG_ALERT };
	static bool opened;
	const char *d = a->detail;
	int lines = 0;

	(void)arg;
	if (!opened) {
		openlog("kim-integrity", LOG_PID | LOG_NDELAY, LOG_AUTHPRIV);
		opened = true;
	}
	syslog(pri[a->sev], "%s", a->line);
	/* the byte-level explanation of serious changes, one record per line */
	if (a->sev < KE_CRIT)
		return;
	while (d && *d && lines < KE_DETAIL_LINES) {
		const char *e = strchr(d, '\n');
		int l = e ? (int)(e - d) : (int)strlen(d);

		if (l > 0)
			syslog(pri[a->sev], "  detail: %.*s", l, d);
		lines += l > 0;
		d = e ? e + 1 : NULL;
	}
}

int ke_audit_open(void)
{
	int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_AUDIT);

	return fd < 0 ? -errno : fd;
}

static int audit_send(int fd, const char *msg)
{
	static uint32_t seq;
	union {
		struct nlmsghdr nh;
		char buf[NLMSG_SPACE(KE_AUDIT_MAX)];
	} req;
	struct sockaddr_nl kern = { .nl_family = AF_NETLINK };
	size_t len = strnlen(msg, KE_AUDIT_MAX - 1);
	struct pollfd p = { .fd = fd, .events = POLLIN };

	memset(&req, 0, sizeof(req));
	req.nh.nlmsg_len = NLMSG_LENGTH(len + 1);
	req.nh.nlmsg_type = KE_AUDIT_TRUSTED_APP;
	req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nh.nlmsg_seq = ++seq;
	memcpy(NLMSG_DATA(&req.nh), msg, len);
	if (sendto(fd, &req, req.nh.nlmsg_len, 0, (struct sockaddr *)&kern, sizeof(kern)) < 0)
		return -errno;

	/* the kernel acks with NLMSG_ERROR (error 0 = accepted) */
	if (poll(&p, 1, 200) == 1) {
		char ack[NLMSG_SPACE(sizeof(struct nlmsgerr))];
		ssize_t r = recv(fd, ack, sizeof(ack), MSG_DONTWAIT);
		const struct nlmsghdr *h = (const struct nlmsghdr *)ack;

		if (r >= (ssize_t)NLMSG_LENGTH(sizeof(struct nlmsgerr)) && h->nlmsg_type == NLMSG_ERROR)
			return ((const struct nlmsgerr *)NLMSG_DATA(h))->error;
	}
	return 0;
}

void ke_sink_audit(const struct ke_alert *a, void *arg)
{
	char msg[KE_AUDIT_MAX];
	int fd = arg ? *(int *)arg : -1, r;
	static bool warned;

	if (fd < 0)
		return;
	snprintf(msg, sizeof(msg), "op=kim-integrity %s", a->line);
	r = audit_send(fd, msg);
	if (r < 0 && !warned) {
		fprintf(stderr, "audit: %s (further audit errors not shown)\n", strerror(-r));
		warned = true;
	}
}

/* ------------------------------------------------------------------ */
/* Real action backend                                                */
/* ------------------------------------------------------------------ */
static int read_small(const char *path, char *buf, size_t n)
{
	ssize_t r;
	int fd = open(path, O_RDONLY | O_CLOEXEC);

	if (fd < 0)
		return -errno;
	r = read(fd, buf, n - 1);
	close(fd);
	if (r < 0)
		return -errno;
	buf[r] = '\0';
	return 0;
}

static int write_small(const char *path, const char *val)
{
	ssize_t r;
	int fd = open(path, O_WRONLY | O_CLOEXEC);

	if (fd < 0)
		return -errno;
	r = write(fd, val, strlen(val));
	close(fd);
	return r < 0 ? -errno : 0;
}

/* "none [integrity] confidentiality" -> "integrity" */
int ke_lockdown_current(char *buf, size_t n)
{
	char raw[128], *a, *b;
	int err = read_small("/sys/kernel/security/lockdown", raw, sizeof(raw));

	if (err)
		return err;
	a = strchr(raw, '[');
	b = a ? strchr(a, ']') : NULL;
	if (!b)
		return -EINVAL;
	snprintf(buf, n, "%.*s", (int)(b - a - 1), a + 1);
	return 0;
}

static int real_lockdown(void *ctx, const char *level)
{
	char cur[32];

	(void)ctx;
	if (!ke_lockdown_current(cur, sizeof(cur)) &&
	    (!strcmp(cur, level) || !strcmp(cur, "confidentiality")))
		return 1;                       /* already at least that strict */
	return write_small("/sys/kernel/security/lockdown", level);
}

static int real_modules_off(void *ctx)
{
	char cur[8];

	(void)ctx;
	if (!read_small("/proc/sys/kernel/modules_disabled", cur, sizeof(cur)) && cur[0] == '1')
		return 1;
	return write_small("/proc/sys/kernel/modules_disabled", "1");
}

static int real_unload(void *ctx, const char *module)
{
	(void)ctx;
	return syscall(SYS_delete_module, module, O_NONBLOCK) ? -errno : 0;
}

static int real_panic(void *ctx)
{
	(void)ctx;
	/* /proc/sysrq-trigger is not filtered by kernel.sysrq; 'c' = crash (kdump) */
	return write_small("/proc/sysrq-trigger", "c");
}

const struct ke_backend ke_backend_real = {
	real_lockdown, real_modules_off, real_unload, real_panic, NULL,
};
