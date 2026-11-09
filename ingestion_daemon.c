// SPDX-License-Identifier: GPL-2.0
/*
 * ingestion_daemon.c - zero-copy consumer for /dev/kernel_integrity_buf
 *
 * Library part (always built): mapping, lock-free peek/consume, chunking.
 * Daemon part (main): compiled out with -DKIM_LIB_ONLY (used by the tests).
 *
 * Memory ordering:
 *   head : acquire-load here  <-> release-store in the kernel
 *   tail : release-store here <-> acquire-load in the kernel
 * A frame is therefore fully written before we see it, and fully read
 * before the kernel is allowed to overwrite its slot.
 */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <time.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#ifdef __AVX2__
# include <immintrin.h>
#endif

#include "ingestion_daemon.h"

#define RING_ALIGN (64u * 1024u)   /* frames 16 KiB aligned, ring 64 KiB aligned */

uint64_t kim_now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* Map the ring at a 64 KiB aligned address: reserve, then MAP_FIXED over it. */
static int map_ring_aligned(struct kim_ctx *c)
{
	size_t span = c->ring_len + RING_ALIGN;
	uint8_t *rsv = mmap(NULL, span, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	uintptr_t a;
	void *m;

	if (rsv == MAP_FAILED)
		return -errno;
	a = ((uintptr_t)rsv + RING_ALIGN - 1) & ~(uintptr_t)(RING_ALIGN - 1);
	m = mmap((void *)a, c->ring_len, PROT_READ, MAP_SHARED | MAP_FIXED,
		 c->fd, (off_t)KIM_OFF_RING);
	if (m == MAP_FAILED) {
		int e = errno;

		munmap(rsv, span);
		return -e;
	}
	c->ring_map = m;
	c->ring_rsv = rsv;          /* kept so close can release the slack too */
	c->ring_rsv_len = span;
	return 0;
}

int kim_ctx_open(struct kim_ctx *c, const char *path)
{
	void *p;
	int err;

	memset(c, 0, sizeof(*c));
	c->fd = open(path, O_RDWR | O_CLOEXEC);   /* RDWR: tail page is writable */
	if (c->fd < 0)
		return -errno;

	p = mmap(NULL, KIM_PAGE, PROT_READ, MAP_SHARED, c->fd, (off_t)KIM_OFF_HDR);
	if (p == MAP_FAILED) { err = -errno; goto fail; }
	c->hdr = p;

	p = mmap(NULL, KIM_PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, c->fd,
		 (off_t)KIM_OFF_CONS);
	if (p == MAP_FAILED) { err = -errno; goto fail; }
	c->cons = p;

	/* geometry first: the ring is mapped at the size the header advertises */
	if (c->hdr->magic != KIM_MAGIC || c->hdr->abi_version != KIM_ABI_VERSION ||
	    c->hdr->nslots < KIM_NSLOTS_MIN || c->hdr->nslots > KIM_NSLOTS_MAX ||
	    (c->hdr->nslots & (c->hdr->nslots - 1)) || c->hdr->frame_bytes != KIM_FRAME_BYTES ||
	    c->hdr->desc_size != KIM_DESC_SIZE || c->hdr->desc_off != 0 ||
	    c->hdr->data_off != KIM_DESC_RING_BYTES_N(c->hdr->nslots)) {
		err = -EPROTO;
		goto fail;
	}
	c->ring_len = KIM_RING_BYTES_N(c->hdr->nslots);
	err = map_ring_aligned(c);
	if (err)
		goto fail;
	if (c->hdr->text_win_len) {     /* direct_text: frames may point here */
		p = mmap(NULL, c->hdr->text_win_len, PROT_READ, MAP_SHARED, c->fd,
			 (off_t)KIM_OFF_TEXT);
		if (p == MAP_FAILED) { err = -errno; goto fail; }
		c->text = p;
		c->text_len = c->hdr->text_win_len;
		c->text_base = c->hdr->text_win_base;
	}
	c->desc = (const struct kim_desc *)((const uint8_t *)c->ring_map + c->hdr->desc_off);
	c->data = (const uint8_t *)c->ring_map + c->hdr->data_off;
	c->mask = c->hdr->nslots - 1;
	c->frame_bytes = c->hdr->frame_bytes;
	c->tail = __atomic_load_n(&c->cons->tail, __ATOMIC_RELAXED);
	return 0;
fail:
	kim_ctx_close(c);
	return err;
}

void kim_ctx_close(struct kim_ctx *c)
{
	if (c->ring_map)
		munmap(c->ring_map, c->ring_len);
	if (c->ring_rsv)         /* leftover PROT_NONE slack around the window */
		munmap(c->ring_rsv, c->ring_rsv_len);   /* harmless if partly unmapped */
	if (c->text)
		munmap((void *)c->text, c->text_len);
	if (c->cons)
		munmap(c->cons, KIM_PAGE);
	if (c->hdr)
		munmap((void *)c->hdr, KIM_PAGE);
	if (c->fd > 0)
		close(c->fd);
	memset(c, 0, sizeof(*c));
	c->fd = -1;
}

uint64_t kim_available(const struct kim_ctx *c)
{
	uint64_t head = __atomic_load_n(&c->hdr->head, __ATOMIC_ACQUIRE);

	return head - c->tail;
}

/* Payload of frame 'seq': its ring slot, or the live kernel text for a
 * KIM_F_DIRECT frame. A DIRECT frame outside the window (cannot happen with a
 * correct kernel) resolves to its slot, whose bytes will not verify. */
const uint8_t *kim_payload(const struct kim_ctx *c, uint64_t seq)
{
	uint32_t slot = (uint32_t)seq & c->mask;
	const struct kim_desc *d = &c->desc[slot];

	if (d->flags & KIM_F_DIRECT) {
		uint64_t o = d->base_address - c->text_base;

		if (c->text && d->base_address >= c->text_base && o < c->text_len &&
		    d->length <= c->text_len - o)
			return c->text + o;
	}
	return c->data + (size_t)slot * c->frame_bytes;
}

size_t kim_peek(struct kim_ctx *c, struct kim_frame *out, size_t max)
{
	uint64_t avail = kim_available(c);
	size_t i, n = avail < max ? (size_t)avail : max;

	if (avail > c->hdr->nslots)      /* cannot happen unless the ABI is broken */
		return 0;
	for (i = 0; i < n; i++) {
		uint32_t slot = (uint32_t)(c->tail + i) & c->mask;

		out[i].d = &c->desc[slot];
		out[i].payload = kim_payload(c, c->tail + i);
	}
	return n;
}

uint32_t kim_peek_chunk(struct kim_ctx *c, uint32_t max_bytes, struct kim_chunk *ck)
{
	return kim_peek_chunk_at(c, c->tail, max_bytes, ck);
}

/* Like kim_peek_chunk() but starting at frame 'seq' (tail <= seq < head), so a
 * dispatcher can hand out chunks ahead of the in-order consume point. */
uint32_t kim_peek_chunk_at(struct kim_ctx *c, uint64_t seq, uint32_t max_bytes,
			   struct kim_chunk *ck)
{
	uint64_t head = __atomic_load_n(&c->hdr->head, __ATOMIC_ACQUIRE);
	uint64_t avail = head - seq;
	uint32_t slot0, n = 1, bytes, maxf = max_bytes / c->frame_bytes;
	const struct kim_desc *d0;

	if (seq >= head || seq < c->tail || head - c->tail > c->hdr->nslots)
		return 0;
	if (!maxf)
		maxf = 1;
	slot0 = (uint32_t)seq & c->mask;
	d0 = &c->desc[slot0];
	bytes = d0->length;

	/* Extend while frames are same segment+epoch, adjacent, previous frame
	 * full (only a segment's last frame is short), all in the same place
	 * (slots or text window) and the ring has not wrapped. */
	while (n < maxf && n < avail && slot0 + n < c->hdr->nslots) {
		const struct kim_desc *p = &c->desc[slot0 + n - 1];
		const struct kim_desc *q = &c->desc[slot0 + n];

		if (p->length != c->frame_bytes ||
		    q->segment_id != d0->segment_id ||
		    q->scan_epoch != d0->scan_epoch ||
		    q->seg_offset != p->seg_offset + p->length ||
		    ((q->flags ^ d0->flags) & KIM_F_DIRECT))
			break;
		bytes += q->length;
		n++;
	}
	ck->first = d0;
	ck->data = kim_payload(c, seq);
	ck->bytes = bytes;
	ck->nframes = n;
	return n;
}

void kim_consume(struct kim_ctx *c, uint32_t nframes)
{
	c->tail += nframes;
	__atomic_store_n(&c->cons->tail, c->tail, __ATOMIC_RELEASE);
}

int kim_wait(struct kim_ctx *c, int timeout_ms)
{
	struct pollfd p = { .fd = c->fd, .events = POLLIN };

	return poll(&p, 1, timeout_ms);
}

/* Read-everything kernel: stands in for the Module-2 hash (VAES/AVX2 slot). */
uint64_t kim_xor_checksum(const void *buf, size_t n)
{
	const uint8_t *p = buf;
	uint64_t r = 0;
	size_t i = 0;

#ifdef __AVX2__
	__m256i a0 = _mm256_setzero_si256(), a1 = a0, a2 = a0, a3 = a0;

	for (; i + 128 <= n; i += 128) {
		a0 = _mm256_xor_si256(a0, _mm256_loadu_si256((const __m256i *)(p + i)));
		a1 = _mm256_xor_si256(a1, _mm256_loadu_si256((const __m256i *)(p + i + 32)));
		a2 = _mm256_xor_si256(a2, _mm256_loadu_si256((const __m256i *)(p + i + 64)));
		a3 = _mm256_xor_si256(a3, _mm256_loadu_si256((const __m256i *)(p + i + 96)));
	}
	a0 = _mm256_xor_si256(_mm256_xor_si256(a0, a1), _mm256_xor_si256(a2, a3));
	{
		uint64_t t[4];

		_mm256_storeu_si256((__m256i *)t, a0);
		r = t[0] ^ t[1] ^ t[2] ^ t[3];
	}
#endif
	for (; i + 8 <= n; i += 8) {
		uint64_t w;

		memcpy(&w, p + i, 8);
		r ^= w;
	}
	return r;
}

#ifndef KIM_LIB_ONLY
/* ------------------------------------------------------------------ */
/* Daemon                                                             */
/* ------------------------------------------------------------------ */
static volatile sig_atomic_t g_stop;
static void on_sig(int s) { (void)s; g_stop = 1; }

struct sink_stats {
	uint64_t bytes, chunks, frames, xor_acc;
	uint64_t seg_bytes[8];       /* by segment_type */
};

/* Default sink: this is where Module 2 (hash verification) plugs in. */
static void default_sink(const struct kim_chunk *ck, void *user)
{
	struct sink_stats *s = user;

	s->xor_acc ^= kim_xor_checksum(ck->data, ck->bytes);
	s->bytes += ck->bytes;
	s->frames += ck->nframes;
	s->chunks++;
	if (ck->first->segment_type < 8)
		s->seg_bytes[ck->first->segment_type] += ck->bytes;
}

static void usage(const char *a0)
{
	fprintf(stderr,
		"usage: %s [-d dev] [-c cpu] [-p e|p] [-i interval_ms] [-t seconds]\n"
		"  -p e : 32 KiB chunks (E-core L1D)   -p p : 128 KiB chunks (P-core L2)\n", a0);
}

int main(int argc, char **argv)
{
	const char *dev = KIM_DEV_PATH;
	uint32_t chunk = KIM_CHUNK_P_CORE, interval = 0;
	int cpu = -1, secs = 0, opt, have_interval = 0;
	struct kim_ctx c;
	struct sink_stats st = {0};
	uint64_t t0, last = 0, last_bytes = 0;
	int ret;

	while ((opt = getopt(argc, argv, "d:c:p:i:t:h")) != -1) {
		switch (opt) {
		case 'd': dev = optarg; break;
		case 'c': cpu = atoi(optarg); break;
		case 'p': chunk = (optarg[0] == 'e') ? KIM_CHUNK_E_CORE : KIM_CHUNK_P_CORE; break;
		case 'i': interval = (uint32_t)atoi(optarg); have_interval = 1; break;
		case 't': secs = atoi(optarg); break;
		default:  usage(argv[0]); return 2;
		}
	}

	if (cpu >= 0) {
		cpu_set_t set;

		CPU_ZERO(&set);
		CPU_SET(cpu, &set);
		if (sched_setaffinity(0, sizeof(set), &set))
			perror("sched_setaffinity");
	}

	ret = kim_ctx_open(&c, dev);
	if (ret) {
		fprintf(stderr, "open %s: %s (root? module loaded?)\n", dev, strerror(-ret));
		return 1;
	}
	if (have_interval && ioctl(c.fd, KIM_IOC_SET_INTERVAL, &interval))
		perror("KIM_IOC_SET_INTERVAL");

	signal(SIGINT, on_sig);
	signal(SIGTERM, on_sig);
	t0 = last = kim_now_ns();

	while (!g_stop) {
		struct kim_chunk ck;
		uint32_t n = kim_peek_chunk(&c, chunk, &ck);
		uint64_t now;

		if (n) {
			default_sink(&ck, &st);
			kim_consume(&c, n);
		} else {
			kim_wait(&c, 100);
		}
		now = kim_now_ns();
		if (now - last >= 1000000000ull) {
			double dt = (now - last) / 1e9;

			printf("%6.1f MB/s | frames %llu | epochs %llu | ring_full %llu | "
			       "fault_pages %llu | bad_tail %llu | segs %llu | direct %llu remap %llu\n",
			       (st.bytes - last_bytes) / dt / 1e6,
			       (unsigned long long)st.frames,
			       (unsigned long long)c.hdr->epochs_done,
			       (unsigned long long)c.hdr->ring_full_events,
			       (unsigned long long)c.hdr->fault_pages,
			       (unsigned long long)c.hdr->bad_tail_events,
			       (unsigned long long)c.hdr->n_segments,
			       (unsigned long long)c.hdr->direct_frames,
			       (unsigned long long)c.hdr->remap_frames);
			fflush(stdout);
			last = now;
			last_bytes = st.bytes;
		}
		if (secs && (now - t0) / 1000000000ull >= (uint64_t)secs)
			break;
	}
	printf("total %llu bytes in %llu chunks (xor %016llx)\n",
	       (unsigned long long)st.bytes, (unsigned long long)st.chunks,
	       (unsigned long long)st.xor_acc);
	kim_ctx_close(&c);
	return 0;
}
#endif /* KIM_LIB_ONLY */
