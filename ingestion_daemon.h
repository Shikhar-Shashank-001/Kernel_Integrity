/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ingestion_daemon.h - user-space side of the zero-copy kernel memory ring.
 *
 * Consumer protocol (single consumer, lock-free):
 *     n = kim_peek_chunk(&c, KIM_CHUNK_P_CORE, &ck);   // acquire-load head
 *     ... hash/verify ck.data[0 .. ck.bytes) in place ...
 *     kim_consume(&c, n);                              // release-store tail
 * Nothing is ever copied out of the ring.
 */
#ifndef INGESTION_DAEMON_H
#define INGESTION_DAEMON_H

#include <stddef.h>
#include <stdint.h>
#include "kim_uapi.h"

/* Downstream cache-sized slices, all multiples of the 16 KiB frame. */
#define KIM_CHUNK_E_MIN   (1u * KIM_FRAME_BYTES)    /*  16 KiB  beta_E (L1D)  */
#define KIM_CHUNK_E_CORE  (2u * KIM_FRAME_BYTES)    /*  32 KiB                */
#define KIM_CHUNK_P_MIN   (4u * KIM_FRAME_BYTES)    /*  64 KiB  beta_P (L2)   */
#define KIM_CHUNK_P_CORE  (8u * KIM_FRAME_BYTES)    /* 128 KiB                */
#define KIM_CHUNK_P_MAX   (16u * KIM_FRAME_BYTES)   /* 256 KiB                */

/* Segment descriptor, as published by the kernel (see kim_uapi.h):
 *   segment_type, base_address, length, page_offset, timestamp_ns (+ extras) */
typedef struct kim_desc kim_segment_desc_t;

struct kim_ctx {
	int                    fd;
	const struct kim_hdr  *hdr;       /* RO window                       */
	struct kim_cons       *cons;      /* RW window (tail only)           */
	const struct kim_desc *desc;      /* RO, 64-byte aligned             */
	const uint8_t         *data;      /* RO, 16 KiB slots                */
	const uint8_t         *text;      /* RO live kernel text, or NULL    */
	size_t                 text_len;
	uint64_t               text_base; /* kernel VA of text[0]            */
	void                  *ring_map;  /* for munmap                      */
	void                  *ring_rsv;  /* alignment reservation           */
	size_t                 ring_rsv_len;
	size_t                 ring_len;  /* KIM_RING_BYTES_N(hdr->nslots)   */
	uint64_t               tail;      /* private mirror of cons->tail    */
	uint32_t               mask, frame_bytes;
};

struct kim_frame {
	const struct kim_desc *d;
	const uint8_t         *payload;   /* d->length valid bytes           */
};

/* Run of consecutive frames of ONE segment, contiguous in memory (no ring
 * wrap), so it can be handed to a SIMD kernel as a single buffer. All frames
 * of a chunk are either in ring slots or in the text window (KIM_F_DIRECT),
 * so frame i is always at data + i * KIM_FRAME_BYTES. */
struct kim_chunk {
	const struct kim_desc *first;
	const uint8_t         *data;
	uint32_t               bytes;     /* sum of frame lengths            */
	uint32_t               nframes;
};

typedef void (*kim_sink_fn)(const struct kim_chunk *ck, void *user);

int      kim_ctx_open(struct kim_ctx *c, const char *path); /* 0 or -errno */
void     kim_ctx_close(struct kim_ctx *c);
uint64_t kim_available(const struct kim_ctx *c);            /* frames ready */
const uint8_t *kim_payload(const struct kim_ctx *c, uint64_t seq); /* frame bytes */
size_t   kim_peek(struct kim_ctx *c, struct kim_frame *out, size_t max);
uint32_t kim_peek_chunk(struct kim_ctx *c, uint32_t max_bytes, struct kim_chunk *ck);
uint32_t kim_peek_chunk_at(struct kim_ctx *c, uint64_t seq, uint32_t max_bytes,
			   struct kim_chunk *ck);       /* tail <= seq < head */
void     kim_consume(struct kim_ctx *c, uint32_t nframes);
int      kim_wait(struct kim_ctx *c, int timeout_ms);       /* poll(2)     */
uint64_t kim_xor_checksum(const void *p, size_t n);         /* AVX2 if built */
uint64_t kim_now_ns(void);                                  /* CLOCK_MONOTONIC */

#endif /* INGESTION_DAEMON_H */
