/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * kim_uapi.h - ABI shared by kernel_extractor.ko and the user-space bridge.
 *
 * Memory model (SPSC, lock-free):
 *   producer : kernel worker thread  - owns kim_hdr.head, descriptors, payload
 *   consumer : ingestion daemon      - owns kim_cons.tail
 *
 * mmap windows (byte offsets passed to mmap(2); each must be mapped whole):
 *   KIM_OFF_HDR   4 KiB  PROT_READ             kim_hdr (geometry, head, stats)
 *   KIM_OFF_CONS  4 KiB  PROT_READ|PROT_WRITE  kim_cons (consumer tail only)
 *   KIM_OFF_RING  16.06 MiB PROT_READ          [64 KiB descriptors][16 MiB payload]
 *   KIM_OFF_TEXT  hdr.text_win_len PROT_READ  live kernel text (direct_text=1):
 *                 page-aligned [_stext, _etext), never writable or executable
 *
 * Kernel-text frames flagged KIM_F_DIRECT carry no copy in their slot: the
 * payload is the live text at text window offset (base_address -
 * hdr.text_win_base). The kernel still walks the page tables for every such
 * frame each scan and only marks it DIRECT if every page still maps to the
 * physical page the window exposes; otherwise it copies (KIM_F_REMAP).
 *
 * Every shared index lives on its own 64-byte cache line (no false sharing).
 * Every payload slot is 16 KiB: 1 slot = E-core L1D chunk (beta_E min),
 * 2 slots = 32 KiB (beta_E max), 4..16 slots = 64..256 KiB (beta_P range).
 */
#ifndef KIM_UAPI_H
#define KIM_UAPI_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define KIM_DEV_NAME         "kernel_integrity_buf"
#define KIM_DEV_PATH         "/dev/" KIM_DEV_NAME
#define KIM_MAGIC            0x4b494d42u          /* "KIMB" */
#define KIM_ABI_VERSION      2u                   /* 2: text window, DIRECT/REMAP */

#define KIM_PAGE             4096ul
#define KIM_FRAME_SHIFT      14u
#define KIM_FRAME_BYTES      (1u << KIM_FRAME_SHIFT)            /* 16 KiB  */
#define KIM_NSLOTS           2048u        /* default; module param ring_slots */
#define KIM_NSLOTS_MIN       256u         /* hdr->nslots is a pow2 in [MIN, MAX] */
#define KIM_NSLOTS_MAX       4096u
#define KIM_DESC_SIZE        64u
#define KIM_NAME_LEN         20u
/* Ring geometry for n slots: n descriptors, then n payload slots. */
#define KIM_DESC_RING_BYTES_N(n) ((unsigned long)(n) * KIM_DESC_SIZE)
#define KIM_RING_BYTES_N(n)  ((unsigned long)(n) * (KIM_DESC_SIZE + KIM_FRAME_BYTES))
#define KIM_DESC_RING_BYTES  KIM_DESC_RING_BYTES_N(KIM_NSLOTS)  /* 128 KiB */
#define KIM_DATA_RING_BYTES  ((unsigned long)KIM_NSLOTS * KIM_FRAME_BYTES) /* 32 MiB */
#define KIM_RING_BYTES       KIM_RING_BYTES_N(KIM_NSLOTS)

/* mmap offsets are only keys: each must be mapped exactly, with its full length. */
#define KIM_OFF_HDR          0x00000ul
#define KIM_OFF_CONS         0x01000ul
#define KIM_OFF_RING         0x10000ul                          /* 64 KiB aligned */
#define KIM_OFF_TEXT         0x4000000ul

/* segment_type */
#define KIM_SEG_KTEXT          1u   /* [_stext, _etext)                    */
#define KIM_SEG_SYSCALL_TABLE  2u   /* sys_call_table                      */
#define KIM_SEG_COMPAT_TABLE   3u   /* ia32_sys_call_table / x32_...       */
#define KIM_SEG_MOD_TEXT       4u   /* LKM executable code                 */
#define KIM_SEG_MOD_RODATA     5u   /* LKM read-only data                  */

/* descriptor flags */
#define KIM_F_FIRST   0x0001u  /* first frame of segment in this epoch      */
#define KIM_F_LAST    0x0002u  /* last frame of segment in this epoch       */
#define KIM_F_FAULT   0x0004u  /* >=1 page not present/unreadable: zero-filled */
#define KIM_F_PTE_W   0x0008u  /* >=1 page had the PTE RW bit set (W^X alarm
                                  for text/rodata)                          */
#define KIM_F_PTE_X   0x0010u  /* >=1 page was executable (NX clear)        */
#define KIM_F_DIRECT  0x0020u  /* payload is in the text window, not the slot */
#define KIM_F_REMAP   0x0040u  /* kernel text page maps to a different physical
                                  page than at load (copied instead; alarm) */

/* One frame descriptor == exactly one cache line. */
struct kim_desc {
	__u64 base_address;     /* kernel VA of first payload byte (post-KASLR) */
	__u64 timestamp_ns;     /* CLOCK_MONOTONIC, ktime_get_ns()              */
	__u32 segment_type;
	__u32 segment_id;       /* unique per segment instance (module reload => new id) */
	__u32 length;           /* valid payload bytes (<= KIM_FRAME_BYTES)     */
	__u32 seg_length;       /* total bytes in segment                       */
	__u32 seg_offset;       /* byte offset of this frame in the segment     */
	__u32 scan_epoch;       /* full-scan generation                         */
	__u16 page_offset;      /* base_address & (PAGE_SIZE-1)                 */
	__u16 flags;
	char  name[KIM_NAME_LEN]; /* truncated segment/module name, NUL padded  */
} __attribute__((aligned(64)));

/* Kernel-owned, read-only to user space. */
struct kim_hdr {
	/* line 0: immutable after device registration */
	__u32 magic, abi_version, nslots, frame_bytes;
	__u32 desc_size, desc_off, data_off, reserved0;
	__s64 kaslr_slide;
	__u64 ktext_start, ktext_end;
	__u64 sys_call_table;
	/* line 1: resolved addresses (cont.) */
	__u64 ktext_phys, sct_phys, ia32_sct, x32_sct;
	__u64 text_win_base;    /* kernel VA of text window byte 0 (page aligned) */
	__u64 text_win_len;     /* 0 = no text window (direct_text=0 or refused)  */
	__u64 direct_frames;    /* frames published without a copy               */
	__u64 remap_frames;     /* text frames whose physical page had moved      */
	/* line 2: producer cursor */
	__u64 head __attribute__((aligned(64)));  /* release-stored by kernel */
	__u64 epoch, n_segments;
	__u64 pte_rechecks;     /* alarming PTE readings re-walked (W/absent/moved) */
	__u64 pte_overruled;    /* ... where the stable re-walk disagreed (a race) */
	__u64 copy_ns;          /* producer time emitting copied frames          */
	__u64 direct_ns;        /* producer time emitting direct (no-copy) frames */
	__u64 reserved2[1];
	/* line 3: statistics (single writer: kernel) */
	__u64 frames_total __attribute__((aligned(64)));
	__u64 bytes_total, ring_full_events, fault_pages;
	__u64 bad_tail_events, epochs_done, last_epoch_ns, seg_overflow;
};

/* User-owned: the kernel only ever *reads* tail and validates it. */
struct kim_cons {
	__u64 tail __attribute__((aligned(64)));
	__u64 reserved[7];
};

_Static_assert(sizeof(struct kim_desc) == 64, "descriptor must be one cache line");
_Static_assert(sizeof(struct kim_hdr) <= 4096, "hdr must fit one page");
_Static_assert(sizeof(struct kim_cons) <= 4096, "cons must fit one page");
_Static_assert((KIM_NSLOTS & (KIM_NSLOTS - 1)) == 0, "nslots must be pow2");
_Static_assert(KIM_DESC_RING_BYTES_N(KIM_NSLOTS_MIN) % KIM_FRAME_BYTES == 0,
	       "payload slots must stay 16 KiB aligned for every pow2 nslots >= MIN");

#define KIM_IOC_MAGIC        'K'
#define KIM_IOC_SET_INTERVAL _IOW(KIM_IOC_MAGIC, 1, __u32) /* ms; 0 = free-run */
#define KIM_IOC_KICK         _IO(KIM_IOC_MAGIC, 2)         /* start epoch now   */
#define KIM_IOC_RESCAN       _IO(KIM_IOC_MAGIC, 3)         /* re-enumerate LKMs */

#endif /* KIM_UAPI_H */
