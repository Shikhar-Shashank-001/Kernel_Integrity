# CLAUDE.md — Hardware-Accelerated Active Kernel Integrity & Lockdown (Ubuntu, hybrid CPU)

Read this first. It explains what exists (Phase 1 + Modules 1–4, all built and verified),
what is still open, and the design traps already found.
**Source files are the ground truth; this file explains intent, ABI and decisions.**

---------------------------------------------------------------------------
## 1. Project in one paragraph

Phase 1 built and benchmarked a cache-aware AES-CTR engine (256-bit VAES/AVX2)
for **hybrid Intel CPUs (P-cores + E-cores)**, tuned by three parameters:
`alpha` (fraction of data given to P-cores), `beta_P` (P-core chunk, kept in L2),
`beta_E` (E-core chunk, kept in L1D). Phase 2 reuses that engine to build an
**active Linux kernel integrity verifier**: continuously read the running
kernel's `.text`, `sys_call_table` and loaded-LKM memory, compute cryptographic
digests in cache-sized chunks spread over P/E cores according to power state,
compare to a golden baseline, and enforce (log, lockdown, unload, panic) on mismatch.

Target (product decision 2026-11-06): **Ubuntu 26.04 LTS only, Intel Core 12th gen (Alder Lake) and
newer only.** Kernel **7.0.0-42-generic** since 2026-11-06 (results up to then are on 7.0.0-38),
gcc 15.2. Every user-space binary links `kim_cpu.o` (kim_cpu.c, built WITHOUT -mavx2/-mvaes): a
constructor exits before main() unless the CPU is GenuineIntel, an Alder Lake-or-newer client model
(list from the kernel's intel-family.h, plus family 18) and has AVX2/VAES/VPCLMULQDQ/AES-NI/PCLMUL.
`KIM_ALLOW_ANY_CPU=1` skips only the model check. test_dispatcher U0 covers the model list (95/95).
Plan: finish testing + comparisons on this machine first; .deb packaging (DKMS + systemd, monitor-only
default) comes last.
After every kernel update: `make clean && make` (vermagic must match, else insmod "Invalid module
format"), then re-sign with MOK.priv/MOK.der.
Working dir today: `~/Locked_Kernel/File_Extractor/files`.

---------------------------------------------------------------------------
## 2. Module map and status

| Module | Purpose | Status |
|---|---|---|
| 1 Kernel Memory Extractor & Ingestion Engine | Zero-copy export of kernel `.text`, syscall tables, LKM text/rodata to user space | **DONE, 31/31 tests pass on 7.0.0-38 and 7.0.0-42 (ABI v2, direct_text: 8.8 -> 14.3 GB/s, §4.8)** |
| 2 Cache-Aware Hybrid Core Dispatcher | Power-aware alpha split, P/E thread pinning, beta chunking | **DONE: 71/71 tests + real-device runs on AC/battery bit-exact; streamed sweep -> P-only defaults** (§6) |
| 3 SIMD/VAES Verification Engine | Per-frame keyed tag (AES-GCM-SIV) at near memory-bandwidth speed | **Tag engine + baseline learn/check/explain DONE: live check caught 27/27 legit patches, 0 false events** (§7) |
| 4 Lockdown & Action Enforcement | Classify events, alert to auditd/syslog, lockdown, unload/panic | **DONE: 37/37 (mock backend), live dry-run 0 false actions, auditd+journald verified** (§7) |

Note: the original plan said Module 1 would use eBPF or `perf_event_open`.
**We implemented a custom LKM + `/dev/kernel_integrity_buf` + `remap_pfn_range()`**
(the other option listed in the spec). eBPF cannot read arbitrary kernel text
into a ringbuf as cheaply and cannot mmap it; keep the LKM.

---------------------------------------------------------------------------
## 3. Phase 1 results (inform Module 2/3 defaults)

Workload: 100 GB AES-CTR. Efficiency = GB/s per Watt. "Without power" = battery.

| Technique | Efficiency battery | Efficiency plugged in |
|---|---|---|
| CUDA AES-CTR (T-tables, PCIe bound) | 0.465 | 0.222 |
| CPU AES-CBC (serial dependency) | 0.523 | 0.318 |
| E-cores only | 0.825 | 0.624 |
| P-cores only (in-cache) | 2.663 | 1.678 |
| **Optimal hybrid (alpha, beta tuned)** | **3.426** | **2.304** |

Throughput: P-only 47.6 / 93.0 GB/s, E-only 7.85 / 15.1 GB/s, optimal hybrid
69.2 / 105.5 GB/s (battery / plugged). Plain CPU CTR (not cache-optimised): ~16 GB/s.

Tuned parameters:
- **Battery:** alpha = 0.75. Best region beta_P 64–256 KB, beta_E 16–32 KB (peak 3.43).
- **Plugged in:** alpha = 0.80. Best region beta_P 256–512 KB, beta_E 16–32 KB
  (peak 2.30; also 2.29 at beta_P 256 KB / beta_E 1024 KB). **The plan says
  beta_P 64–256 KB; the plugged heatmap peaks at 512 KB. Make beta_P configurable
  and re-sweep on the real pipeline.**
- Stats: alpha strongly correlates with efficiency (r=0.80), beta_E negatively
  (r=-0.30), beta_P not significantly.

**Critical caveat:** the 47–105 GB/s numbers are *in-cache* ("theoretical limit"):
the same chunk is re-encrypted from cache. Real kernel memory must stream from
DRAM, and Module 1 measured **~9 GB/s** for the kernel-side snapshot copy
(~9.3 GB/s ingest incl. AVX2 read). One scan is ~40 MiB (24.4 MB text + ~16 MB
modules) ≈ 4–5 ms of memory traffic. Expect Module 2/3 on real data to be bounded
by DRAM/copy bandwidth, not by the in-cache figures. Do not promise 100 GB/s.

---------------------------------------------------------------------------
## 4. Module 1 — what was built (files)

```
kim_uapi.h          Shared kernel/user ABI (descriptor, header, consumer page, ioctls, flags)
kernel_extractor.c  LKM: kallsyms bootstrap, segment table, worker kthread, misc device, mmap
ingestion_daemon.h  User API: kim_ctx, kim_frame, kim_chunk, peek/consume/wait, chunk-size macros
ingestion_daemon.c  Library (mmap, lock-free peek/consume, chunking, AVX2 xor) + demo daemon main()
test_extractor.c    T1–T6 functional tests + B1–B3 benchmarks (needs root + module loaded)
Makefile            kbuild + user build; see build notes (§8)
```

### 4.1 Architecture

```
 kernel worker kthread ──memcpy──> [ desc ring 64 KiB | payload 1024 x 16 KiB ] <──mmap RO── user
         │ publish: smp_store_release(hdr->head)        acquire-load(head)
         └ backpressure: acquire-load(cons->tail)       release-store(tail) ──────────────┘
```
- SPSC lock-free ring. Producer = kthread `kim_extractor`; consumer = **exactly one**
  user process (device is single-open, `EBUSY` otherwise, `CAP_SYS_ADMIN` only).
- User space never `read()`s: it consumes frames **in place** (no `copy_to_user`).
  The kernel does one in-kernel `memcpy` (snapshot) from kernel memory into the ring.
- Ring never blocks: if full, the worker publishes and backs off 100–300 µs, then
  resumes from a saved cursor. Nothing is dropped; `ring_full_events` counts it.

### 4.2 mmap windows (byte offsets; each must be mapped whole)

| Offset | Size | Prot | Content |
|---|---|---|---|
| `KIM_OFF_HDR` 0x0 | 4 KiB | R | `struct kim_hdr` (geometry, `head`, stats, resolved addresses) |
| `KIM_OFF_CONS` 0x1000 | 4 KiB | RW | `struct kim_cons` (consumer `tail` only; kernel validates it) |
| `KIM_OFF_RING` 0x10000 | `hdr.nslots` x (64 B + 16 KiB) | R | descriptors then payload slots (default 2048 slots = 128 KiB + 32 MiB) |
| `KIM_OFF_TEXT` 0x4000000 | `hdr.text_win_len` | R, never X | live kernel text (direct_text, §4.8) |

Ring write-protection is enforced: `PROT_WRITE` -> `EPERM`, `VM_MAYWRITE` cleared,
`MAP_PRIVATE`/wrong length refused. Ring memory is `vzalloc`ed (no stale-data leak).
The daemon maps the ring at a 64 KiB-aligned address (reserve + `MAP_FIXED`).

### 4.3 Frame descriptor (exactly 64 bytes, cache-line aligned)

`base_address` (kernel VA, post-KASLR), `timestamp_ns` (CLOCK_MONOTONIC),
`segment_type`, `segment_id` (unique per segment instance), `length` (valid bytes),
`seg_length`, `seg_offset`, `scan_epoch`, `page_offset`, `flags`, `name[20]`.
Types: `KTEXT=1, SYSCALL_TABLE=2, COMPAT_TABLE=3 (ia32/x32), MOD_TEXT=4, MOD_RODATA=5`.
Flags: `FIRST, LAST, FAULT (zero-filled page), PTE_W (writable PTE seen — W^X alarm), PTE_X`.

Geometry: 1 frame = 16 KiB payload slot. beta_E 16–32 KB = 1–2 frames;
beta_P 64–256 KB = 4–16 frames. Only a segment's last frame is short.
`kim_peek_chunk(ctx, max_bytes, &ck)` returns up to N consecutive frames of one
segment/epoch, contiguous in memory (no ring wrap) = one SIMD-ready buffer.
Chunk macros: `KIM_CHUNK_E_MIN/E_CORE (16/32 KiB)`, `KIM_CHUNK_P_MIN/P_CORE/P_MAX (64/128/256 KiB)`.

### 4.4 Segments extracted
- **Kernel text** `[_stext,_etext)` (~24.4 MB on this machine).
- **`sys_call_table`** (472 entries here) plus `ia32_sys_call_table` / `x32_sys_call_table` when present.
- **Per-module** text and rodata (376 module segments on this machine).

### 4.5 Safety and compatibility decisions (do not regress)
- `kallsyms_lookup_name` is unexported (>=5.7): resolved through a transient kprobe,
  **stepping back 4 bytes over ENDBR64** (IBT), plus a self-check.
- Every page: `lookup_address()` PTE check, then `copy_from_kernel_nofault()`
  (module param `fast_copy=1` -> plain memcpy after PTE check). Unreadable page =>
  zero frame + `KIM_F_FAULT`, never an Oops.
- KASLR: refuses to load if text is outside the kernel-image window or slide is not
  page-aligned. Header exposes `kaslr_slide`. No kernel addresses are logged to dmesg.
- Module memory lifetime: `MODULE_STATE_GOING` notifier takes `seg_lock`, so a
  module cannot be freed mid-copy. Initial enumeration walks the module list under RCU
  with `try_module_get`. Struct layout compat: `mod->mem[MOD_TEXT/RODATA]` (>=6.4) vs `core_layout`.
- Kernel-version shims: `vm_flags_set/clear` (>=6.3); `.llseek = no_llseek` only `< 6.12`.
- Module params: `scan_interval_ms` (0 = free-run), `worker_cpu`, `worker_nice`,
  `fast_copy`, `monitor_modules`, `ring_slots` (pow2 256-4096, default 2048 since round 3; user space maps
  `KIM_RING_BYTES_N(hdr.nslots)` and checks `data_off`), `backoff_us` (ring-full sleep
  `backoff_us..3x`, default 100). hdr `copy_ns`/`direct_ns`: producer time per frame kind
  (from the per-frame timestamp, no extra clock reads). ioctls: `KIM_IOC_SET_INTERVAL`, `KIM_IOC_KICK`, `KIM_IOC_RESCAN`.

### 4.6 Verified results (user's run, 7.0.0-38-generic)
23 passed / 0 failed / 0 skipped. Covers header/ABI/alignment, mmap hardening,
one full epoch (2797 frames, 40.4 MiB, 0 faults, 0 writable text PTEs, continuity ok),
addresses == `/proc/kallsyms`, all 472 syscall entries inside text, ring payload ==
`/proc/kcore` (3776 B). Benchmarks: producer 9.15 GB/s; ingest+AVX2 8.8–9.44 GB/s
(32/128/256 KiB chunks); kick->first-frame p50 151 µs, p99 249 µs;
`ring_full_events=888` (benchmark saturates the ring on purpose).
**Soak/churn (soak_churn.sh, 2026-11-02): PASS.** 600 s back-to-back through the full stack:
118,288 epochs (~5 TB scanned) at 8.31 GB/s while `dummy` was loaded/unloaded 537 times
(NEW_SEGMENT 1076 = VANISHED 1076); fault_pages 0, bad_tail 0, crit/emerg 0,
189 patch-like changes (network static keys toggled by the dummy netdev) all reverted. rmmod while
the device was open was refused ("in use") and succeeded after the daemon exited. fast_copy=1 +
worker_cpu=6 gave the identical modal digest and the kthread ran on CPU 6 (its 6.84 vs 7.35 GB/s is
confounded: CPU 6 also hosts a P worker). Slab +8.6 MB / VmallocUsed +0.4 MB after rmmod, not
attributable to kernel_extractor (537 netdev create/destroy cycles); a clean leak check would loop
insmod/rmmod without churn. **Caveat (found 2026-11-06): the dmesg check of this run was void** — it
took "lines after the starting line count", which is always empty once the kernel ring buffer is
full and rotating (direct_bench showed 0 new lines despite 14 insmods). Both scripts now write a
unique marker to /dev/kmsg and check every line after it, and count the module's "ready" lines as a
self-test. The soak was also on the copy path; re-run it on direct_text.
**Soak re-run on direct_text (2026-11-06): FAIL, 1 check, fixed in code (passing run below).**
191,557 epochs at 14.70 GB/s, 534 churn cycles (NEW_SEGMENT = VANISHED 1070), fault 0, bad_tail 0,
remap 0, 14 changes all reverted, dmesg clean (marker check working: 3 of 3 loads seen), fast_copy
digest identical, rmmod busy/after OK. The failure: **2 WX events (CRIT, would lockdown)** on
long-loaded modules (rfcomm text +0x4000 at epoch 31782, xfs text +0xe8000 at 156609), each one
epoch only and each at a dummy load/unload. Diagnosis (most likely, not proven): a false reading.
The kernel has CONFIG_ARCH_HAS_EXECMEM_ROX, so module text shares 2M ROX pages that CPA
splits and re-merges (`cpa_collapse_large_pages`) on every module load/unload, and our lockless
`lookup_address()` reads the PMD twice, so it can see a merged 2M page's code bytes as PTEs or read a
PTE table being freed. Fix (kernel_extractor.c `kim_pte_stable/kim_pte_recheck`): any alarming
reading (W, not present, text pfn moved) is re-walked once per level from a single snapshot with
IRQs off (gup_fast style; collapse frees the old table only after flush_tlb_all's IPIs), using
init_mm.pgd resolved via kallsyms (init_mm isn't exported). New hdr counters `pte_rechecks` /
`pte_overruled` (reserved2 slots, layout unchanged) are printed on kd_daemon's "kernel (this run)" line:
overruled > 0 with wx 0 confirms the race.
**Soak re-run with the PTE fix (2026-11-06 16:50): race confirmed fixed; 1 new false CRIT, fixed.**
`pte rechecks 2, overruled 2`, wx 0 (the race happened twice and was filtered). 141,572 epochs at
10.87 GB/s (whole machine slower this run: part C default 9.73 vs 14.54 before, so not the fix;
cause unchecked, power/thermal?), 529 churn cycles, fault/bad_tail/remap 0, dmesg clean, digest
identical. The CRIT: CHANGED "unexplained" on ktext udp_destroy_sock+0x36 `eb20 -> 6690`, which is the
UDP encap static key (same flip as 7 neighbours, classed jmp8->nop2, all reverted later). The
decoder tried 5-byte forms first and accepted an unchanged 0xe9 byte 1-4 bytes before the site as a
"jmp retarget" (implausible target). Fix (kv_explain.c `decode_one`): pass 0 tries only nop<->branch
transitions in every form, pass 1 only retargets. Regression test added (test_baseline 30/30).
**Soak with both fixes, kernel 7.0.0-42 (2026-11-06 18:36): PASS, all 10 checks.** 209,507 epochs at
14.78 GB/s, 525 churn cycles (NEW_SEGMENT = VANISHED 1052), crit/emerg 0, wx 0, fault 0, remap 0,
bad_tail 0; 115 changes all patch-like (0 unexplained), 112 reverted, 0 left in CHANGED;
`pte rechecks 1, overruled 1` (race hit once more, filtered); dmesg clean with 3/3 loads seen;
fast_copy digest identical (13.09 vs 13.86 GB/s default); rmmod busy/after OK; memory after rmmod
Slab +4.6 MB, VmallocUsed -3.8 MB (no leak signal). This is the first fully valid soak (the 11-02
one had a void dmesg check and ran on the copy path).

### 4.7 Known limitations of Module 1
- A module that unlinks itself from the module list is invisible to the initial
  enumeration (the load notifier still sees it if loaded after us). Cross-check with
  `/sys/module` and address-range sweeps later.
- Init-section memory is not monitored (freed after init). `MOD_RO_AFTER_INIT` not included yet.
- x86_64 only; relies on `lookup_address()`/PTE bits.
- Snapshot copy costs one DRAM read+write per byte. Done for kernel text (§4.8, direct_text);
  modules keep snapshots (lifetime hazard: their pages can be freed on unload).

### 4.8 direct_text (ABI v2, 2026-11-04): kernel text hashed in place, not copied
The kernel's single copy thread was the pipeline bottleneck (§6). Kernel text (24.4 of 40.4 MiB per
scan) is physically contiguous and never freed, so with module param `direct_text=1` (default):
- init: window = `[_stext & PAGE_MASK, PAGE_ALIGN(_etext))` (never past it: the page after can be
  freed at boot); refused (pr_warn, direct off) unless every page is present and maps linearly from
  `__pa_symbol(start)`. mmap of `KIM_OFF_TEXT` = one `remap_pfn_range`; PROT_WRITE/PROT_EXEC ->
  EPERM, VM_MAYWRITE/VM_MAYEXEC cleared, exact length, MAP_SHARED only.
- every scan, per text frame: still `lookup_address()` per page (W/X flags as before) and check the
  page maps to the window's physical page -> descriptor only, `KIM_F_DIRECT`, no copy. Mismatch ->
  copy as before + `KIM_F_REMAP` (someone remapped kernel text: kv_baseline `REMAP` event, Module 4
  CRIT like W^X). Not present -> copy path -> FAULT as before.
- user lib: `kim_payload(c, seq)` resolves slot vs window; `kim_peek_chunk_at` never mixes DIRECT
  and copied frames, so `ck->data + i * 16 KiB` stays valid for every consumer. hdr line 1 gained
  `text_win_base, text_win_len, direct_frames, remap_frames` (was reserved1[4]).
- Semantics change: DIRECT bytes are read live while hashing, not snapshotted, so a text_poke
  during the read can give a torn frame -> suspect -> TRANSIENT on the confirm scan (same as before
  when the copy raced a patch). Tag/digest definition unchanged: copy and direct must give the same
  digest.
- Tests: test_extractor T2 (+4 window hardening) and T7 (all text frames DIRECT, 0 REMAP, window ==
  /proc/kcore on 5 sampled frames); test_dispatcher +2 direct configs (static mock text window, slot
  poisoned, every 7th text frame copied as REMAP) -> 91/91, TSAN clean; negative control (library
  allowed to mix) caught: 169 bad frames, 0/6 digests. test_baseline 29/29 (REMAP once per frame),
  test_enforcer 38/38. Live validation + A/B: `sudo ./direct_bench.sh`.

**Real device 2026-11-06 (AC, direct_bench.sh, 3 interleaved reps x 10 s, fixed key, -L 0):**
test_extractor 31/31 (T2 window hardening, T7: every text frame DIRECT, 0 REMAP, window == kcore);
producer-only rate 18.6 GB/s (was 9.15), single-thread ingest+AVX2 13.2-14.8 GB/s (was 8.8-9.4).

| config | GB/s | W | GB/J | vs copy |
|---|---|---|---|---|
| copy (direct_text=0), P-only default | 8.81 ± 0.18 | 33.8 | 0.261 ± 0.011 | |
| **direct, P-only default** | **14.30 ± 0.22** | 36.9 | **0.387 ± 0.007** | **+62% GB/s, +48% GB/J** |
| direct, hybrid alpha 0.8 | 13.63 ± 0.24 | 43.4 | 0.314 ± 0.007 | +55%, +20% |
| direct, E-only | 13.26 ± 0.32 | 41.1 | 0.323 ± 0.018 | +50%, +24% |

- Epoch digest `28d933341452e8d2` identical in all 12 runs (copy and direct): bit-exact.
- P-only stays the most efficient with direct_text (hybrid/E-only slower AND +4-7 W), so the
  2026-11-03 defaults stand. Battery not measured yet.
- live_check.sh on the direct path: same as on copy — 20/20 static-key + 7/7 ftrace CHANGED
  patch-like, all REVERTED, dummy NEW_SEGMENT/VANISHED x2, 0 transient/unstable/wx/fault/remap,
  0 Module-4 action records.
- **AC vs battery, same day (2026-11-07, kernel 7.0.0-42, direct_bench 3 reps x 10 s each;
  CSVs direct_bench_ac.csv / direct_bench_bat.csv, figures + script in plots/):**

  | config | AC GB/s | AC W | AC GB/J | Bat GB/s | Bat W | Bat GB/J |
  |---|---|---|---|---|---|---|
  | copy | 7.57 ± 0.46 | 39.7 | 0.192 | 6.66 ± 0.04 | 14.1 | 0.473 |
  | direct P-only | **14.26 ± 0.34** | 39.9 | **0.358** | **11.96 ± 0.02** | 15.6 | **0.769** |
  | direct P+E 0.8 | 13.59 ± 0.05 | 45.0 | 0.302 | 11.85 ± 0.01 | 16.8 | 0.705 |
  | direct E-only | 12.95 ± 0.46 | 45.5 | 0.285 | 11.12 ± 0.06 | 15.6 | 0.715 |

  direct vs copy: AC +88% GB/s / +86% GB/J, battery +79% / +63%. Digest identical within each
  session (12/12). P-only best in both states. Battery direct = 0.84x the AC throughput at 0.39x the
  power = 2.15x the efficiency: the last ~24 W on AC buy only ~2.3 GB/s (~0.1 GB/J marginal), so an
  AC power cap / power-saver profile is the obvious next efficiency experiment. Battery runs have
  CV <= 0.6% (vs up to 6% on AC): use battery for small A/B differences. Copy on AC 7.57 vs 8.81 on
  11-04 (-38 kernel, 33.8 W) while direct is unchanged (14.26 vs 14.30): cross-day, cause unchecked.
- Next limit not identified: 4 P workers average ~3.6 GB/s each (single-core tag ~8.3 GB/s from
  DRAM), producer alone tops out at 18.6 GB/s (still copies 16 MiB of modules per scan); DRAM
  traffic per scan is now ~2x the scanned bytes. Measure before optimising further.
- **Profile round 1 (2026-11-08, AC, -42, `SET=pipeline ./profile_bench.sh`, 2 reps x 8 s):** the
  limit is the kernel thread. Scan = 40.6 MiB = 1495 direct text frames (23.4 MiB) + 1314 copied
  module frames (~20.5 MiB, `copy_from_kernel_nofault`). kthread on CPU 87%, runnable-waiting 0%,
  asleep 12% (~1 ring-full back-off per scan: the 1495 text descriptors do not fit in 1024 slots).
  Reader: waits for workers 52% / ring empty 42%. P workers ~40% busy (the old "20% avg" included
  4 idle E workers; fixed: busy is now per class). 1 P worker: 10.4 GB/s at 94% busy; 2P 13.6;
  4P 14.6. xor tag 14.3 (tag compute is not the limit). kthread nice 0: 14.3 (no change); pinned
  to an E-core: 12.3-12.5 (slower, confirms producer-bound). AC run-to-run spread up to 13%.
- **Profile round 2 (2026-11-08, battery, `SET=producer`, 3 reps, CV 0-3%):** kthread 99% on CPU,
  never asleep; 87% of wall emitting copied frames at only 5.7 GB/s, 12% direct frames (~290 ns
  each). base 11.78 GB/s 0.760 GB/J. No gain from ring 2048 (11.48) / 4096 (11.20), back-off 20 us
  (11.85), fast_copy (11.40, slower: keep the nofault copy); ring 256/512 hurt (9.22/11.35).
  **Win: kthread alone on a P core (3 workers + kthread on CPU 6): 12.50 GB/s (+6%), 0.778 GB/J**,
  copy rate 6.5 GB/s (no SMT sibling contention). Now the kd_daemon default (`-K`, kthread pinned
  from user space with sched_setaffinity; `-K -1` = old layout).
- **Profile round 3 (2026-11-08, `SET=kcore`, 5 reps, battery then AC):** with the kthread on its own
  core it outruns the consumers in the text phase again and sleeps 10-13% on a full 1024-slot ring;
  2048 slots removes that (sleep 0%). Battery (drifted down ~10% over the run, shuffled):
  4P-shared 10.97 GB/s 0.665 GB/J | auto 12.14 0.730 | **auto+r2048 13.08 0.770 (+19%, +16%)** |
  auto+bo20 12.16. AC: 13.96 0.342 | 14.34 0.337 | **15.58 0.358 (+12%, +5%)** | 14.77 0.345.
  r2048 beat 4P-shared in every rep on both. **Defaults now: ring 2048 slots (32 MiB + 128 KiB),
  kthread on its own P core (daemon).** back-off stays 100 us (no gain).
  Re-signed; test_extractor 31/31 and soak_churn.sh PASS with these defaults (user-reported,
  2026-11-08). **This is the finalised working version.**
  Remaining lever: module text/rodata is still copied (~20 MiB/scan, ~87% of the producer's time);
  only zero-copy for module memory removes it (design not started; pages are freed on unload).

---------------------------------------------------------------------------
## 5. Hard design constraints discovered (must be solved in Phase 2)

1. **Kernel text is legitimately patched at runtime** (jump labels/static keys, ftrace
   call sites, kprobes/eBPF, static calls, livepatch, alternatives on CPU hotplug/mitigation
   changes; modules too). A naive "hash == baseline" will raise false positives.
   Options: (a) baseline after boot settles and treat changes as events to explain,
   (b) **mask known patch sites** (jump_label, ftrace, alternatives tables) and hash the rest,
   (c) watch patch events and re-baseline affected regions. `sys_call_table` (rodata) is
   normally immutable — a mismatch there is a strong signal. **But since 6.9 x86-64 dispatches
   syscalls through `x64_sys_call()` / `ia32_sys_call()` (switch statements in text), not through
   `sys_call_table`** (confirmed on 7.0: no `ia32_/x32_sys_call_table` symbols). Patching the table
   no longer hooks anything; real hooks must change text, which the ktext hash covers. Keep the
   table check as a tripwire. Also: Module 1 skips its own module text (enumeration starts after
   THIS_MODULE), so the monitor does not measure itself yet. Module 1 itself briefly
   registers a kprobe at load.
2. **Baselines are per boot, not universal.** KASLR relocations and module load addresses
   are baked into the bytes, so hashes differ across boots (and per module load).
   Capture the golden baseline at a trusted point each boot (early, after modules settle)
   or normalise relocations. Key module baselines by module name (+ build id) and seg_offset.
3. **Protect the baseline and the key.** A root attacker can rewrite a baseline stored in
   plain user space. Plan for: signed/sealed baseline (TPM/IMA or kernel keyring), and keep the
   MAC key out of attacker-readable memory. Decide the threat model explicitly.
4. **The ring is single-consumer.** Module 2 has many worker threads but only one process may
   open the device. Use **one reader/dispatcher thread** that peeks chunks (zero-copy
   pointers) and hands them to per-worker queues. **Do not call `kim_consume()` until every
   worker has finished reading that chunk** — the kernel reuses a slot as soon as `tail`
   passes it. Implement in-order completion tracking (or copy out if you need out-of-order).
5. **AES-CTR alone is not a digest.** CTR produces keystream; encrypting memory with it does
   not give a verifiable fingerprint. For Module 3 use an integrity primitive that is also
   parallel and VAES/PCLMUL friendly: **GHASH/GMAC (VPCLMULQDQ) or AES-based PMAC**, or a
   keyed hash. Avoid CBC-MAC/CMAC (serial dependency — exactly the Phase-1 bottleneck).
   Compute **per-chunk tags** keyed by (segment_id/name, seg_offset) so a mismatch localises
   the changed region and workers need no ordering between chunks.
6. **Plan wording to fix:** `security_locked_down()` is a *query* ("is lockdown active for
   reason X?"), not a trigger. To raise lockdown at runtime from user space, write
   `integrity` or `confidentiality` to `/sys/kernel/security/lockdown` (one-way until reboot;
   requires the lockdown LSM enabled). **On the dev machine lockdown is already `integrity` at
   boot (Secure Boot)**, so only `confidentiality` is left to raise; that level blocks kprobes,
   `/proc/kcore`, perf, tracefs and BPF kernel reads. Verify behaviour on this kernel before relying on it,
   and note lockdown will also block things Module 1 uses (e.g. `/proc/kcore`, new unsigned
   modules, kprobes) — load everything needed *before* locking.
7. **Secure Boot:** an unsigned `.ko` is rejected ("Key was rejected by service"). Sign with
   a MOK key after every rebuild. Never commit `MOK.priv`.

---------------------------------------------------------------------------
## 6. Module 2 — Cache-Aware Hybrid Core Dispatcher (done; throughput tuning open)

```
module2_dispatcher/
  kd_topology.[ch]   P/E classes (PMU cpu lists, CPUID 0x1A fallback), SMT siblings, caches
  kd_power.[ch]      AC/battery rule, listener (netlink uevent + polling), RAPL package energy
  kd_dispatcher.[ch] reader -> per-worker SPSC queues -> in-order completion -> kim_consume()
  kd_daemon.c        real-device driver: xor tag stand-in, per-epoch GB/s, W, GB/J, digest
  test_dispatcher.c  U1-U6 unit tests on mock sysfs trees + P1 pipeline vs a mock kernel producer
  Makefile           make | make test | make tsan   (uses ../ingestion_daemon.c, ../kim_uapi.h)
```
All sysfs readers take a `sysroot` (NULL = live `/sys`) so tests run on mock trees.
Module 1 library gained `kim_peek_chunk_at(c, seq, max, ck)` (user lib only, no ABI change).

Dev machine (i5-12450H): P = CPUs 0–7 (4 cores x SMT2, L1D 48K, L2 1280K per core),
E = CPUs 8–11 (L1D 32K, one 2 MB L2 shared by the 4), mains supply `ADP1`, RAPL root-only.

Design decisions (keep unless re-decided):
- **One reader thread** owns the device. It dispatches ahead of `tail` (`disp_seq`) and completes
  strictly in ring order (`comp_seq == c->tail`): a slot is consumed only after every frame up to
  it is done. In-flight window capped at one ring (pend_n/done/res are per slot).
- **alpha = per-epoch byte credit:** next chunk goes to P while P's share <= alpha (error <= one
  chunk per epoch; worst measured 0.006). **Strict**: if every queue of that class is full the reader
  waits, no work stealing, so a sweep measures alpha itself. Within a class: least-assigned worker.
- **Power changes apply at the next epoch boundary**; per-epoch stats record the params used.
- **Results are per frame** (`kd_result`: descriptor copy + 32-byte tag) and delivered in ring order,
  so digests and verdicts are independent of alpha/beta/timing. Chunk boundaries are NOT stable
  (they depend on what the kernel had published at peek time) => **Module 3 must emit per-frame (or
  per-page) tags, never per-chunk tags.** The `kd_work_fn` signature already enforces this.
- Placement: one worker per physical P core (siblings share the L2 that beta_P targets) + every
  E core; reader on the spare SMT sibling of a busy P core (CPU 7 here). `-s` uses both siblings.
- Defaults (changed 2026-11-03 after the streamed sweep below): **alpha 1.0 (P-cores only),
  beta_P 256K, beta_E 16K for both power states** (were the Phase-1 optima 0.75/128K/16K battery,
  0.80/256K/16K AC). Betas are rounded to 16 KiB frames, range 16 KiB–1 MiB.
- Workers spin `cfg.spin` polls (512) then futex-sleep (10 ms timeout as a missed-wakeup safety net);
  the reader futex-waits on completions (200 µs) or poll(2)s the device when idle.
- Epoch end = first frame of the next epoch, or (idle) `hdr->epoch` advanced and every published
  frame consumed. Relies on x86 TSO for the kernel's head-then-epoch store order.
- First epoch after attaching is flagged `partial` unless `tail` was 0 (fresh module load).
- Power rule: any Mains/USB* supply online -> AC; else Mains or Battery present -> battery;
  supplies with `scope=Device` (mouse batteries) ignored; no supplies -> AC.

Verified 2026-10-26 (user space, no root): 62/62 pass, 5 repeated runs, TSAN clean x3 (TSAN cannot
model the seq_cst fences of the futex eventcount; that part is reasoned, not tool-checked).
P1 covers 9 configs (alpha 0..1, beta 16K..512K, 1..12 workers, 64..1024-slot rings, random worker
delays, idle gaps, mid-epoch module unload, short frames, AC->battery switch). Negative control:
consuming at dispatch time is caught (up to 194 corrupted frames, all digests wrong) in every config
with ring pressure; configs without ring pressure cannot detect it by design.

Real-device results 2026-10-26 (7.0.0-38, `scan_interval_ms=0`, `kd_daemon -t 10`, xor tag):

| Power | alpha / beta_P / beta_E | GB/s per epoch | Package W | GB/J |
|---|---|---|---|---|
| AC | 0.80 / 256K / 16K (default) | 4.9–5.8 | 43–45 | 0.11–0.13 |
| AC | 0.50 / 64K / 32K | ~5.4 | ~38 | 0.142 |
| battery | 0.75 / 128K / 16K (default) | ~4.7 avg | n/a | 0.262 |
| battery | 0.50 | ~4.7 avg | n/a | 0.282 |

- Acceptance met on real data: epoch digest `76f1560527167a74` identical in all 4 runs (different
  alpha/beta/power, ~5000 epochs), P share exactly alpha, per-worker bytes within 0.2% inside a
  class, `bad_tail 0`, `fault_pages 0`, 0 pin failures, 378 segments (376 module + ktext + sct).
- **Throughput is below Module 1's single-consumer 9 GB/s, and the pipeline is producer-bound.**
  Pinning the kthread (`worker_cpu=1 worker_nice=0`) gave only +3% (AC, 5.73 -> 5.89 GB/s avg) and
  +6% (battery, 4.89 -> 5.18). Removing a P worker (`-n 3`) did not lower throughput (P workers just
  took more each), and per-run `ring_full` was only ~2-3.5k / 10 s (producer blocked < ~7% of the
  time) => workers are not the limit. Remaining suspects: the kthread shares a physical core with a
  P worker (CPUs 1/3/5 are all siblings of workers; untested: `-n 3` + `worker_cpu=6`), and lower
  all-core turbo vs the single-thread Module-1 benchmark. Real fix if needed: skip the snapshot copy
  for static kernel text (§4.7). At 1 scan/s an epoch costs ~7 ms (<1% duty), so not urgent.
- Lower alpha was more energy-efficient in both power states with the trivial xor tag (the job is
  copy/DRAM bound, so E-cores are as useful as P-cores). **Do not retune defaults until Module 3's
  real tag adds compute**, then re-sweep (task 8). GB/J is not comparable to Phase-1's in-cache 2.3–3.4.
- Older `ring_full` numbers were cumulative since insmod (they include time with no consumer);
  `kd_daemon` now prints per-run deltas.

Still to do for Module 2:
- Optional: `-n 3` with `worker_cpu=6`; unplug/replug during a run to exercise the netlink path.

**Streamed alpha/beta sweep (sweep.sh, AC 2026-11-02 22:21, battery 2026-11-03 08:19).** 138 runs
per state (7 alphas x 4 beta_P x 2 beta_E, 3 reps, 8 s, shuffled), SIV tags, no baseline.
On AC efficiency drifted -28% over the 25 min sweep (laptop heating up; raw CV 9.2%); runs are in
random order so sweep_analyze.py removes a linear trend over run order -> CV 2.9%. Battery: package
power capped at 16-17 W in every config, drift -1%, CV 3.7%. Drift-corrected results:

| | AC GB/s | AC W | AC GB/J | Battery GB/s | Battery W | Battery GB/J |
|---|---|---|---|---|---|---|
| E-only (alpha 0) | 8.89 | 39.5 | 0.227 | 5.85 | 17.0 | 0.343 |
| P-only (alpha 1) | 8.56 | 37.1 | **0.235** | 5.81 | 16.6 | **0.351** |
| old default (Phase-1 hybrid) | 8.82 | 41.9 | 0.212 | 5.64 | 16.9 | 0.334 |
| hybrid alphas 0.5-0.9 (marginal) | 8.65-8.89 | | 0.207-0.214 | 5.49-5.67 | | 0.329-0.336 |

- **P-only is +11% more efficient than the Phase-1 hybrid on AC** (> 2x noise) at -3% throughput and
  -11% power; on battery +5% (within noise, same direction). beta_P 512 > 64 on AC (+8%, r=+0.46 in
  hybrid runs, consistent with Phase 1's plugged heatmap peak at 512 KB); beta_E no effect.
- Why this inverts Phase 1: Phase 1 was compute-bound (in-cache AES-CTR, P-cores ~6x faster than
  E). Here the bottleneck is the single kernel snapshot-copy thread (~9 GB/s AC, ~5.8 GB/s battery);
  the SIV tag is cheap (P:E only 1.6x) and 4 workers of either class have ~3x spare capacity, so
  waking the second core class adds power, not throughput. On battery the package power cap makes
  every config cost ~16.5 W, so efficiency = throughput.
- Throughput in these runs (8.2-9.6 GB/s AC) is far above the 5.7-5.9 GB/s measured on 10-26/10-28
  for the same config; cause not identified (system load / module params of those sessions?).
  Comparisons inside one sweep are valid; across days they are not.
- Follow-ups: worker-count sweep (`-n`/`-m`, e.g. 2 P workers) and removing the snapshot copy for
  static text (§4.7) — the producer, not alpha, is now the lever. **Snapshot removal done 2026-11-06
  (direct_text, §4.8): 8.81 -> 14.30 GB/s, 0.261 -> 0.387 GB/J on AC; P-only still best.**

## 7. Module 3 — verification engine and Module 4 — enforcement

**Decision (user, 2026-10-26): per-frame tag = AES-GCM-SIV (RFC 8452)**, chosen over AES-PMAC and
SHA-256/SHA-NI. Tag = AES-GCM-SIV encryption of an EMPTY plaintext with
AAD = location block || frame payload; location block = LE32 segment_type, LE32 seg_offset,
LE32 seg_length, LE32 fnv1a32(name). Fixed nonce "KIM-FRAME-v1" per key (nonce reuse is safe for
SIV; it makes the tag deterministic and lets the POLYVAL key/powers be derived once per key).
Addresses, segment_id and epoch are deliberately not bound (they change across reloads/scans).
Plain GMAC was rejected: same nonce + changed memory would leak the GHASH key.

```
module3_verifier/
  kv_tag.[ch]      key derivation (RFC 8452 s4), CPU dispatch, tag driver, location block
  kv_ref.c         by-definition reference: FIPS-197 AES (S-box computed), POLYVAL = a*b*x^-128 bitwise
  kv_fast.c        AES-NI + 256-bit VPCLMULQDQ, 8 blocks per step with H^1..H^8, one reduction per step
  kv_impl.h        internal ops table
  gen_vectors.py   independent vectors from python3-cryptography (OpenSSL) -> kv_vectors.h (kept in tree)
  test_verifier.c  T1-T6 KATs/differential tests, B1 per-core-type throughput
  Makefile         make | make test | make vectors; builds libkv.a (linked by kd_daemon)
```
Verified 2026-10-26: 12/12 — AES-128/256 FIPS-197, RFC 8452 appendix A POLYVAL and C.1 tag, 42
OpenSSL vectors (AES-128/256, AAD 0..16400 B incl. every 16-byte boundary), 3 frame vectors, 400
random fast-vs-reference tags (unaligned) + POLYVAL 0..40 blocks. Both impls pass everything.

Single-thread tag throughput (AES-256, 16 KiB frames): **P-core 9.3 GB/s in-cache / 8.3 GB/s from
DRAM; E-core 6.0 / 5.2 GB/s** (ratio ~1.6x, far below Phase-1 VAES CTR's ~6x, because POLYVAL is
carry-less multiply, not AES rounds). 4P+4E capacity >> the ~5.9 GB/s producer, so the pipeline stays
producer-bound. Headroom if needed: 16-block stride / taking the S*H_8 product off the reduction
critical path (the loop is latency-bound on the per-step reduction).

`kd_daemon` now uses it by default (`-T siv`; `-T xor` = old checksum). Key: random 256-bit per run
from getrandom(), mlock()ed, wiped at exit; `-k <hex>` fixes it so digests can be compared across runs.
Key protection beyond that (TPM/keyring sealing) is still open (§5.3).

Real-device run 2026-10-28 (AC, `scan_interval_ms=0`, fixed `-k`, 10 s each):

| Tag | alpha / beta_P / beta_E | Avg GB/s | Package W | GB/J | Digest |
|---|---|---|---|---|---|
| SIV | 0.80 / 256K / 16K | 5.72 | 46.5–48.6 | 0.127–0.130 | 927ac6dd2c30a382 |
| SIV | 0.50 / 64K / 32K | 5.56 | 47.6–49.2 | 0.100–0.109 | 927ac6dd2c30a382 |
| xor | 0.80 / 256K / 16K | 5.65 | 46.6–48.5 | 0.089–0.091 | 76f1560527167a74 |

- Real tag is bit-exact across alpha/beta and costs no throughput vs xor (still producer-bound).
- With the real tag alpha=0.80 beat 0.50 on GB/J (reversed vs the xor-only runs of 10-26), as
  expected once workers do real compute. Package power varied ~10% between days for the same
  config, so the task-8 sweep needs repetitions and interleaved ordering.
- The xor digest equals the 10-26 one: kernel text + module text/rodata unchanged in between
  (if the machine was not rebooted) — legitimate patching looks rare in steady state.

**Baseline (decided with user 2026-10-28: "learn, re-verify, explain"; baseline in memory per
daemon run, random key).** `kv_baseline.[ch]` + `kv_explain.[ch]` in module3_verifier, linked into
`kd_daemon` (`-L` learn epochs = 3, `-C` confirm scans = 1, `-B` no baseline bytes):
- LEARNING: first -L complete epochs record each frame's tag (+ a copy of the bytes, ~40 MiB);
  a frame changing meanwhile -> UNSTABLE (latest kept). Partial first epoch is not counted.
- CHECKING: differing frame -> suspect; still differing after -C more scans -> CHANGED (with
  explanation); suspect that matches again -> TRANSIENT; CHANGED that matches -> REVERTED; a
  CHANGED frame is re-reported only if its content changes again. Also NEW_SEGMENT (module loaded
  after learning, trusted on first use), VANISHED, WX (writable PTE), FAULT — once per frame.
- Frames keyed by (segment_id, seg_offset): ids are stable while the device is open.
- Explanation = changed byte ranges symbolised via /proc/kallsyms (reloaded when modules appear
  or a target is unresolved), with nop5<->jmp/call rel32, nop2<->jmp8 and call/jmp retargets
  decoded; syscall tables decoded per entry. Verdict is a HINT only (never suppresses an event):
  patch-like = jump target inside the same function, or entry call (<=16 B) into an
  ftrace/trampoline/bpf symbol, or retarget between known symbols; else unexplained.
- `kd_result` gained `payload` (ring pointer, valid only inside on_result) so the reader can copy /
  diff bytes before the slot is released; covered by a new test_dispatcher check.
- Tests: test_baseline 22/22 (mock kallsyms, real SIV tags: jump-label patch, revert, transient,
  ftrace attach, mid-function call into an unknown module, syscall-table hijack, module
  load/unload, W^X/fault once, unstable-while-learning, no-bytes, confirm 0); test_dispatcher 71/71.
- Live validation script (root): `module3_verifier/live_check.sh` — static key flip
  (sched_schedstats), `dummy` module load/unload, ftrace on vfs_read; restores everything on exit.
- **Live run 2026-10-29 (7.0.0-38, scans every 250 ms):** quiet period 0 events; static key flip
  -> 20 frames CHANGED, all 20 REVERTED on restore; dummy -> NEW_SEGMENT x2 (text+rodata), then
  VANISHED x2; ftrace on vfs_read -> 7 CHANGED, all 7 REVERTED; 0 TRANSIENT/UNSTABLE/WX/FAULT.
  Detection was 27/27, but 8 were labelled UNEXPLAINED by two decoder gaps, now fixed:
  (1) adjacent patch sites merged into one range (3 x nop2 back to back, nop5+nop2 in the
  scheduler) — ranges are now tiled into consecutive instructions; (2) call retargets were judged
  by the entry-call rule — ftrace's `ftrace_call: ftrace_stub -> function_trace_call` and
  tracepoint static calls `__traceiter_sched_wakeup -> probe_sched_wakeup` are now "retarget
  between known symbols". Also: frames with >12 ranges no longer turn unexplained just because the
  printed list is capped. Regression tests X2 (7 cases, incl. negatives) added: test_baseline 29/29.
  **Re-run 2026-10-29 21:28 with the fix: 20/20 static-key and 7/7 ftrace changes patch-like, 0
  unexplained.** The re-run also caught unprompted background patching after the ftrace step:
  7 networking frames (dev_queue_xmit_nit, netif_receive_skb, packet_rcv, tpacket_rcv,
  ip_local_deliver_finish, ip6_input_finish, __ioam6_fill_trace_data) flipped nop->jmp and back
  twice within ~5 s — the packet-tap / timestamp static keys, toggled when some process opens a
  packet or timestamping socket (likely NetworkManager reacting to the dummy interface; not
  verified). All decoded as same-function jump labels (patch-like) and reverted after ~1 scan.
  => legitimate runtime patching does happen in normal operation; Module 4 must treat
  "patch-like CHANGED then REVERTED" as low-severity/aggregated and alert on unexplained ones.
- Known limit of the hint: a retarget into a function of a malicious *module* still resolves to a
  known symbol and looks patch-like (static calls legitimately target modules, e.g. kvm_intel).
  Module 4 should weigh it together with NEW_SEGMENT timing.

Still to do for Module 3:
- Authoritative patch-site tables from Module 1 (jump_label / ftrace / static_call) to replace
  the pattern heuristic; key/baseline sealing (TPM/keyring) for persistence across restarts.

### Module 4 — enforcement (built and live-validated in dry-run 2026-10-29)

```
module4_enforcer/
  ke.h / ke.c      policy: severity, rate limits, summaries, action planning, deferred panic
  ke_io.c          sinks (console, syslog/journald, auditd over NETLINK_AUDIT) + real backend
  test_enforcer.c  E1-E8 with a mock backend and fake clock (nothing on the host changes)
  Makefile         make | make test; builds libke.a (linked by kd_daemon)
```
Severity (ke_classify): EMERG = CHANGED syscall/compat table; CRIT = CHANGED code with verdict
unexplained, CHANGED mod_rodata (any verdict), WX; WARN = NEW_SEGMENT/VANISHED (unless `-N`
allow-listed), FAULT, UNSTABLE, CHANGED without bytes; NOTICE = patch-like CHANGED (INFO if the
segment is `-W` allow-listed), TRANSIENT; INFO = REVERTED, LEARNED. Allow-lists never downgrade an
unexplained change. Names compare as descriptors store them (19 chars).

Actions — **dry-run by default**; every recommended action is logged as `kim_action=... result=
would|done|already|failed|not-enabled|no-suspect|pending-confirmation|cancelled-reverted`:
- CRIT+: lockdown -> `confidentiality` and `kernel.modules_disabled=1` (default action set with
  `-e`; one-way until reboot, not destructive; each executed/described once per run).
- CRIT+ with `-A ...,unload`: `delete_module(O_NONBLOCK)` of SUSPECTS only = modules that loaded
  after the baseline (NEW_SEGMENT, not allow-listed) AND appear as `[module]` branch targets in the
  explanation. Opt-in because unloading a module whose hooks are still in kernel text can oops.
- EMERG with `-A ...,panic`: sysrq 'c' only after the change persisted `panic_confirm` (3) more
  complete epochs (on top of kv_baseline's confirm scan); a REVERTED of that frame cancels it.
Alerts: one-line key=value records. Console gets action+summary lines (the daemon already prints
[EVENT] details); syslog (tag `kim-integrity`, LOG_AUTHPRIV, crit/emerg also get the explanation
lines) gets everything; auditd gets WARN+ as AUDIT_TRUSTED_APP (1121) `op=kim-integrity ...`
(define is ours: libaudit not installed). Rate limit: token bucket per severity (burst 20,
10/min; INFO+NOTICE share one), suppressed counts go into the summary (every 60 s, only if
something happened). Action and summary records are never rate limited.

kd_daemon flags: `-e` enforce, `-A lockdown,modules,unload,panic,all,none`, `-N` allow-new,
`-W` allow-change, `-S` no syslog, `-U` no audit, `-X` self-test (synthetic WARN/CRIT/EMERG
through the real sinks, always dry-run, no device needed). `-e` requires SIV + baseline.

Verified 2026-10-29: test_enforcer 37/37; `kd_daemon -X` delivered all records to journald
(non-root; auditd path needs root — check with `sudo ./kd_daemon -X` then
`sudo ausearch -m TRUSTED_APP -ts recent`). live_check.sh now also reports Module 4 action
records, which must be 0 for the legitimate changes it makes.

Live (root) 2026-10-29: `sudo kd_daemon -X` -> auditd received every WARN+ record as
`type=TRUSTED_APP ... msg='op=kim-integrity ...'` (uid=0 auid=1000; note subj=snap.code.code: started
from the VS Code snap terminal it carries that AppArmor label — production should run from systemd).
live_check.sh dry-run: **0 action records** for all legitimate activity; enforcer counted info 28,
notice 34, warn 4 (dummy NEW_SEGMENT x2 + VANISHED x2), crit 0, emerg 0; 39 low-severity alerts
suppressed by the shared INFO/NOTICE bucket and reported in the summary. Same run: right after
`modprobe -r dummy` the 7 networking static-key frames flipped for a single scan -> 7 TRANSIENT
(not CHANGED), which supports the dummy-interface hypothesis of §7 and shows the confirm scan works.

**Fixed 2026-11-06:** `plan()` ran modules_disabled before unload_suspects(), but the kernel's
delete_module() returns EPERM once kernel.modules_disabled=1, so `-A ...,unload` with the default
set could never unload a suspect. Unload now runs first. The mock backend now refuses unload after
modules_off, as the kernel does (test_enforcer 38/38 failed 1 before the fix).

Still open for Module 4: enforcement was only tested
against the mock backend — raising lockdown on the dev laptop is one-way until reboot, so do it
deliberately, e.g. in a VM; self-protection (the daemon/module can be killed by a root attacker);
sealed key/baseline.

---------------------------------------------------------------------------
## 8. Build, run, test

```bash
sudo apt install build-essential linux-headers-$(uname -r)
make clean && make                    # module + ingestion_daemon + test_extractor
make SIMD=                            # portable user-space build (no AVX2/VAES)
sudo make test                        # insmod, run T1–T6 + benchmarks, rmmod
sudo insmod kernel_extractor.ko [scan_interval_ms=1000 worker_cpu=N fast_copy=1]
sudo ./ingestion_daemon -p p -t 10    # -p e|p chunk size, -c cpu, -i interval ms
sudo rmmod kernel_extractor
```
Module 2 (user space only; run `make` there, not the top-level `make`, if you don't want to
rebuild/resign the .ko):
```bash
cd module3_verifier && make && make test         # tag KATs, throughput, baseline tests; no root
sudo ./live_check.sh                             # baseline vs real legitimate kernel changes
cd module4_enforcer && make && make test         # policy/actions with a mock backend; no root
cd module2_dispatcher && make && make test       # no root needed; make tsan for ThreadSanitizer
sudo ./kd_daemon -t 10 [-a alpha] [-P KiB] [-E KiB] [-n maxP] [-m maxE] [-s] [-f ac|bat] [-i ms]
                      [-T siv|xor] [-k hexkey] [-L n] [-C n] [-B]
                      [-e] [-A lockdown,modules,unload,panic] [-N mods] [-W segs] [-S] [-U] [-X]
```
Secure Boot signing (repeat after each rebuild):
`sudo /usr/src/linux-headers-$(uname -r)/scripts/sign-file sha256 MOK.priv MOK.der kernel_extractor.ko`

Makefile notes: kbuild half and user half are split by `ifneq ($(KERNELRELEASE),)`.
`.RECIPEPREFIX = >` is set **only inside the `else` (user) branch** — putting it at the top
breaks the kernel's own makefiles. If `make` says "missing separator", the file was damaged
(e.g. pasted into the wrong file or tabs lost). The previous run of `make clean` can warn if
nothing is built yet; harmless. Compiler/pahole version warnings are harmless (no BTF needed).

Tools to use when changing kernel code: `dmesg -w`, `sudo bpftrace`/`ftrace` (note: enabling
tracing patches kernel text — see §5.1), `perf stat` for cache behaviour, `cat /proc/kallsyms`
(needs root for addresses), `mokutil --sb-state`.

---------------------------------------------------------------------------
## 9. Conventions for working in this repo

- Kernel C: Linux kernel style (tabs, 80 cols), GPL-2.0, **no sleeping while holding `seg_lock`
  across a copy**, never block the extraction path, validate all consumer-written data.
- Anything touching `kim_uapi.h` changes the ABI: bump `KIM_ABI_VERSION`, update both sides
  and the tests. Keep descriptors at 64 bytes (`_Static_assert`).
- Any kernel-API use must be guarded for 6.x vs 7.x (`LINUX_VERSION_CODE`). Re-test on
  7.0.0-38 after every kernel-side change; compile-check on older headers too.
- Never log kernel addresses; keep device root-only. Do not weaken ring write-protection.
- Add tests with every feature; extend `test_extractor.c` or add per-module test programs.
- Suggested layout for Phase 2 (optional): `common/` (kim_uapi.h, ingestion lib), `module1_extractor/`,
  `module2_dispatcher/`, `module3_verifier/`, `module4_enforcer/`, `docs/` (Progress report PDF),
  `.gitignore` containing `*.ko *.o *.mod* Module.symvers modules.order .*.cmd MOK.priv MOK.der`.

---------------------------------------------------------------------------
## 10. Suggested first tasks for Claude Code (in order)

1. Read all six Module 1 files, build, run `sudo make test` and confirm 23/23 on this machine.
2. Soak/churn tests for Module 1: 10-minute run with `scan_interval_ms=0`, plus a loop of
   `modprobe`/`rmmod` of a small module while scanning; confirm no Oops, no `bad_tail`, no leaks.
   -> `sudo ./soak_churn.sh` (files/): A 600 s full-stack soak + `dummy` churn, B rmmod while busy
   must be refused, C fast_copy=1 + worker_cpu=6 must give the same modal digest; checks dmesg for
   BUG/Oops/WARNING/stalls, kernel counters, CRIT/EMERG, Slab/VmallocUsed. **Done 2026-11-02: PASS** (§4.6).
3. ~~Implement Module 2 topology + power detection with unit tests (mock sysfs trees).~~ Done.
4. ~~Build the reader -> worker -> completion-tracker pipeline using the `kim_chunk` API
   with a trivial xor sink; verify slot-reuse safety with injected delays.~~ Done on a mock
   ring and on the real device (§6).
5. ~~Implement Module 3 tag function (scalar reference first, then AVX2/VAES/PCLMUL),
   known-answer tests, then plug into the pipeline.~~ Done (AES-GCM-SIV, §7), verified on device.
6. ~~Baseline learn/verify + patch-site design~~ Built ("learn, re-verify, explain", §7); live run done 2026-10-29 (27/27 detected, 0 unexplained after fix).
7. ~~Module 4 dry-run alerting (auditd + syslog), then gated enforcement actions.~~ Done (§7), live dry-run validated.
8. Re-sweep alpha/beta_P/beta_E on the real streamed workload and update defaults.
   -> `module2_dispatcher/sweep.sh` (root; run once on AC, once on battery; ~25 min each, QUICK=1
   ~5 min): alpha {0,.5,.65,.75,.8,.9,1} x beta_P {64..512} x beta_E {16,32}, 3 reps, shuffled,
   fixed key, -L 0, CSV per run from kd_daemon's new `result:` line (whole-run RAPL energy).
   `sweep_analyze.py *.csv` -> Markdown: best configs, reference points (E-only, P-only, default,
   best), marginal effects (beta_P over alpha>0, beta_E over alpha<1), Pearson r, noise (CV).
   **Done 2026-11-02/03** (§6): defaults changed to alpha 1.0 / 256K / 16K. sweep_analyze.py now
   removes linear drift over run order (`--raw` to disable).
9. **Next (user decision 2026-11-08, to start later):** final comparisons on this machine, then
   .deb packaging (kim-dkms + kim-daemon, monitor-only default; Ubuntu 26.04 + Intel 12th gen+).
   **Started 2026-11-09.** Final comparison: `sudo ./final_bench.sh` once on battery, once on AC
   (5 stages x 5 reps x 10 s: 1-copy, 2-direct, 3-own-core, 4-final, 5-final-verify; all rebuilt
   from today's binaries with module params / daemon flags; digest must be identical), then
   `python3 -I plots/plot_final.py . plots` -> final_1_stages.png, final_2_gain_over_copy.png,
   final_3_kernel_thread_time.png, final_summary.csv/.md. Packaging: `packaging/build_debs.sh`
   (no root) -> packaging/dist/kim-dkms_1.0.0_all.deb (/usr/src/kim-1.0.0 + Kbuild + dkms.conf,
   postinst dkms add/build/install; Ubuntu DKMS signs with /var/lib/shim-signed/mok/MOK.*) and
   kim-daemon_1.0.0_amd64.deb (/usr/sbin/kimd = kd_daemon, kim.service: ExecStartPre modprobe,
   ExecStopPost modprobe -r, hardened, StartLimitBurst 5/300 s; /etc/kim/kimd.conf conffile
   KIMD_OPTS="-q -L 3 -i 1000" monitor-only, KIM_MODULE_OPTS). Both preinst refuse non-26.04 and
   non-12th-gen+ (KIM_ALLOW_UNSUPPORTED=1 overrides OS/model, never missing AVX2/VAES/VPCLMULQDQ;
   tested with fake cpuinfo/os-release). kd_daemon stdout is now line-buffered (journald).
   **Final comparison 2026-11-09 (7.0.0-42, 5 x 10 s per stage, shuffled; plots/final_*.png):**

   | stage | Bat GB/s | Bat W | Bat GB/J | AC GB/s | AC W | AC GB/J |
   |---|---|---|---|---|---|---|
   | 1-copy | 6.53 | 14.3 | 0.456 | 8.70 | 33.2 | 0.262 |
   | 2-direct | 11.73 | 15.6 | 0.755 | 15.32 | 36.3 | 0.422 |
   | 3-own-core | 12.54 | 16.1 | 0.778 | 16.53 | 37.3 | 0.443 |
   | **4-final** | **13.27** | 16.6 | **0.798** | **17.10** | 38.9 | **0.440** |
   | 5-final-verify | 13.36 | 16.5 | 0.808 | 17.20 | 38.3 | 0.449 |

   Final vs copy: battery +103% GB/s / +75% GB/J, AC +97% / +68%. Baseline checking costs nothing
   measurable (stage 5 = stage 4). Digest 2b2a85bc9f20da65 identical in all 50 runs. Stage 5's one
   event per run is the LEARNED record (no changes seen). On AC stage 4 adds throughput but not
   GB/J over stage 3 (more watts); on battery it adds both.
   **Package install test 2026-11-09: PASS.** apt pulled dkms 3.2.2 + linux-headers-generic
   (7.0.0-43 headers: a kernel update is pending); DKMS built, signed with
   /var/lib/shim-signed/mok/MOK.priv (the user's enrolled key, copied there), installed
   updates/dkms/kernel_extractor.ko.zst; kim.service started under the hardened unit, kthread pinned
   to CPU 6, baseline learned in ~1 s (378 segments, 2808 frames, 365703 symbols), syslog + auditd
   sinks up, 60 s summaries; `apt remove` stopped the service and unloaded the module. Service CPU
   4.0 s in its first 34 s (start-up + learning + kallsyms load); steady-state cost not measured yet.
   Idle E workers are still spawned (alpha 1.0) and wake every 10 ms: worth not starting them.
   Zero-copy module memory (the remaining ~1.4-1.8x lever, §4.8 round 2) was offered and not taken
   up for now; revisit only if the user asks.
