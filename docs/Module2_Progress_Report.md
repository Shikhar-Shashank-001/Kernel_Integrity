# Module 2 (Cache-Aware Hybrid Core Dispatcher)

## 1. Objective

Module 1 exports the running kernel's memory (kernel `.text`, `sys_call_table`, and the text and read-only data of every loaded module, about 40.4 MiB per scan) into a 16 MiB shared ring buffer that user space maps read-only. Module 2 reads that ring and spreads the work over the hybrid CPU using the scheduling parameters found in Phase 1:

- **α**: the fraction of each scan's bytes given to the P-cores.
- **β_P / β_E**: the chunk size handed to a P-core (sized for its L2) or an E-core (sized for its L1D).
- **Power awareness**: α and β switch automatically between the *Without Power* (battery) and *With Power* (AC) optima.

Module 2 also has to be **correct under concurrency**. Many worker threads read the ring at the same time, but the kernel reuses a ring slot as soon as user space releases it. A slot released too early would be overwritten while a worker is still checking it, and the verifier would silently check the wrong bytes.

## 2. Architecture

```
  Module 1 (kernel)                         Module 2 (user space)
  kim_extractor kthread                     reader thread (pinned, CPU 7)
     | copies kernel memory                    | cuts the ring into β_P / β_E chunks
     v                                         | assigns α of the bytes to P-cores
  [ 16 MiB ring, 1024 x 16 KiB frames ] ---->  +--> per-worker lock-free queues
     ^                                                  |
     |   kim_consume() strictly in ring order           v
     +--------------------------------------  4 P-core workers (CPU 0,2,4,6)
            (only after every earlier frame     4 E-core workers (CPU 8-11)
             has been processed)                compute one tag per frame
```

- **One reader thread owns the device.** Module 1 allows a single consumer. The reader dispatches chunks to the workers ahead of the release point, then releases slots back to the kernel **strictly in ring order**, only once every frame before that point is finished.
- **Workers** pull chunks from their own queue, compute a per-frame result (currently an AVX2 XOR checksum standing in for the Module 3 tag), and mark the chunk complete.
- **Results come out in ring order** with a copy of each frame's descriptor (segment, offset, flags), ready for Module 4.

## 3. Implementation

| Component | Function |
|---|---|
| `kd_topology.c` | Finds P-cores and E-cores (from `/sys/devices/cpu_core` and `cpu_atom`, with CPUID leaf 0x1A as a fallback), groups hyperthread siblings, reads L1D/L2/L3 sizes |
| `kd_power.c` | Decides With Power / Without Power from `/sys/class/power_supply`, listens for plug/unplug (kernel uevents + polling), reads package energy (Intel RAPL) |
| `kd_dispatcher.c` | The pipeline: reader thread, per-worker lock-free queues, α/β scheduling, in-order completion, per-epoch statistics |
| `kd_daemon.c` | Runs the pipeline on the real device; prints GB/s, Watts, GB/s per Watt and a digest for every scan |
| `test_dispatcher.c` | 62 automated tests that need no root and no kernel module |

Topology detected on the test machine (Intel Core i5-12450H):

| Core type | Logical CPUs | Physical cores | L1D | L2 | Workers placed on |
|---|---|---|---|---|---|
| P-core | 0–7 | 4 (2 threads each) | 48 KiB | 1280 KiB per core | CPU 0, 2, 4, 6 |
| E-core | 8–11 | 4 | 32 KiB | 2 MiB shared by 4 | CPU 8, 9, 10, 11 |

## 4. Key design decisions

1. **α is enforced per scan by bytes, not by a static split.** The total size of a scan is not known in advance, so the reader gives the next chunk to the P-cores whenever their share so far is ≤ α, and to the E-cores otherwise. The error is at most one chunk per scan.
   - *Reason:* this implements D_P = α·S_total without knowing S_total, and it adapts automatically when modules are loaded or unloaded.
2. **One worker per physical P-core; the reader goes on the spare hyperthread.**
   - *Reason:* two hyperthreads on one core share the L2 cache that β_P is sized for.
3. **Power changes take effect at the next scan boundary.**
   - *Reason:* each scan is then measured under a single, known setting, which keeps the statistics clean.
4. **Results are per 16 KiB frame and delivered in ring order.**
   - *Reason:* chunk boundaries depend on how much the kernel had published at that moment, so they are not reproducible. Per-frame results are, which makes the final digest independent of α, β and thread timing. **This constrains Module 3:** its integrity tags must be per frame (or per page), never per chunk.
5. **No work stealing: the split is strict.**
   - *Reason:* the planned α/β re-sweep then measures the effect of α itself, not of a scheduler correcting it.

## 5. Verification (no root required)

The pipeline was tested against a **mock kernel producer** that follows Module 1's ring protocol exactly (same publish and backpressure rules). The content of every frame depends on its (segment, offset, scan number), so any frame read after its slot has been reused is detectable.

| Test group | What is checked | Result |
|---|---|---|
| U1–U6 unit tests | CPU-list and cache-size parsing; topology on mock sysfs trees (hybrid, non-hybrid, offline CPUs); worker placement; power rules (charger, USB-C charging, mouse batteries ignored, desktop); plug/unplug listener; parameter validation | 30 / 30 |
| P1 pipeline (9 configurations) | Digest of every scan equals an independently computed reference; no frame changes under a worker; P share matches α; power switch applies per scan | 30 / 30 |
| Live system check | Real topology and power state are detected | 2 / 2 |
| **Total** | | **62 / 62** |

The nine pipeline configurations cover α from 0 to 1, β from 16 KiB to 512 KiB, 1 to 12 workers, ring sizes of 64 to 1024 slots, random worker delays of up to 300 µs, idle gaps between scans, a module unloaded in the middle of a scan, short final frames, and an AC → battery switch.

Additional checks:

- **Repeatability:** 5 consecutive runs, all 62/62.
- **ThreadSanitizer** (data-race detector): clean on 3 runs. Limitation: it cannot model the memory fences in the thread sleep/wake handshake, so that part was verified by reasoning.
- **Negative control:** a deliberately broken version that releases slots before the workers finish was caught in every configuration where the ring fills up. It produced up to 194 corrupted frames and wrong digests, which shows the tests can actually detect the failure they target.
- **Two defects found and fixed during testing:**
  - a crash from a misaligned memory allocation;
  - the reader could get more than one ring ahead of the release point. It is now capped, and worker sleeps have a 10 ms timeout so a missed wake-up can only add latency, not hang the pipeline.

## 6. Results on the real kernel

Setup: kernel 7.0.0-38-generic, Module 1 in back-to-back mode (`scan_interval_ms=0`), 10-second runs, AVX2 XOR checksum as the per-frame tag. One scan = 2,797 frames = 40.4 MiB (kernel text, `sys_call_table`, 376 module segments).

### 6.1 Correctness

| Check | Result |
|---|---|
| Scan digest across all runs (4 α/β settings, With and Without Power, about 5,000 scans) | **Identical in every run** (`76f1560527167a74`) |
| P-core share of bytes vs α | Exactly α: 80.0 %, 50.0 %, 75.0 %, 50.0 % |
| Balance between workers of the same type | Within 0.2 % |
| Slots released too early (`bad_tail`) / unreadable pages / thread-pinning failures | 0 / 0 / 0 |

### 6.2 Throughput and efficiency

Average throughput is total bytes ÷ 10 s. Efficiency is GB/s per Watt (= GB per Joule), measured over the whole CPU package.

| Power state | α / β_P / β_E | Throughput (GB/s) | Power (W) | Efficiency (GB/s per Watt) |
|---|---|---|---|---|
| With Power | 0.80 / 256 KiB / 16 KiB (default) | 5.73 | 43.5–44.9 | 0.108–0.134 |
| With Power | 0.50 / 64 KiB / 32 KiB | 5.71 | 38.1 | 0.142 |
| Without Power | 0.75 / 128 KiB / 16 KiB (default) | 4.89 | – | 0.262 |
| Without Power | 0.50 / 128 KiB / 16 KiB | 4.92 | – | 0.282 |

Each scan of 40.4 MiB took about 7.3–8.7 ms With Power.

### 6.3 Bottleneck experiment

The Module 1 kernel thread was pinned to CPU 1 with normal priority (`worker_cpu=1 worker_nice=0`). The default α/β for each power state was used.

| Power state | Default placement | Kernel thread pinned | Pinned, one fewer P worker (`-n 3`) |
|---|---|---|---|
| With Power | 5.73 GB/s | 5.89 GB/s (+3 %) | 5.94 GB/s |
| Without Power | 4.89 GB/s | 5.18 GB/s (+6 %) | 5.13 GB/s |

## 7. Analysis

**1. The pipeline is correct on real data.**

- **Results:** the same digest across every α, β and power state, α met exactly, zero errors.
- **Architectural Reason:** per-frame results, delivered in order, decouple the answer from how the work was scheduled. That is the property Module 4 needs in order to compare scans against a baseline.

**2. The kernel-side producer, not the worker pool, limits throughput.**

- **Results:** removing a P worker did not reduce throughput (each remaining P worker simply did more: 15.1 GB vs 11.2 GB). The kernel thread waited for free ring space only about 2,000–3,500 times in 10 s, i.e. under about 7 % of the time.
- **Architectural Reason:** Module 1 copies kernel memory with a single kernel thread (read + write per byte, then read again by the workers). End-to-end throughput (~5.9 GB/s) is below Module 1's standalone 9.15 GB/s, likely for two reasons:
  - the kernel thread shares a physical core with a busy worker (CPUs 1, 3 and 5 are all hyperthread siblings of workers);
  - turbo frequency is lower when all cores are busy than in Module 1's single-thread benchmark.

  At the default rate of one scan per second, a scan uses under 1 % of CPU time, so this does not limit the verifier today.

**3. A lower α was more energy-efficient on this workload.**

- **Results:** α = 0.50 beat the Phase 1 optimum in both power states (0.142 vs ≤ 0.134 With Power; 0.282 vs 0.262 Without Power).
- **Architectural Reason:** with only an XOR checksum per frame, the work is bound by memory copying, so E-cores keep up with P-cores at lower power. Module 3's cryptographic tag adds real computation, which should shift the optimum back toward the P-cores. The defaults are therefore unchanged until α/β are re-swept with the real tag.

**4. These efficiency numbers are not directly comparable with Phase 1.** The Phase 1 optimum (2.30 / 3.43 GB/s per Watt) re-encrypted data already in cache. Here every byte is read from live kernel memory, copied into the ring and read again, and the figure includes the kernel thread's work and whole-package power.

## 8. Findings that affect Modules 3 and 4

1. **System calls no longer go through `sys_call_table`.** Since Linux 6.9, x86-64 dispatches system calls through switch statements compiled into kernel text (`x64_sys_call()`, `ia32_sys_call()`). On this kernel, `ia32_sys_call_table` and `x32_sys_call_table` no longer exist. Overwriting `sys_call_table` therefore no longer hooks system calls; a real hook must modify kernel text, which the kernel-text hash covers. The table check stays as a tripwire.
2. **The monitor does not yet check itself.** Module 1's module enumeration starts after its own entry, so its own code is not hashed. This should be added before enforcement is enabled.
3. **Kernel lockdown already starts at `integrity` on this machine** (Secure Boot is on). Module 4 can only raise it to `confidentiality`, which also blocks kprobes, `/proc/kcore`, perf, tracefs and BPF kernel reads.

## 9. Limitations and next steps

- **Module 3: integrity tag engine.** A per-frame keyed tag (GHASH/GMAC with VPCLMULQDQ, or AES-PMAC), with a scalar reference implementation and NIST known-answer tests, plugged into the Module 2 worker interface.
- **Re-sweep α, β_P, β_E** with the real tag, on streamed kernel memory, With and Without Power.
- **Remaining Module 2 checks:**
  - kernel thread on a fully free core (`-n 3` with `worker_cpu=6`);
  - unplug/replug during a run, to exercise the live power-event path (tests used the polling path).
- **Possible optimisation:** hash static kernel text in place instead of copying it into the ring, removing the producer bottleneck.

---

## Meeting talking points

- **Day 1: dispatcher built and verified.** I built the Module 2 hybrid dispatcher: it detects P/E cores and battery vs AC power, splits each kernel scan between P- and E-cores using α and β, and releases ring slots back to the kernel only in order. It passes 62/62 automated tests, including a deliberately broken version that the tests successfully catch.
- **Day 2: correct on the real kernel.** On the real kernel it produced the same digest across about 5,000 scans for every α/β and power setting, hit α exactly, and had zero errors. It processes a full 40 MiB scan of kernel memory in about 7–8 ms at 4.9–5.9 GB/s.
- **Day 3: bottleneck found, and findings that shape the next modules.** Profiling showed the kernel copy thread, not the worker pool, limits throughput, and on this memory-bound workload a lower α was more energy-efficient. I also found that since Linux 6.9 system calls no longer go through `sys_call_table`, so kernel-text hashing is the real defence. Next is Module 3, the cryptographic per-frame tag.
