#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# profile_bench.sh - find the throughput limit of the full pipeline
# (direct_text, scan_interval_ms=0) by removing one suspect per configuration.
# kd_daemon prints a profile of the reader, the workers and the kernel thread.
# Root. Takes ~REPS * nconfigs * (SECS + 3) s.
#
# SET=producer (default, round 2, needs the module with ring_slots/backoff_us)
#   base           module defaults: 1024 slots, back-off 100-300 us, nofault copy
#   fastcopy       memcpy after the PTE check instead of copy_from_kernel_nofault
#   r256 .. r4096  ring size: small = copy target stays in L3, large = all kernel
#                  text descriptors fit and the thread never stalls on them
#   bo20           back-off 20-60 us
#   r2048-bo20-fc  the three together
#   3P-kcore       3 P workers; kthread pinned alone on the 4th P core (CPU 6)
# SET=kcore (round 3): the daemon's new default (last P core kept free and the
#   kthread pinned there from user space, -K) vs the old 4-worker layout (-K -1),
#   plus ring 2048 / back-off 20 on top (they may matter on AC, where it sleeps)
# SET=pipeline (round 1): default 2P 1P xor knice0 kE-nice0 kE-nice0-xor
#
# Usage (root, from File_Extractor/files/):  sudo ./profile_bench.sh
# Env: SET (producer) REPS (3) SECS (8) KCPU (8: E-core for SET=pipeline)
# Battery gives far less run-to-run noise than AC (turbo/thermal).
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
KO=$HERE/kernel_extractor.ko
DAEMON=$HERE/module2_dispatcher/kd_daemon
SET=${SET:-producer}
OUT=$HERE/profile_bench_$SET.log
RUNS=$HERE/profile_runs_$SET
REPS=${REPS:-3}
SECS=${SECS:-8}
KCPU=${KCPU:-8}
KEY=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f   # test-only

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
[ -x "$DAEMON" ] || { echo "build first: make && make -C module2_dispatcher"; exit 1; }

# name | insmod params | daemon args
case $SET in
producer)
	CONFIGS=(
		"base||-K -1"
		"fastcopy|fast_copy=1|-K -1"
		"r256|ring_slots=256|-K -1"
		"r512|ring_slots=512|-K -1"
		"r2048|ring_slots=2048|-K -1"
		"r4096|ring_slots=4096|-K -1"
		"bo20|backoff_us=20|-K -1"
		"r2048-bo20-fc|ring_slots=2048 backoff_us=20 fast_copy=1|-K -1"
		"3P-kcore|worker_cpu=6 worker_nice=0|-n 3"
	) ;;
kcore)
	CONFIGS=(
		"4P-shared||-K -1"
		"auto||"
		"auto-r2048|ring_slots=2048|"
		"auto-bo20|backoff_us=20|"
	) ;;
pipeline)
	CONFIGS=(
		"default||"
		"2P||-n 2"
		"1P||-n 1"
		"xor||-T xor"
		"knice0|worker_nice=0|"
		"kE-nice0|worker_cpu=$KCPU worker_nice=0|"
		"kE-nice0-xor|worker_cpu=$KCPU worker_nice=0|-T xor"
	) ;;
*) echo "SET must be kcore, producer or pipeline"; exit 1 ;;
esac
if [ "$SET" != pipeline ] && ! modinfo -p "$KO" | grep -q '^ring_slots:'; then
	echo "kernel_extractor.ko has no ring_slots parameter: rebuild (make) and re-sign it"; exit 1
fi

cleanup() { lsmod | grep -qw kernel_extractor && rmmod kernel_extractor 2>/dev/null; }
trap cleanup EXIT

log() { echo "$*" | tee -a "$OUT"; }
: > "$OUT"
rm -rf "$RUNS"
mkdir -p "$RUNS"
power=$(cat /sys/class/power_supply/*/online 2>/dev/null | grep -q 1 && echo AC || echo battery)
log "== profile_bench SET=$SET $(date) | kernel $(uname -r) | $power | $REPS x ${SECS}s per config"
lsmod | grep -qw kernel_extractor && rmmod kernel_extractor

list=$(for r in $(seq "$REPS"); do
	for i in "${!CONFIGS[@]}"; do echo "$i $r"; done | shuf
done)

n=0
while read -r i r; do
	IFS='|' read -r name kp dargs <<< "${CONFIGS[$i]}"
	n=$((n + 1))
	f=$RUNS/$(printf %02d "$n")_${name}_$r.log
	# shellcheck disable=SC2086
	insmod "$KO" scan_interval_ms=0 $kp || { log "insmod failed ($name: $kp)"; exit 1; }
	# shellcheck disable=SC2086
	"$DAEMON" -i 0 -L 0 -k $KEY -S -U -q -t "$SECS" $dargs > "$f" 2>&1
	rmmod kernel_extractor
	printf '  %2d %-14s rep %s: %s %s\n' "$n" "$name" "$r" \
		"$(grep -o 'gbps=[0-9.]*' "$f")" "$(grep -o 'power=[A-Za-z]*' "$f")" | tee -a "$OUT"
	sleep 2
done <<< "$list"

log ""
log "== summary (mean over reps; cv = run-to-run spread of GB/s)"
python3 - "$RUNS" "$SECS" "${CONFIGS[@]}" <<'EOF' | tee -a "$OUT"
import re, statistics as st, sys
from pathlib import Path

order = [c.split("|", 1)[0] for c in sys.argv[3:]]
num = lambda pat, s: float(m.group(1)) if (m := re.search(pat, s)) else float("nan")
secs = float(sys.argv[2])
rows = {}
for p in sorted(Path(sys.argv[1]).glob("*.log")):
    name = p.stem.split("_", 1)[1].rsplit("_", 1)[0]
    s = p.read_text()
    rows.setdefault(name, []).append({
        "gbps": num(r"gbps=([\d.]+)", s), "w": num(r"watts=([-\d.]+)", s),
        "gbpj": num(r"gbpj=([-\d.]+)", s),
        "rd_k": num(r"for the kernel \(ring empty\) (\d+)%", s),
        "wkP": num(r"workers busy P (\d+)%", s),
        "k_cpu": num(r"kernel thread: on CPU (\d+)%", s),
        "k_sleep": num(r"asleep (\d+)%", s),
        "full": num(r"ring_full (\d+)", s),
        "cp": num(r"copied (\d+)% of wall", s),
        "cp_gbs": num(r"\(([\d.]+) GB/s while copying\)", s),
        "dir": num(r"direct (\d+)%\s+of wall", s),
        "ran": (m.group(1).strip() if (m := re.search(r"ran on:(.*)", s)) else "?"),
    })
mean = lambda v: st.mean(v) if v else float("nan")
print(f"{'config':14} {'GB/s':>6} {'cv':>4} {'W':>5} {'GB/J':>6} | {'kthread cpu':>11} {'sleep':>5} "
      f"{'full/s':>6} | {'copy':>4} {'GB/s':>5} {'direct':>6} | {'rd: kern':>8} {'P busy':>6} | ran on (last rep)")
for c in order:
    rs = rows.get(c)
    if not rs:
        continue
    g = lambda k: mean([r[k] for r in rs])
    gb = [r["gbps"] for r in rs]
    cv = 100 * st.stdev(gb) / st.mean(gb) if len(gb) > 1 else float("nan")
    print(f"{c:14} {g('gbps'):6.2f} {cv:3.0f}% {g('w'):5.1f} {g('gbpj'):6.3f} | {g('k_cpu'):10.0f}% "
          f"{g('k_sleep'):4.0f}% {g('full') / secs:6.0f} | {g('cp'):3.0f}% {g('cp_gbs'):5.1f} {g('dir'):5.0f}% | "
          f"{g('rd_k'):7.0f}% {g('wkP'):5.0f}% | {rs[-1]['ran']}")
print(f"\n(first row = reference; copy/direct = share of wall time the kernel thread spent "
      f"emitting copied / direct frames)")
EOF
log ""
log "per-run logs: $RUNS/   summary: $OUT"
