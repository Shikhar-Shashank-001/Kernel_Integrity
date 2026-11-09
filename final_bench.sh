#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# final_bench.sh - the optimisation history on one machine, one session.
# Every stage is rebuilt from today's binaries with module parameters and
# daemon flags, interleaved and shuffled, same fixed key, so the differences
# are the optimisations and not the day. Run once on battery, once on AC.
# Root. ~REPS * 5 * (SECS + 3) s (default ~5.5 min).
#
#   1-copy          original pipeline: every byte copied by the kernel thread
#                   (direct_text=0, 1024-slot ring, 4 P workers, kthread unpinned)
#   2-direct        kernel text hashed in place through the read-only window
#   3-own-core      + kthread pinned alone on a P core (daemon -K), 3 workers
#   4-final         + 2048-slot ring (module default): today's defaults
#   5-final-verify  4-final with the baseline learning and checking (-L 3): the
#                   full monitor, i.e. what a user actually runs
#
# All stages must produce the same modal epoch digest (bit-exact tags).
# Output: final_bench_<ac|battery>.csv + final_runs_<power>/ + final_bench_<power>.log
# Plot both with:  python3 -I plots/plot_final.py . plots
#
# Usage (root, from File_Extractor/files/):  sudo ./final_bench.sh
# Env: REPS (5) SECS (10)
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
KO=$HERE/kernel_extractor.ko
DAEMON=$HERE/module2_dispatcher/kd_daemon
REPS=${REPS:-5}
SECS=${SECS:-10}
KEY=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f   # test-only

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
[ -x "$DAEMON" ] || { echo "build first: make && make -C module2_dispatcher"; exit 1; }
modinfo -p "$KO" | grep -q '^ring_slots:' || { echo "rebuild + re-sign kernel_extractor.ko"; exit 1; }

power=$(cat /sys/class/power_supply/*/online 2>/dev/null | grep -q 1 && echo ac || echo battery)
OUT=$HERE/final_bench_$power.log
CSV=$HERE/final_bench_$power.csv
RUNS=$HERE/final_runs_$power

cleanup() { lsmod | grep -qw kernel_extractor && rmmod kernel_extractor 2>/dev/null; }
trap cleanup EXIT
log() { echo "$*" | tee -a "$OUT"; }
num() { grep -o "$2" "$1" | head -1 | grep -o '[0-9.]*' | head -1; }
modal_digest() {
	grep -E '^epoch ' "$1" | awk '{print $NF}' | sort | uniq -c | sort -rn | head -1 | awk '{print $2}'
}

: > "$OUT"
rm -rf "$RUNS"
mkdir -p "$RUNS"
log "== final_bench $(date) | kernel $(uname -r) | $power | $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ //') | $REPS x ${SECS}s"
lsmod | grep -qw kernel_extractor && rmmod kernel_extractor

# name | insmod params | daemon args
CONFIGS=(
	"1-copy|direct_text=0 ring_slots=1024|-K -1 -L 0"
	"2-direct|ring_slots=1024|-K -1 -L 0"
	"3-own-core|ring_slots=1024|-L 0"
	"4-final||-L 0"
	"5-final-verify||-L 3"
)
list=$(for r in $(seq "$REPS"); do
	for i in "${!CONFIGS[@]}"; do echo "$i $r"; done | shuf
done)

echo "config,rep,power,gbps,watts,gbpj,epochs,digest,k_cpu,k_sleep,copy_pct,direct_pct,copy_gbs,p_busy,ring_full_per_s,events" > "$CSV"
n=0
while read -r i r; do
	IFS='|' read -r name kp dargs <<< "${CONFIGS[$i]}"
	n=$((n + 1))
	f=$RUNS/$(printf %02d "$n")_${name}_$r.log
	# shellcheck disable=SC2086
	insmod "$KO" scan_interval_ms=0 $kp || { log "insmod failed ($name: $kp)"; exit 1; }
	# shellcheck disable=SC2086
	"$DAEMON" -i 0 -k $KEY -S -U -t "$SECS" $dargs > "$f" 2>&1
	rmmod kernel_extractor
	res=$(grep '^result: ' "$f")
	kv() { echo "$res" | tr ' ' '\n' | sed -n "s/^$1=//p"; }
	full=$(num "$f" 'ring_full [0-9]*')
	secs=$(kv seconds)
	fps=$(python3 -c "print(round(${full:-0} / ${secs:-1}))")
	ev=$(grep -c '^\[EVENT\]' "$f")
	echo "$name,$r,$power,$(kv gbps),$(kv watts),$(kv gbpj),$(kv epochs),$(modal_digest "$f"),$(num "$f" 'on CPU [0-9]*'),$(num "$f" 'asleep [0-9]*'),$(num "$f" 'copied [0-9]*'),$(num "$f" 'direct [0-9]*% of wall'),$(num "$f" '([0-9.]* GB/s while copying'),$(num "$f" 'workers busy P [0-9]*'),$fps,$ev" >> "$CSV"
	printf '  %2d %-15s rep %s: %6s GB/s %6s W %7s GB/J digest %s\n' "$n" "$name" "$r" \
		"$(kv gbps)" "$(kv watts)" "$(kv gbpj)" "$(modal_digest "$f")" | tee -a "$OUT"
	sleep 2
done <<< "$list"

log ""
log "== summary (mean ± sd over reps; gain vs 1-copy)"
python3 - "$CSV" <<'EOF' | tee -a "$OUT"
import csv, statistics as st, sys
rows = list(csv.DictReader(open(sys.argv[1])))
f = lambda x: float(x) if x not in ("", None) else float("nan")
order = sorted({r["config"] for r in rows})
sd = lambda v: st.stdev(v) if len(v) > 1 else 0.0
base = None
print(f"{'stage':15} {'GB/s':>13} {'W':>5} {'GB/J':>13} | {'vs copy':>17} | kthread: copy direct asleep")
for c in order:
    rs = [r for r in rows if r["config"] == c]
    g, w, e = ([f(r[k]) for r in rs] for k in ("gbps", "watts", "gbpj"))
    m = lambda k: st.mean(f(r[k]) for r in rs)
    if base is None:
        base = (st.mean(g), st.mean(e))
    print(f"{c:15} {st.mean(g):6.2f} ± {sd(g):4.2f} {st.mean(w):5.1f} {st.mean(e):.3f} ± {sd(e):.3f} | "
          f"{(st.mean(g)/base[0]-1)*100:+5.0f}% {(st.mean(e)/base[1]-1)*100:+5.0f}% GB/J | "
          f"{m('copy_pct'):5.0f}% {m('direct_pct'):5.0f}% {m('k_sleep'):5.0f}%")
ds = {r["digest"] for r in rows}
print(f"digests: {len(ds)} distinct -> {'IDENTICAL across all stages' if len(ds) == 1 else 'DIFFER: ' + str(sorted(ds))}")
ev = [int(r["events"]) for r in rows if r["config"] == "5-final-verify"]
print(f"5-final-verify events per run: {ev} (expect a few patch-like static-key flips, no CRIT)")
EOF
log ""
log "CSV: $CSV   per-run logs: $RUNS/"
