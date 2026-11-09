#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# sweep.sh - alpha / beta_P / beta_E sweep on the real streamed workload
# (kernel memory -> ring -> hybrid pipeline -> AES-GCM-SIV tags), measuring
# GB/s, package watts (RAPL) and GB/J per configuration. Run once plugged in
# and once on battery, then analyse with sweep_analyze.py.
#
# Configurations run REPS times in random order (so thermal drift and other
# slow changes do not line up with one setting). alpha=0 only varies beta_E,
# alpha=1 only beta_P.
#
# Usage (root, from module2_dispatcher/):
#   sudo ./sweep.sh              # full: ~23 min
#   sudo QUICK=1 ./sweep.sh      # 1 rep, 5 s runs: ~5 min
# Env: ALPHAS BETA_P BETA_E (KiB) REPS SECS COOLDOWN CSV
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
DAEMON=$HERE/kd_daemon
KO=$HERE/../kernel_extractor.ko
KEY=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f   # test-only

ALPHAS=${ALPHAS:-"0 0.5 0.65 0.75 0.8 0.9 1"}
BETA_P=${BETA_P:-"64 128 256 512"}
BETA_E=${BETA_E:-"16 32"}
if [ "${QUICK:-0}" = 1 ]; then REPS=${REPS:-1}; SECS=${SECS:-5}; else REPS=${REPS:-3}; SECS=${SECS:-8}; fi
COOLDOWN=${COOLDOWN:-2}

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
[ -x "$DAEMON" ] || { echo "build first: make"; exit 1; }

# power state from sysfs (same rule as kd_power.c, simplified)
power=bat
for s in /sys/class/power_supply/*; do
	t=$(cat "$s/type" 2>/dev/null)
	if { [ "$t" = Mains ] || [ "${t#USB}" != "$t" ]; } && [ "$(cat "$s/online" 2>/dev/null)" = 1 ]; then
		power=ac
	fi
done
CSV=${CSV:-$HERE/sweep_${power}_$(date +%Y%m%d_%H%M).csv}

we_loaded=0
if [ ! -e /dev/kernel_integrity_buf ]; then
	insmod "$KO" scan_interval_ms=0 || exit 1
	we_loaded=1
fi
trap '[ $we_loaded = 1 ] && rmmod kernel_extractor' EXIT

# configuration list (one line per run), shuffled
list=$(mktemp)
for a in $ALPHAS; do
	for bp in $BETA_P; do
		for be in $BETA_E; do
			[ "$a" = 0 ] && [ "$bp" != "${BETA_P%% *}" ] && continue
			[ "$a" = 1 ] && [ "$be" != "${BETA_E%% *}" ] && continue
			for r in $(seq "$REPS"); do echo "$a $bp $be $r"; done
		done
	done
done | shuf > "$list"
n=$(wc -l < "$list")
echo "power=$power | $n runs x ${SECS}s (+${COOLDOWN}s cooldown) ~ $(( n * (SECS + COOLDOWN + 1) / 60 )) min | -> $CSV"

echo "order,power,alpha,beta_p_kib,beta_e_kib,rep,workers_p,workers_e,epochs,bytes,seconds,gbps,joules,watts,gbpj" > "$CSV"
run() {   # run <alpha> <beta_p> <beta_e> -> prints the result: line
	"$DAEMON" -q -i 0 -L 0 -k "$KEY" -S -U -f "$power" -a "$1" -P "$2" -E "$3" -t "$SECS" 2>/dev/null |
		grep '^result: '
}

run 0.8 256 16 > /dev/null          # warm-up (discarded)
i=0
start=$SECONDS
while read -r a bp be r; do
	i=$((i + 1))
	line=$(run "$a" "$bp" "$be")
	if [ -z "$line" ]; then
		echo "  run $i failed (alpha=$a bp=$bp be=$be)"
		continue
	fi
	kv() { echo "$line" | tr ' ' '\n' | sed -n "s/^$1=//p"; }
	echo "$i,$power,$a,$bp,$be,$r,$(kv workers_p),$(kv workers_e),$(kv epochs),$(kv bytes),$(kv seconds),$(kv gbps),$(kv joules),$(kv watts),$(kv gbpj)" >> "$CSV"
	eta=$(( (SECONDS - start) * (n - i) / i ))
	printf '\r  %3d/%d  alpha=%-4s bP=%-3s bE=%-2s  %s GB/s %s W %s GB/J   ETA %dm%02ds ' \
		"$i" "$n" "$a" "$bp" "$be" "$(kv gbps)" "$(kv watts)" "$(kv gbpj)" $((eta / 60)) $((eta % 60))
	sleep "$COOLDOWN"
done < "$list"
rm -f "$list"
echo
echo "done: $CSV"
echo "analyse: python3 $HERE/sweep_analyze.py $CSV [other.csv]"
