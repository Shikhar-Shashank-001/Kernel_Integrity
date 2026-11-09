#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# soak_churn.sh - Module 1 robustness test on the real kernel (root).
#
#   A  soak + churn   DURATION s (600) of back-to-back scans through the whole
#                     stack (kd_daemon: SIV tags, baseline, Module 4 dry-run)
#                     while `dummy` is loaded/unloaded every 0.2-1.0 s.
#   B  rmmod busy     rmmod kernel_extractor while the daemon holds the device
#                     must be refused; after the daemon exits it must succeed.
#   C  fast_copy      fast_copy=1 with the kthread pinned (worker_cpu=6) must
#                     give the same scan digest as the default copy path.
#
# PASS needs: no new BUG/Oops/WARNING/stall lines in dmesg, bad_tail 0,
# fault_pages 0, no CRIT/EMERG alert, daemon exits cleanly, B and C as above.
# Save your work first: a kernel bug here could crash the machine.
#
# Usage (root, from File_Extractor/files/):  sudo ./soak_churn.sh
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
KO=$HERE/kernel_extractor.ko
DAEMON=$HERE/module2_dispatcher/kd_daemon
OUT=${OUT:-$HERE/soak_churn.log}
DURATION=${DURATION:-600}
KEY=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f   # test-only
TMP=$(mktemp -d)

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
[ -x "$DAEMON" ] || { echo "build first: make -C module2_dispatcher"; exit 1; }
lsmod | grep -qw dummy && { echo "unload dummy first (modprobe -r dummy)"; exit 1; }

dpid=""
cpid=""
fails=0

cleanup() {
	[ -n "$cpid" ] && kill "$cpid" 2>/dev/null && wait "$cpid" 2>/dev/null
	[ -n "$dpid" ] && kill -INT "$dpid" 2>/dev/null && wait "$dpid" 2>/dev/null
	lsmod | grep -qw dummy && modprobe -r dummy
	lsmod | grep -qw kernel_extractor && rmmod kernel_extractor 2>/dev/null
	rm -rf "$TMP"
}
trap cleanup EXIT

log() { echo "$*" | tee -a "$OUT"; }
check() {   # check <condition-exit-status> <message>
	if [ "$1" = 0 ]; then log "  [PASS] $2"; else log "  [FAIL] $2"; fails=$((fails + 1)); fi
}
mem() { awk '/^(Slab|VmallocUsed):/ {printf "%s %s kB  ", $1, $2}' /proc/meminfo; }
modal_digest() {   # most frequent epoch digest in a daemon log
	grep -E '^epoch ' "$1" | awk '{print $NF}' | sort | uniq -c | sort -rn | head -1 | awk '{print $2}'
}

: > "$OUT"
lsmod | grep -qw kernel_extractor && rmmod kernel_extractor
# Kernel-log window: a unique marker written to /dev/kmsg, then every line
# after it (a line count is useless once the ring buffer is full and rotates).
MARK="kim-test-$$-$(date +%s%N)"
echo "kim: $MARK start" > /dev/kmsg
dmesg_since_mark() {
	if dmesg | grep -q "$MARK"; then
		dmesg | sed -n "/$MARK/,\$p" | tail -n +2
	else
		echo "kim: (marker rotated out of the kernel log; whole buffer checked)"
		dmesg
	fi
}
mem_start=$(mem)
log "== soak_churn $(date) | kernel $(uname -r) | duration ${DURATION}s"
log "memory before: $mem_start"

# ------------------------------------------------------------------ A
log ""
log "== A: soak + churn (${DURATION}s)"
insmod "$KO" scan_interval_ms=0 || { log "insmod failed"; exit 1; }
"$DAEMON" -q -i 0 -L 3 -N dummy -S -U > "$TMP/a.log" 2>&1 &
dpid=$!
sleep 3

(
	n=0
	while :; do
		modprobe dummy && n=$((n + 1))
		sleep "0.$((RANDOM % 8 + 2))"
		modprobe -r dummy
		sleep "0.$((RANDOM % 8 + 2))"
		echo "$n" > "$TMP/churn.count"
	done
) &
cpid=$!

end=$((SECONDS + DURATION))
while [ $SECONDS -lt $end ]; do
	if ! kill -0 "$dpid" 2>/dev/null; then
		log "  daemon died during soak"
		break
	fi
	sleep 10
	printf '\r  %4ds left, churn cycles %s ' $((end - SECONDS)) "$(cat "$TMP/churn.count" 2>/dev/null || echo 0)"
done
echo
kill "$cpid" 2>/dev/null
wait "$cpid" 2>/dev/null
cpid=""
lsmod | grep -qw dummy && modprobe -r dummy
cycles=$(cat "$TMP/churn.count" 2>/dev/null || echo 0)

# ------------------------------------------------------------------ B
log ""
log "== B: rmmod while the device is open"
rmmod kernel_extractor 2> "$TMP/rmmod.err"
rc=$?
check $([ $rc != 0 ] && grep -q "in use" "$TMP/rmmod.err"; echo $?) \
	"rmmod refused while busy: $(tr -d '\n' < "$TMP/rmmod.err")"

kill -INT "$dpid" 2>/dev/null
wait "$dpid"
drc=$?
dpid=""
cat "$TMP/a.log" >> "$OUT"
check $([ $drc = 0 ]; echo $?) "daemon exited cleanly after ${DURATION}s soak (exit $drc)"
check $(grep -q 'result: ' "$TMP/a.log"; echo $?) "daemon reported results: $(grep 'result: ' "$TMP/a.log" | sed 's/.*epochs=\([0-9]*\).*gbps=\([0-9.]*\).*/\1 epochs, \2 GB\/s/')"
check $(grep -Eq 'kernel \(this run\):.*fault_pages 0 \| bad_tail 0' "$TMP/a.log"; echo $?) \
	"kernel counters: $(grep 'kernel (this run)' "$TMP/a.log" | sed 's/^kernel (this run): //')"
check $(grep -Eq '^enforcer: .* crit 0 emerg 0' "$TMP/a.log"; echo $?) \
	"no CRIT/EMERG alerts: $(grep '^enforcer: events' "$TMP/a.log" | sed 's/ | actions.*//')"
log "  churn: $cycles load/unload cycles; NEW_SEGMENT $(grep -c 'NEW_SEGMENT' "$TMP/a.log"), VANISHED $(grep -c 'VANISHED' "$TMP/a.log")"
log "  baseline: $(grep '^baseline: checking' "$TMP/a.log" | sed 's/^baseline: //')"

rmmod kernel_extractor
check $? "rmmod succeeds once the device is closed"

# ------------------------------------------------------------------ C
log ""
log "== C: fast_copy=1 and worker_cpu pinning vs default copy path"
insmod "$KO" scan_interval_ms=0
"$DAEMON" -i 0 -L 0 -k $KEY -S -U -t 15 > "$TMP/c0.log" 2>&1
rmmod kernel_extractor
insmod "$KO" scan_interval_ms=0 fast_copy=1 worker_cpu=6
"$DAEMON" -i 0 -L 0 -k $KEY -S -U -t 15 > "$TMP/c1.log" 2>&1 &
cdp=$!
sleep 5
psr=$(ps -eLo psr,comm | awk '$2 == "kim_extractor" {print $1; exit}')
wait $cdp
rmmod kernel_extractor
d0=$(modal_digest "$TMP/c0.log")
d1=$(modal_digest "$TMP/c1.log")
check $([ -n "$d0" ] && [ "$d0" = "$d1" ]; echo $?) "same modal digest: default $d0 / fast_copy $d1"
check $([ "$psr" = 6 ]; echo $?) "kthread pinned: kim_extractor on CPU ${psr:-?} (expected 6)"
log "  default:   $(grep 'result: ' "$TMP/c0.log" | sed 's/.*gbps=\([0-9.]*\).*/\1 GB\/s/')"
log "  fast_copy: $(grep 'result: ' "$TMP/c1.log" | sed 's/.*gbps=\([0-9.]*\).*/\1 GB\/s/')"

# ------------------------------------------------------------------ kernel log
log ""
log "== kernel log since start"
dmesg_since_mark > "$TMP/dmesg.new"
bad=$(grep -Ei 'BUG|Oops|WARNING:|general protection|Call Trace|soft lockup|hard LOCKUP|rcu.*stall|hung_task|kernel_extractor.*(error|fail)' "$TMP/dmesg.new")
check $([ -z "$bad" ]; echo $?) "no BUG/Oops/WARNING/stall in dmesg ($(wc -l < "$TMP/dmesg.new") new lines)"
[ -n "$bad" ] && log "$bad"
log "  module loads seen: $(grep -c 'kernel_extractor: ready' "$TMP/dmesg.new") (expected 3)"
log "memory before: $mem_start"
log "memory after:  $(mem)"

log ""
if [ $fails = 0 ]; then log "== RESULT: PASS"; else log "== RESULT: FAIL ($fails check(s))"; fi
log "full log: $OUT"
