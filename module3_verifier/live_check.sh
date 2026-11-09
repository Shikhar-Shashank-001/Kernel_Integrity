#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# live_check.sh - exercise the Module-3 baseline on the real kernel with
# legitimate, reversible changes, and check that each one is reported.
#
#   1. static key flip      sysctl kernel.sched_schedstats 1 -> back
#                           expect CHANGED (patch-like, jump label) then REVERTED
#   2. module load/unload   modprobe dummy / modprobe -r dummy
#                           expect NEW_SEGMENT then VANISHED
#   3. ftrace one function  function tracer filtered to vfs_read -> nop
#                           expect CHANGED (patch-like, call at entry) then REVERTED
#
# Everything is restored on exit (also on Ctrl-C).
# Usage (root, from module3_verifier/):  sudo ./live_check.sh
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
DAEMON=$HERE/../module2_dispatcher/kd_daemon
KO=$HERE/../kernel_extractor.ko
LOG=${LOG:-$HERE/live_check.log}
TR=/sys/kernel/tracing
SS=/proc/sys/kernel/sched_schedstats
STEP=${STEP:-3}                 # seconds per state (scans run every 250 ms)

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
[ -x "$DAEMON" ] || { echo "build first: make -C ../module2_dispatcher"; exit 1; }

old_ss=$(cat $SS)
we_loaded_ko=0
we_loaded_dummy=0
pid=""

cleanup() {
	echo "$old_ss" > $SS
	if [ -w $TR/current_tracer ]; then
		echo nop > $TR/current_tracer
		echo > $TR/set_ftrace_filter
	fi
	[ $we_loaded_dummy = 1 ] && lsmod | grep -qw dummy && modprobe -r dummy
	if [ -n "$pid" ]; then
		kill -INT "$pid" 2>/dev/null
		wait "$pid" 2>/dev/null
	fi
	[ $we_loaded_ko = 1 ] && rmmod kernel_extractor
}
trap cleanup EXIT

mark() { echo "=== $*" | tee -a "$LOG"; }

if [ ! -e /dev/kernel_integrity_buf ]; then
	insmod "$KO" scan_interval_ms=250 || exit 1
	we_loaded_ko=1
fi
if lsmod | grep -qw dummy; then
	echo "dummy is already loaded; unload it first (modprobe -r dummy)"
	exit 1
fi

: > "$LOG"
"$DAEMON" -q -i 250 -L 3 -C 1 >> "$LOG" 2>&1 &
pid=$!

for _ in $(seq 60); do
	grep -q "LEARNED" "$LOG" && break
	sleep 0.5
done
grep -q "LEARNED" "$LOG" || { echo "baseline never finished learning; see $LOG"; exit 1; }
mark "baseline learned; quiet period"
sleep "$STEP"

mark "1a static key: sched_schedstats=1"
echo 1 > $SS
sleep "$STEP"
mark "1b static key: sched_schedstats=$old_ss (restored)"
echo "$old_ss" > $SS
sleep "$STEP"

mark "2a modprobe dummy"
modprobe dummy && we_loaded_dummy=1
sleep "$STEP"
mark "2b modprobe -r dummy"
modprobe -r dummy && we_loaded_dummy=0
sleep "$STEP"

if [ -w $TR/current_tracer ]; then
	mark "3a ftrace: function tracer on vfs_read"
	echo vfs_read > $TR/set_ftrace_filter
	echo function > $TR/current_tracer
	sleep "$STEP"
	mark "3b ftrace: tracer off"
	echo nop > $TR/current_tracer
	echo > $TR/set_ftrace_filter
	sleep "$STEP"
else
	mark "3 skipped: tracefs not writable (lockdown=confidentiality?)"
fi

mark "done"
kill -INT "$pid"
wait "$pid"
pid=""

echo
echo "---- event counts per step ----"
awk '/^===/ {step=$0; print; next}
     /^\[EVENT\]/ {split($0, f, " "); n[step " " f[2]]++; printf "    %s %s %s %s\n", f[2], f[5], f[6], ($0 ~ /\(patch-like\)/ ? "patch-like" : ($0 ~ /\(unexplained\)/ ? "UNEXPLAINED" : ""))}' "$LOG" |
	uniq -c | sed 's/^ *1 \(===\)/\1/'
echo
grep '^baseline:' "$LOG" | tail -1
grep '^enforcer:' "$LOG" | tail -1
echo
echo "---- Module 4 (dry-run) ----"
grep -E '^\[KE ' "$LOG" | grep -c 'kim_action=' | sed 's/^/action records (expected 0 for legitimate changes): /'
grep -E '^\[KE .*kim_summary' "$LOG" | tail -3
echo "full log with byte-level explanations: $LOG"
