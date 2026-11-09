#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# direct_bench.sh - validate and measure direct_text (hash live kernel text
# through a read-only window instead of copying it every scan). Root.
#
#   1  sign kernel_extractor.ko (Secure Boot) if MOK.priv/MOK.der are here
#   2  Module 1 tests with direct_text=1 (T2 window hardening, T7 DIRECT/kcore)
#   3  A/B: copy (direct_text=0) vs direct, REPS interleaved runs of SECS each,
#      same fixed key: modal epoch digests must be identical, GB/s and GB/J
#      compared; plus direct with a P+E hybrid (alpha 0.8) and E-only, since
#      the bottleneck may move from the kernel copy to the workers
#   4  live_check.sh (static key / module / ftrace) on the direct path
#
# Usage (root, from File_Extractor/files/):  sudo ./direct_bench.sh
# Env: REPS (3) SECS (10) SKIP_LIVE=1
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
KO=$HERE/kernel_extractor.ko
DAEMON=$HERE/module2_dispatcher/kd_daemon
OUT=${OUT:-$HERE/direct_bench.log}
REPS=${REPS:-3}
SECS=${SECS:-10}
KEY=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f   # test-only
TMP=$(mktemp -d)

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
[ -x "$DAEMON" ] && [ -x "$HERE/test_extractor" ] || { echo "build first: make && make -C module2_dispatcher"; exit 1; }

cleanup() {
	lsmod | grep -qw kernel_extractor && rmmod kernel_extractor 2>/dev/null
	rm -rf "$TMP"
}
trap cleanup EXIT

log() { echo "$*" | tee -a "$OUT"; }
modal_digest() {
	grep -E '^epoch ' "$1" | awk '{print $NF}' | sort | uniq -c | sort -rn | head -1 | awk '{print $2}'
}
kv() { echo "$1" | tr ' ' '\n' | sed -n "s/^$2=//p"; }

: > "$OUT"
log "== direct_bench $(date) | kernel $(uname -r) | $REPS x ${SECS}s per config"
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

# ------------------------------------------------------------------ 1
SIGN=/usr/src/linux-headers-$(uname -r)/scripts/sign-file
if [ -f "$HERE/MOK.priv" ] && [ -f "$HERE/MOK.der" ] && [ -x "$SIGN" ]; then
	"$SIGN" sha256 "$HERE/MOK.priv" "$HERE/MOK.der" "$KO" && log "signed $KO"
fi

# ------------------------------------------------------------------ 2
log ""
log "== Module 1 tests (direct_text=1)"
insmod "$KO" direct_text=1 || { log "insmod failed (signed? see dmesg)"; exit 1; }
"$HERE/test_extractor" 2>&1 | tee -a "$OUT" | grep -E '^T|FAIL|SKIP|passed|GB/s'
rmmod kernel_extractor

# ------------------------------------------------------------------ 3
log ""
log "== A/B runs (scan_interval_ms=0, fixed key, no baseline)"
# config: name direct_text daemon-args
CONFIGS=(
	"copy    0 "
	"direct  1 "
	"direct-hybrid-0.8 1 -a 0.8"
	"direct-E-only     1 -a 0"
)
list=$TMP/list
for r in $(seq "$REPS"); do
	for i in "${!CONFIGS[@]}"; do echo "$i $r"; done | shuf
done > "$list"

echo "config,rep,direct_text,gbps,watts,gbpj,epochs,digest,direct_frames,remap_frames" > "$TMP/res.csv"
n=0
while read -r i r; do
	set -- ${CONFIGS[$i]}
	name=$1 dt=$2; shift 2
	n=$((n + 1))
	insmod "$KO" scan_interval_ms=0 direct_text="$dt" || { log "insmod failed"; exit 1; }
	"$DAEMON" -i 0 -L 0 -k $KEY -S -U -t "$SECS" "$@" > "$TMP/run.log" 2>&1
	rmmod kernel_extractor
	res=$(grep '^result: ' "$TMP/run.log")
	kl=$(grep '^kernel (this run)' "$TMP/run.log")
	dg=$(modal_digest "$TMP/run.log")
	df=$(echo "$kl" | sed -n 's/.*| direct \([0-9]*\).*/\1/p')
	rf=$(echo "$kl" | sed -n 's/.*| remap \([0-9]*\).*/\1/p')
	echo "$name,$r,$dt,$(kv "$res" gbps),$(kv "$res" watts),$(kv "$res" gbpj),$(kv "$res" epochs),$dg,$df,$rf" >> "$TMP/res.csv"
	printf '  %2d %-18s rep %s: %s GB/s %s W %s GB/J digest %s direct %s remap %s\n' "$n" "$name" "$r" \
		"$(kv "$res" gbps)" "$(kv "$res" watts)" "$(kv "$res" gbpj)" "$dg" "$df" "$rf" | tee -a "$OUT"
	sleep 2
done < "$list"
cp "$TMP/res.csv" "$HERE/direct_bench.csv"

log ""
log "== summary (mean over reps)"
python3 - "$TMP/res.csv" <<'EOF' | tee -a "$OUT"
import csv, statistics as st, sys
rows = list(csv.DictReader(open(sys.argv[1])))
order = []
for r in rows:
    if r["config"] not in order:
        order.append(r["config"])
def f(x):
    try: return float(x)
    except ValueError: return float("nan")
base = None
print(f"{'config':18} {'GB/s':>12} {'W':>6} {'GB/J':>13}  vs copy")
for c in sorted(order, key=lambda c: (c != "copy", c)):
    rs = [r for r in rows if r["config"] == c]
    g = [f(r["gbps"]) for r in rs]; w = [f(r["watts"]) for r in rs]; e = [f(r["gbpj"]) for r in rs]
    sd = lambda v: st.stdev(v) if len(v) > 1 else 0.0
    m = st.mean(g)
    if c == "copy": base = (m, st.mean(e))
    rel = f"{(m / base[0] - 1) * 100:+.0f}% GB/s, {(st.mean(e) / base[1] - 1) * 100:+.0f}% GB/J" if base else ""
    print(f"{c:18} {m:6.2f} ± {sd(g):4.2f} {st.mean(w):6.1f} {st.mean(e):.3f} ± {sd(e):.3f}  {rel}")
ds = {r["digest"] for r in rows}
print(f"digests: {len(ds)} distinct {sorted(ds)} -> {'IDENTICAL (bit-exact)' if len(ds) == 1 else 'DIFFER'}")
print(f"remap frames total: {sum(int(r['remap_frames'] or 0) for r in rows)}; "
      f"direct frames in copy runs: {sum(int(r['direct_frames'] or 0) for r in rows if r['direct_text'] == '0')}")
EOF

# ------------------------------------------------------------------ 4
if [ "${SKIP_LIVE:-0}" != 1 ]; then
	log ""
	log "== live_check.sh on the direct path (module default direct_text=1)"
	"$HERE/module3_verifier/live_check.sh" 2>&1 | tee -a "$OUT" | tail -25
fi

log ""
log "== kernel log since start"
dmesg_since_mark > "$TMP/dmesg.new"
bad=$(grep -Ei 'BUG|Oops|WARNING:|general protection|Call Trace|soft lockup|rcu.*stall|x86/PAT|kernel_extractor.*(error|fail|warn|not mapped)' "$TMP/dmesg.new")
if [ -z "$bad" ]; then log "  clean ($(wc -l < "$TMP/dmesg.new") new lines)"; else log "$bad"; fi
log "  module loads seen: $(grep -c 'kernel_extractor: ready' "$TMP/dmesg.new") (expected $((n + 2)))"
grep -m1 'direct text' "$TMP/dmesg.new" | sed 's/^/  /' | tee -a "$OUT"
log "full log: $OUT   per-run CSV: $HERE/direct_bench.csv"
