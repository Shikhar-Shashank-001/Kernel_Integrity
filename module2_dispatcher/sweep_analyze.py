#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Summarise sweep.sh CSV files (one per power state) as Markdown.

For each power state: mean +- stdev per configuration, the best configurations
by efficiency (GB/J = GB/s per Watt) and by throughput, the effect of each
parameter (marginal means and Pearson r with efficiency, as in Phase 1), and
P-only / E-only / default / best comparisons.

Usage: python3 sweep_analyze.py [--raw] sweep_ac_*.csv sweep_bat_*.csv
       (--raw: no drift correction)
"""
import csv
import statistics as st
import sys
from collections import defaultdict

DEFAULT = {"ac": (1.0, 256, 16), "battery": (1.0, 256, 16), "bat": (1.0, 256, 16)}


def load(paths):
    rows = []
    for p in paths:
        with open(p, newline="") as f:
            for r in csv.DictReader(f):
                try:
                    rows.append({
                        "order": int(r["order"]),
                        "power": r["power"], "alpha": float(r["alpha"]),
                        "bp": int(r["beta_p_kib"]), "be": int(r["beta_e_kib"]),
                        "gbps": float(r["gbps"]), "watts": float(r["watts"]),
                        "gbpj": float(r["gbpj"]),
                    })
                except (KeyError, ValueError):
                    continue
    return rows


def ms(v):
    return (st.mean(v), st.stdev(v) if len(v) > 1 else 0.0)


def fmt(v, d=3):
    m, s = ms(v)
    return f"{m:.{d}f} ± {s:.{d}f}"


def pearson(x, y):
    if len(set(x)) < 2 or len(set(y)) < 2:
        return float("nan")
    return st.correlation(x, y)


def detrend(rows):
    """Remove a linear drift over run order (thermal drift on AC). Runs are in
    random order, so the trend is not confounded with any configuration.
    Returns the relative change over the sweep, as a fraction of the mean."""
    if len(rows) < 10:
        return 0.0
    xs = [r["order"] for r in rows]
    out = 0.0
    for key in ("gbpj", "gbps"):
        ys = [r[key] for r in rows]
        slope, icept = st.linear_regression(xs, ys)
        mid = st.mean(xs)
        for r in rows:
            r[key] -= slope * (r["order"] - mid)
        if key == "gbpj":
            out = slope * (max(xs) - min(xs)) / st.mean(ys)
    return out


def report(power, rows, correct):
    print(f"\n## Power state: {power}  ({len(rows)} runs)\n")
    if correct:
        drift = detrend(rows)
        print(f"Linear drift over the sweep removed: GB/J changed {drift * 100:+.1f}% "
              "from first to last run (GB/s and GB/J are drift-corrected below).\n")
    g = defaultdict(list)
    for r in rows:
        g[(r["alpha"], r["bp"], r["be"])].append(r)

    cfgs = []
    for k, rs in g.items():
        cfgs.append((k, rs, st.mean(x["gbpj"] for x in rs)))
    cfgs.sort(key=lambda c: -c[2])

    if all(r["watts"] < 0 for r in rows):
        print("_No energy data (RAPL unreadable): efficiency columns invalid._\n")

    print("### Best configurations by efficiency\n")
    print("| rank | alpha | beta_P KiB | beta_E KiB | n | GB/s | W | GB/J |")
    print("|---|---|---|---|---|---|---|---|")
    for i, (k, rs, _) in enumerate(cfgs[:8], 1):
        print(f"| {i} | {k[0]:.2f} | {k[1]} | {k[2]} | {len(rs)} | {fmt([x['gbps'] for x in rs], 2)} "
              f"| {fmt([x['watts'] for x in rs], 1)} | {fmt([x['gbpj'] for x in rs])} |")

    best_t = max(cfgs, key=lambda c: st.mean(x["gbps"] for x in c[1]))
    print(f"\nHighest throughput: alpha={best_t[0][0]:.2f} beta_P={best_t[0][1]} beta_E={best_t[0][2]}: "
          f"{fmt([x['gbps'] for x in best_t[1]], 2)} GB/s")

    print("\n### Reference points\n")
    print("| configuration | GB/s | W | GB/J |")
    print("|---|---|---|---|")

    def ref(name, sel):
        rs = [r for r in rows if sel(r)]
        if rs:
            print(f"| {name} | {fmt([x['gbps'] for x in rs], 2)} | {fmt([x['watts'] for x in rs], 1)} "
                  f"| {fmt([x['gbpj'] for x in rs])} |")

    ref("E-cores only (alpha 0)", lambda r: r["alpha"] == 0)
    ref("P-cores only (alpha 1)", lambda r: r["alpha"] == 1)
    d = DEFAULT.get(power)
    if d:
        ref(f"current default {d[0]}/{d[1]}K/{d[2]}K",
            lambda r: abs(r["alpha"] - d[0]) < 1e-9 and r["bp"] == d[1] and r["be"] == d[2])
    k = cfgs[0][0]
    ref(f"best {k[0]:.2f}/{k[1]}K/{k[2]}K", lambda r: (r["alpha"], r["bp"], r["be"]) == k)

    print("\n### Effect of each parameter (marginal means over all other settings)\n")
    # a chunk size only matters where that core class gets work: beta_P over
    # alpha > 0, beta_E over alpha < 1 (else the single-class runs bias it)
    scope = {"alpha": rows, "bp": [r for r in rows if r["alpha"] > 0],
             "be": [r for r in rows if r["alpha"] < 1]}
    for key, name in (("alpha", "alpha"), ("bp", "beta_P KiB"), ("be", "beta_E KiB")):
        sub = scope[key]
        vals = sorted({r[key] for r in sub})
        print(f"| {name} | " + " | ".join(str(v) for v in vals) + " |")
        print("|---|" + "---|" * len(vals))
        print("| GB/J | " + " | ".join(f"{st.mean(r['gbpj'] for r in sub if r[key] == v):.3f}"
                                     for v in vals) + " |")
        print("| GB/s | " + " | ".join(f"{st.mean(r['gbps'] for r in sub if r[key] == v):.2f}"
                                     for v in vals) + " |\n")

    hy = [r for r in rows if 0 < r["alpha"] < 1]
    print("Pearson r with efficiency (hybrid runs, 0 < alpha < 1): " + ", ".join(
        f"{n} {pearson([r[k] for r in hy], [r['gbpj'] for r in hy]):+.2f}"
        for k, n in (("alpha", "alpha"), ("bp", "beta_P"), ("be", "beta_E"))))

    cv = [st.stdev([x["gbpj"] for x in rs]) / st.mean([x["gbpj"] for x in rs])
          for _, rs, _ in cfgs if len(rs) > 1 and st.mean([x["gbpj"] for x in rs]) > 0]
    if cv:
        print(f"\nRun-to-run noise: median coefficient of variation of GB/J = {st.median(cv) * 100:.1f}% "
              "(differences smaller than ~2x this are not meaningful).")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    args = [a for a in sys.argv[1:] if a != "--raw"]
    correct = "--raw" not in sys.argv
    rows = load(args)
    if not rows:
        print("no rows")
        return 1
    print("# alpha / beta sweep on streamed kernel memory (AES-GCM-SIV tags)")
    for power in sorted({r["power"] for r in rows}):
        report(power, [r for r in rows if r["power"] == power], correct)
    return 0


if __name__ == "__main__":
    sys.exit(main())
