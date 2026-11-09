#!/usr/bin/env python3
"""final_bench (battery + AC, one session): summary table + three seaborn figures.

usage: python3 -I plot_final.py <dir with final_bench_ac.csv / final_bench_battery.csv> <outdir>
"""
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

src, out = Path(sys.argv[1]), Path(sys.argv[2])
out.mkdir(parents=True, exist_ok=True)

SURFACE, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"
POWER = {"Battery": "#eb6834", "AC": "#2a78d6"}      # same colours as the 11-07 figures
STAGE = {
    "1-copy": "1 copy\neverything",
    "2-direct": "2 text read\nin place",
    "3-own-core": "3 thread on\nown core",
    "4-final": "4 + 2048 ring\n(final)",
    "5-final-verify": "5 final +\nverifying",
}
ORDER = list(STAGE.values())
TIME = {"copying frames": "#2a78d6", "kernel text (no copy)": "#eb6834",
        "asleep (ring full)": "#1baf7a", "other": "#c3c2b7"}

frames = []
for p, name in (("Battery", "final_bench_battery.csv"), ("AC", "final_bench_ac.csv")):
    f = src / name
    if f.exists():
        frames.append(pd.read_csv(f).assign(power=p))
if not frames:
    sys.exit(f"no final_bench_*.csv in {src}")
df = pd.concat(frames, ignore_index=True)
df["stage"] = df["config"].map(STAGE)
powers = [p for p in POWER if p in set(df.power)]

# ------------------------------------------------------------------ table
num = ["gbps", "watts", "gbpj", "copy_pct", "direct_pct", "k_sleep", "p_busy"]
t = df.groupby(["power", "config"])[num].agg(["mean", "std"])
t.columns = [f"{a}_{b}" for a, b in t.columns]
t = t.reset_index()
for k in ("gbps", "gbpj", "watts"):
    base = t[t.config == "1-copy"].set_index("power")[f"{k}_mean"]
    t[f"{k}_vs_copy"] = t.apply(lambda r: r[f"{k}_mean"] / base[r.power] - 1, axis=1)
t["power"] = pd.Categorical(t["power"], powers)
t = t.sort_values(["power", "config"])
t.to_csv(out / "final_summary.csv", index=False)

lines = ["| power | stage | GB/s | W | GB/J | GB/s vs copy | GB/J vs copy |",
         "|---|---|---|---|---|---|---|"]
for _, r in t.iterrows():
    lines.append(f"| {r.power} | {r.config} | {r.gbps_mean:.2f} ± {r.gbps_std:.2f} | {r.watts_mean:.1f} | "
                 f"{r.gbpj_mean:.3f} ± {r.gbpj_std:.3f} | {r.gbps_vs_copy * 100:+.0f}% | "
                 f"{r.gbpj_vs_copy * 100:+.0f}% |")
(out / "final_summary.md").write_text("\n".join(lines) + "\n")
print("\n".join(lines))
for p in powers:
    d = df[df.power == p]
    print(f"{p}: digests {d.digest.nunique()} distinct over {len(d)} runs "
          f"({'bit-exact' if d.digest.nunique() == 1 else 'DIFFER'}); "
          f"GB/s CV per stage %: "
          + ", ".join(f"{c} {g.gbps.std() / g.gbps.mean() * 100:.1f}" for c, g in d.groupby("config")))

sns.set_theme(style="whitegrid", rc={
    "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "axes.edgecolor": GRID,
    "grid.color": GRID, "grid.linewidth": 0.8, "text.color": INK, "axes.labelcolor": INK2,
    "xtick.color": INK2, "ytick.color": INK2, "axes.titleweight": "bold", "font.size": 10})


def legend_below(fig, handles, labels, n):
    fig.legend(handles, labels, loc="lower center", ncol=n, frameon=False, bbox_to_anchor=(0.5, -0.01))


# ------------------------------------------------------------------ fig 1: the three measures per stage
fig, axes = plt.subplots(1, 3, figsize=(17, 5.2))
for ax, (col, title, fmt) in zip(axes, [("gbps", "Throughput (GB/s, higher is better)", "%.1f"),
                                        ("gbpj", "Efficiency (GB per joule, higher is better)", "%.3f"),
                                        ("watts", "Package power (W)", "%.1f")]):
    sns.barplot(data=df, x="stage", y=col, hue="power", order=ORDER, hue_order=powers,
                palette=POWER, errorbar=None, ax=ax, width=0.72, edgecolor=SURFACE, linewidth=2,
                saturation=1)
    sns.stripplot(data=df, x="stage", y=col, hue="power", order=ORDER, hue_order=powers,
                  dodge=True, palette={p: INK for p in powers}, size=3, alpha=0.5, jitter=0.08,
                  ax=ax, legend=False)
    top = df.groupby(["stage", "power"])[col].agg(["mean", "max"])
    w = 0.72 / len(powers)
    for i, s in enumerate(ORDER):
        for j, p in enumerate(powers):
            if (s, p) in top.index:
                r = top.loc[(s, p)]
                ax.annotate(fmt % r["mean"], (i + (j - (len(powers) - 1) / 2) * w, r["max"]),
                            xytext=(0, 4), textcoords="offset points", ha="center", fontsize=8, color=INK)
    ax.set_title(title, loc="left")
    ax.set_xlabel("")
    ax.set_ylabel("")
    ax.tick_params(axis="x", labelsize=8)
    ax.margins(y=0.12)
    ax.grid(axis="x", visible=False)
    h, l = ax.get_legend_handles_labels()
    ax.get_legend().remove()
legend_below(fig, h[:len(powers)], l[:len(powers)], len(powers))
fig.suptitle("Kernel integrity monitor: each optimisation stage, same machine, same session "
             "(i5-12450H, bars = mean, dots = runs)", x=0.01, ha="left", fontweight="bold")
fig.tight_layout(rect=(0, 0.05, 1, 0.97))
fig.savefig(out / "final_1_stages.png", dpi=150, bbox_inches="tight")
plt.close(fig)

# ------------------------------------------------------------------ fig 2: cumulative gain over stage 1
# one panel per measure (no dual axis), lines coloured by power state as in fig 1
fig, axes = plt.subplots(1, 2, figsize=(14, 4.8), sharey=True)
for ax, (col, title) in zip(axes, (("gbps_vs_copy", "Throughput gain over stage 1 (%)"),
                                   ("gbpj_vs_copy", "Efficiency gain over stage 1 (%)"))):
    for p in powers:
        d = t[t.power == p].assign(stage=lambda x: x.config.map(STAGE)).set_index("stage").reindex(ORDER)
        y = d[col] * 100
        ax.plot(range(len(d)), y, color=POWER[p], lw=2, marker="o", ms=8, mec=SURFACE, mew=2, label=p)
        i = ORDER.index(STAGE["4-final"])
        above = p == max(powers, key=lambda q: t[(t.power == q) & (t.config == "4-final")][col].iloc[0])
        ax.annotate(f"{p} {y.iloc[i]:+.0f}%", (i, y.iloc[i]), xytext=(0, 10 if above else -18),
                    textcoords="offset points", ha="center", fontsize=9, color=INK)
    ax.axhline(0, color=INK2, lw=0.8)
    ax.set_xticks(range(len(ORDER)), ORDER, fontsize=8)
    ax.set_title(title, loc="left")
    ax.grid(axis="x", visible=False)
    ax.margins(x=0.06, y=0.15)
h, l = axes[0].get_legend_handles_labels()
legend_below(fig, h, l, len(powers))
fig.tight_layout(rect=(0, 0.06, 1, 1))
fig.savefig(out / "final_2_gain_over_copy.png", dpi=150, bbox_inches="tight")
plt.close(fig)

# ------------------------------------------------------------------ fig 3: where the kernel thread's time goes
k = t.copy()
k["copying frames"] = k["copy_pct_mean"]
k["kernel text (no copy)"] = k["direct_pct_mean"]
k["asleep (ring full)"] = k["k_sleep_mean"]
k["other"] = (100 - k[["copying frames", "kernel text (no copy)", "asleep (ring full)"]].sum(axis=1)).clip(lower=0)
k = k[k.config != "5-final-verify"]          # same kernel side as stage 4
fig, axes = plt.subplots(1, len(powers), figsize=(7.2 * len(powers), 3.6), sharex=True, squeeze=False)
for ax, p in zip(axes[0], powers):
    d = k[k.power == p].assign(stage=lambda x: x.config.map(STAGE)).set_index("stage").reindex(ORDER[:4])
    left = pd.Series(0.0, index=d.index)
    for cat, colr in TIME.items():
        v = d[cat].fillna(0)
        ax.barh(range(len(d)), v, left=left, color=colr, edgecolor=SURFACE, linewidth=2, height=0.62,
                label=cat)
        for i, (val, l0) in enumerate(zip(v, left)):
            if val >= 6:
                ax.text(l0 + val / 2, i, f"{val:.0f}%", ha="center", va="center", fontsize=8,
                        color=INK if cat != "copying frames" else SURFACE)
        left += v
    ax.set_yticks(range(len(d)), d.index, fontsize=8)
    ax.invert_yaxis()
    ax.set_xlim(0, 100)
    ax.set_title(f"{p}: kernel copy thread, share of wall time", loc="left")
    ax.grid(axis="y", visible=False)
h, l = axes[0][0].get_legend_handles_labels()
legend_below(fig, h, l, len(TIME))
fig.tight_layout(rect=(0, 0.08, 1, 1))
fig.savefig(out / "final_3_kernel_thread_time.png", dpi=150, bbox_inches="tight")
plt.close(fig)
print(f"figures + final_summary.csv/.md in {out}")
