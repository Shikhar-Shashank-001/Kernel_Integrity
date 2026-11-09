#!/usr/bin/env python3
"""direct_bench AC vs battery (2026-11-07, kernel 7.0.0-42): table + seaborn figures."""
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

src, out = Path(sys.argv[1]), Path(sys.argv[2])
out.mkdir(parents=True, exist_ok=True)

SURFACE, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"
POWER = {"AC": "#2a78d6", "Battery": "#eb6834"}          # categorical slots 1, 2
CFG = {"copy": "copy (old path)", "direct": "direct, P-only",
       "direct-hybrid-0.8": "direct, P+E (α 0.8)", "direct-E-only": "direct, E-only"}
ORDER = list(CFG.values())
MARK = dict(zip(ORDER, ["o", "s", "^", "D"]))

df = pd.concat([pd.read_csv(src / "direct_bench_ac.csv").assign(power="AC"),
                pd.read_csv(src / "direct_bench_bat.csv").assign(power="Battery")])
df["config"] = df["config"].map(CFG)

# ---- table
g = df.groupby(["power", "config"])
t = g[["gbps", "watts", "gbpj"]].agg(["mean", "std"])
t.columns = [f"{a}_{b}" for a, b in t.columns]
t = t.reset_index()
base = t[t.config == CFG["copy"]].set_index("power")
t["gbps_vs_copy"] = t.apply(lambda r: r.gbps_mean / base.loc[r.power, "gbps_mean"] - 1, axis=1)
t["gbpj_vs_copy"] = t.apply(lambda r: r.gbpj_mean / base.loc[r.power, "gbpj_mean"] - 1, axis=1)
t["config"] = pd.Categorical(t["config"], ORDER)
t = t.sort_values(["power", "config"])
t.to_csv(out / "direct_bench_summary.csv", index=False)
for _, r in t.iterrows():
    print(f"{r.power:8} {r.config:22} {r.gbps_mean:6.2f}±{r.gbps_std:4.2f} GB/s "
          f"{r.watts_mean:5.1f}±{r.watts_std:3.1f} W {r.gbpj_mean:.3f}±{r.gbpj_std:.3f} GB/J "
          f"{r.gbps_vs_copy*100:+4.0f}% {r.gbpj_vs_copy*100:+4.0f}%")
ac, bat = t.set_index(["power", "config"]).loc["AC"], t.set_index(["power", "config"]).loc["Battery"]
d = CFG["direct"]
print(f"battery/AC for direct P-only: GB/s {bat.loc[d,'gbps_mean']/ac.loc[d,'gbps_mean']:.2f}x, "
      f"W {bat.loc[d,'watts_mean']/ac.loc[d,'watts_mean']:.2f}x, GB/J {bat.loc[d,'gbpj_mean']/ac.loc[d,'gbpj_mean']:.2f}x")
for p, s in (("AC", ac), ("Battery", bat)):
    cv = (s.gbps_std / s.gbps_mean * 100).round(1).to_dict()
    print(p, "GB/s CV %:", cv)

sns.set_theme(style="whitegrid", rc={
    "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "axes.edgecolor": GRID,
    "grid.color": GRID, "grid.linewidth": 0.8, "text.color": INK, "axes.labelcolor": INK2,
    "xtick.color": INK2, "ytick.color": INK2, "axes.titleweight": "bold", "font.size": 10})


def bars(ax, col, title, fmt):
    sns.barplot(data=df, x="config", y=col, hue="power", order=ORDER, hue_order=list(POWER),
                palette=POWER, errorbar=None, ax=ax, width=0.7, edgecolor=SURFACE, linewidth=2,
                saturation=1)
    sns.stripplot(data=df, x="config", y=col, hue="power", order=ORDER, hue_order=list(POWER),
                  dodge=True, palette={"AC": INK, "Battery": INK}, size=3.5, alpha=0.55,
                  jitter=0.08, ax=ax, legend=False)
    top = df.groupby(["config", "power"])[col].agg(["mean", "max"])
    for i, c in enumerate(ORDER):
        for j, p in enumerate(POWER):
            r = top.loc[(c, p)]
            ax.annotate(fmt % r["mean"], (i + (j - 0.5) * 0.35, r["max"]), xytext=(0, 5),
                        textcoords="offset points", ha="center", fontsize=8.5, color=INK)
    ax.set_title(title, loc="left")
    ax.set_xlabel("")
    ax.set_ylabel("")
    ax.tick_params(axis="x", labelrotation=18)
    ax.margins(y=0.12)
    ax.grid(axis="x", visible=False)
    if ax.get_legend():
        ax.get_legend().remove()


# ---- figure 1: the three measures as small multiples (never a dual axis)
fig, axes = plt.subplots(1, 3, figsize=(15, 4.8))
bars(axes[0], "gbps", "Throughput (GB/s)", "%.2f")
bars(axes[1], "watts", "Package power (W)", "%.1f")
bars(axes[2], "gbpj", "Efficiency (GB/J), higher is better", "%.3f")
h = [plt.Rectangle((0, 0), 1, 1, color=c) for c in POWER.values()]
fig.legend(h, list(POWER), loc="upper right", ncol=2, frameon=False)
fig.suptitle("direct_text vs copy, AC and battery: bars = mean, dots = the 3 runs (kernel 7.0.0-42, 2026-11-07)",
             x=0.01, ha="left", fontsize=12, fontweight="bold")
fig.tight_layout(rect=(0, 0, 1, 0.93))
fig.savefig(out / "fig1_throughput_power_efficiency.png", dpi=150)
plt.close(fig)

# ---- figure 2: throughput vs power, one dot per run, iso-efficiency lines
fig, ax = plt.subplots(figsize=(10, 5.6))
w = np.linspace(10, 50, 50)
for e in (0.2, 0.3, 0.4, 0.6, 0.8):
    ax.plot(w, e * w, color=GRID, lw=1.2, zorder=0)
    xe = min(50, 16 / e)                       # where the line leaves the plot
    ax.annotate(f"{e} GB/J", (xe, e * xe), xytext=(-4, -12) if xe == 50 else (4, -12),
                textcoords="offset points", color=INK2, fontsize=8,
                ha="right" if xe == 50 else "left")
for (p, c), s in df.groupby(["power", "config"]):
    ax.scatter(s.watts, s.gbps, color=POWER[p], marker=MARK[c], s=60, edgecolors=SURFACE,
               linewidths=1.5, zorder=3)
m = df.groupby(["power", "config"])[["watts", "gbps"]].mean()
for (p, c), r in m.iterrows():
    if c in (CFG["copy"], CFG["direct"]):
        ax.annotate(c, (r.watts, r.gbps), xytext=(8, -3), textcoords="offset points",
                    fontsize=8.5, color=INK)
ax.set_xlim(10, 50)
ax.set_ylim(4, 16)
ax.set_xlabel("package power (W)")
ax.set_ylabel("throughput (GB/s)")
ax.set_title("Each run: throughput vs power; steeper grey line = more efficient", loc="left")
hp = [plt.Line2D([], [], color=c, marker="o", ls="", ms=8) for c in POWER.values()]
hc = [plt.Line2D([], [], color=INK2, marker=MARK[c], ls="", ms=7) for c in ORDER]
l1 = ax.legend(hp, list(POWER), title="power", loc="upper left", bbox_to_anchor=(1.01, 1),
               frameon=False)
ax.add_artist(l1)
ax.legend(hc, ORDER, title="configuration", loc="upper left", bbox_to_anchor=(1.01, 0.72),
          frameon=False, fontsize=8.5)
fig.tight_layout()
fig.savefig(out / "fig2_throughput_vs_power.png", dpi=150)
plt.close(fig)

# ---- figure 3: gain over the copy path, per power state
gl = t[t.config != CFG["copy"]].melt(id_vars=["power", "config"],
                                       value_vars=["gbps_vs_copy", "gbpj_vs_copy"],
                                       var_name="measure", value_name="gain")
gl["gain"] *= 100
fig, axes = plt.subplots(1, 2, figsize=(11, 4.4), sharey=True)
for ax, (meas, title) in zip(axes, (("gbps_vs_copy", "Throughput gain over copy (%)"),
                                    ("gbpj_vs_copy", "Efficiency gain over copy (%)"))):
    sns.barplot(data=gl[gl.measure == meas], x="config", y="gain", hue="power",
                order=ORDER[1:], hue_order=list(POWER), palette=POWER, ax=ax, width=0.7,
                edgecolor=SURFACE, linewidth=2, saturation=1)
    for c in ax.containers:
        ax.bar_label(c, fmt="+%.0f%%", padding=3, fontsize=8.5, color=INK)
    ax.set_title(title, loc="left")
    ax.set_xlabel("")
    ax.set_ylabel("")
    ax.grid(axis="x", visible=False)
    ax.margins(y=0.12)
    ax.get_legend().remove()
fig.legend(h, list(POWER), loc="upper right", ncol=2, frameon=False)
fig.tight_layout(rect=(0, 0, 1, 0.92))
fig.savefig(out / "fig3_gain_over_copy.png", dpi=150)
plt.close(fig)
print("wrote", *sorted(p.name for p in out.glob("*")))
