"""E7 figures: sparse KEM ratchet interval K, bandwidth vs healing (strategy 4.4, 6.1).

Usage:
    .venv/bin/python plots/e7_plot.py results/e7-<date>            # reads summary.csv, snapshots.csv
    .venv/bin/python plots/e7_plot.py results/e7-<date> --out figs

Writes PNG (200 dpi) and SVG into <dir>/figures/:

    e7_bandwidth_vs_healing  the key C1 figure: bytes/message (top) and messages-to-heal (bottom),
                             two stacked panels sharing the K axis (no dual y axis), ML-KEM-768
    e7_bytes_vs_K            bytes/message vs K per suite, binary frame and JSON/base64 frame
    e7_heal_vs_K             messages-to-heal vs K per suite (median, min-max range)
    e7_cpu_vs_K              CPU ms/message and KEM operations/message vs K per suite

Style and helpers come from plot.py. Traffic patterns use four fixed categorical slots from that
palette; their adjacent-pair CVD separation is in the 6-8 band, so every series also has its own
marker shape and a direct label at the line end.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from plot import GRID, INK, INK_2, plt, save  # noqa: E402

TRAFFIC_ORDER = ["alternate", "burst5", "poisson", "oneSided90"]
TRAFFIC_COLORS = {"alternate": "#2a78d6", "burst5": "#eb6834", "poisson": "#1baf7a", "oneSided90": "#e87ba4"}
TRAFFIC_MARKERS = {"alternate": "o", "burst5": "s", "poisson": "^", "oneSided90": "D"}
TRAFFIC_LABELS = {
    "alternate": "strict alternation",
    "burst5": "bursts of 5",
    "poisson": "Poisson both ways",
    "oneSided90": "90/10 one-sided",
}
SUITE_LABELS = {"mlkem768": "ML-KEM-768", "xwing": "X-Wing"}
DODGE = {"alternate": 0.92, "burst5": 0.97, "poisson": 1.03, "oneSided90": 1.08}


def k_axis(ax, ks) -> None:
    ax.set_xscale("log")
    ax.set_xticks(ks)
    ax.set_xticklabels([str(k) for k in ks])
    ax.minorticks_off()
    ax.grid(True, which="major", axis="both", color=GRID, linewidth=0.6)


def line(ax, d: pd.DataFrame, y: str, traffic: str, label_end: bool = True, lo: str | None = None,
         hi: str | None = None, hollow: pd.Series | None = None, fmt=None) -> None:
    d = d.sort_values("K")
    c = TRAFFIC_COLORS[traffic]
    # Range whiskers: dodge each series a little along the log K axis so they never sit on top of each other.
    x = d.K * (DODGE[traffic] if (lo and hi) else 1.0)
    if lo and hi:
        ax.errorbar(x, d[y], yerr=np.vstack([d[y] - d[lo], d[hi] - d[y]]).clip(0), fmt="none", ecolor=c,
                    elinewidth=1.1, capsize=2.5, alpha=0.75, zorder=2)
    ax.plot(x, d[y], color=c, linewidth=2, zorder=3, label=TRAFFIC_LABELS[traffic])
    face = [("white" if (hollow is not None and bool(hollow.loc[i])) else c) for i in d.index]
    ax.scatter(x, d[y], s=110, marker=TRAFFIC_MARKERS[traffic], facecolors="none", edgecolors="white",
               linewidths=2, zorder=3.5)  # 2px surface ring where markers overlap
    ax.scatter(x, d[y], s=42, marker=TRAFFIC_MARKERS[traffic], facecolors=face, edgecolors=c, linewidths=1.6,
               zorder=4)
    if label_end:
        last = d.iloc[-1]
        txt = TRAFFIC_LABELS[traffic] + (f"  {fmt(last[y])}" if fmt else "")
        ax.annotate(txt, (float(d.K.iloc[-1]) * 1.08, last[y]), xytext=(10, 0), textcoords="offset points", va="center",
                    fontsize=7.5, color=INK)


def spread_labels(ax) -> None:
    """Nudge the end-of-line labels apart vertically so they never overlap."""
    texts = [t for t in ax.texts if t.get_position() is not None]
    if len(texts) < 2:
        return
    fig = ax.figure
    fig.canvas.draw()
    r = fig.canvas.get_renderer()
    items = sorted(texts, key=lambda t: t.get_window_extent(r).y0)
    for _ in range(30):
        moved = False
        for a, b in zip(items, items[1:]):
            ea, eb = a.get_window_extent(r), b.get_window_extent(r)
            overlap = ea.y1 + 1 - eb.y0
            if overlap > 0:
                for t, dy in ((a, -overlap / 2), (b, overlap / 2)):
                    x, y = t.xyann
                    t.xyann = (x, y + dy * 72 / fig.dpi)
                moved = True
        if not moved:
            break
        fig.canvas.draw()


def fig_combined(s: pd.DataFrame, out: Path, note: str, floor: float | None, suite: str = "mlkem768") -> None:
    d = s[s.suite == suite]
    ks = sorted(d.K.unique())
    fig, (top, bot) = plt.subplots(2, 1, figsize=(8.2, 6.6), sharex=True, gridspec_kw={"hspace": 0.12})
    for t in TRAFFIC_ORDER:
        dd = d[d.traffic == t]
        if dd.empty:
            continue
        line(top, dd, "binary_mean_steady", t, fmt=lambda v: f"{v:,.0f} B")
        line(bot, dd, "heal_median", t, lo="heal_min", hi="heal_max", hollow=dd.heal_censored > 0,
             fmt=lambda v: f"{v:,.0f}")
    if floor:
        top.axhline(floor, color=INK_2, linewidth=0.9, linestyle="--", zorder=1)
        top.annotate(f"no ratchet data on the header: {floor:,.0f} B", (ks[0], floor), xytext=(0, 4),
                     textcoords="offset points", fontsize=7.5, color=INK_2)
    top.set_ylabel("bytes per message\n(binary frame, mean)")
    top.set_ylim(bottom=0)
    bot.set_ylabel("messages to heal\n(median, min–max)")
    bot.set_yscale("symlog", linthresh=10)
    bot.set_ylim(bottom=0)
    for ax in (top, bot):
        k_axis(ax, ks)
    bot.set_xlabel("sparse interval K (messages per sending chain before a KEM ratchet step), log scale")
    fig.suptitle(f"E7 · Bandwidth vs healing, {SUITE_LABELS[suite]} ratchet", x=0.125, ha="left", y=1.02,
                 fontsize=11, fontweight="semibold", color=INK)
    fig.text(0.125, 0.935, "Larger K saves bytes and KEM work but leaves a stolen state useful for longer.\n"
             "Whiskers = min–max over compromise points. Hollow marker = some compromise points had not healed "
             "by message 1,000, so the value is a lower bound.", fontsize=7.8, color=INK_2, ha="left", va="bottom")
    for ax in (top, bot):
        spread_labels(ax)
    save(fig, out, "e7_bandwidth_vs_healing", note)


def fig_bytes(s: pd.DataFrame, out: Path, note: str) -> None:
    suites = [x for x in SUITE_LABELS if x in set(s.suite)]
    ks = sorted(s.K.unique())
    fig, axes = plt.subplots(2, len(suites), figsize=(5.2 * len(suites), 6.4), sharex=True, sharey="row",
                             squeeze=False, gridspec_kw={"hspace": 0.15})
    for j, suite in enumerate(suites):
        d = s[s.suite == suite]
        for i, (col, lab) in enumerate([("binary_mean_steady", "binary frame"), ("json_mean_steady", "JSON/base64 frame")]):
            ax = axes[i][j]
            for t in TRAFFIC_ORDER:
                dd = d[d.traffic == t]
                if not dd.empty:
                    line(ax, dd, col, t, label_end=(j == len(suites) - 1), fmt=lambda v: f"{v:,.0f}")
            k_axis(ax, ks)
            ax.set_ylim(bottom=0)
            if j == 0:
                ax.set_ylabel(f"bytes per message, {lab}\n(mean, init headers excluded)")
            if i == 0:
                ax.set_title(SUITE_LABELS[suite], loc="left")
            spread_labels(ax)
        axes[1][j].set_xlabel("sparse interval K (log)")
    for i, col in enumerate(["binary_mean_steady", "json_mean_steady"]):
        axes[i][0].set_ylim(0, float(s[col].max()) * 1.06)  # rows share y; leave room for the top markers
    h, l = axes[0][0].get_legend_handles_labels()
    fig.legend(h, l, ncol=4, loc="upper left", bbox_to_anchor=(0.06, 1.0))
    fig.suptitle("E7 · Bytes per message vs K (100 B plaintext)", x=0.06, ha="left", y=1.04, fontsize=11,
                 fontweight="semibold", color=INK)
    save(fig, out, "e7_bytes_vs_K", note)


def fig_heal(s: pd.DataFrame, out: Path, note: str) -> None:
    suites = [x for x in SUITE_LABELS if x in set(s.suite)]
    ks = sorted(s.K.unique())
    fig, axes = plt.subplots(1, len(suites), figsize=(5.2 * len(suites), 3.9), sharey=True, squeeze=False)
    for j, suite in enumerate(suites):
        ax = axes[0][j]
        d = s[s.suite == suite]
        for t in TRAFFIC_ORDER:
            dd = d[d.traffic == t]
            if not dd.empty:
                line(ax, dd, "heal_median", t, label_end=(j == len(suites) - 1), lo="heal_min", hi="heal_max",
                     hollow=dd.heal_censored > 0, fmt=lambda v: f"{v:,.0f}")
        k_axis(ax, ks)
        ax.set_yscale("symlog", linthresh=10)
        ax.set_ylim(bottom=0)
        ax.set_title(SUITE_LABELS[suite], loc="left")
        ax.set_xlabel("sparse interval K (log)")
        spread_labels(ax)
    axes[0][0].set_ylabel("messages to heal (median, min–max)")
    h, l = axes[0][0].get_legend_handles_labels()
    fig.legend(h, l, ncol=4, loc="upper left", bbox_to_anchor=(0.06, 1.06))
    fig.suptitle("E7 · Messages from compromise until the passive attacker's last readable message. "
                 "Hollow = not healed by message 1,000 in some runs", x=0.06, ha="left", y=1.12, fontsize=9.5,
                 color=INK_2)
    save(fig, out, "e7_heal_vs_K", note)


def fig_cpu(s: pd.DataFrame, out: Path, note: str) -> None:
    suites = [x for x in SUITE_LABELS if x in set(s.suite)]
    ks = sorted(s.K.unique())
    fig, axes = plt.subplots(2, len(suites), figsize=(5.2 * len(suites), 6.2), sharex=True, sharey="row",
                             squeeze=False, gridspec_kw={"hspace": 0.15})
    for j, suite in enumerate(suites):
        d = s[s.suite == suite]
        for i, (col, lab) in enumerate([("cpu_ms_mean", "CPU ms per message\n(encrypt + decrypt, mean)"),
                                        ("kem_ops_per_msg", "KEM operations per message\n(keygen + encaps + decaps)")]):
            ax = axes[i][j]
            for t in TRAFFIC_ORDER:
                dd = d[d.traffic == t]
                if not dd.empty:
                    line(ax, dd, col, t, label_end=(j == len(suites) - 1),
                         fmt=(lambda v: f"{v:.2f} ms") if i == 0 else (lambda v: f"{v:.2f}"))
            k_axis(ax, ks)
            ax.set_yscale("log")
            if j == 0:
                ax.set_ylabel(lab)
            if i == 0:
                ax.set_title(SUITE_LABELS[suite], loc="left")
            spread_labels(ax)
        axes[1][j].set_xlabel("sparse interval K (log)")
    h, l = axes[0][0].get_legend_handles_labels()
    fig.legend(h, l, ncol=4, loc="upper left", bbox_to_anchor=(0.06, 1.0))
    fig.suptitle("E7 · CPU and KEM work per message vs K (Node, noble; session-store time excluded)", x=0.06,
                 ha="left", y=1.04, fontsize=11, fontweight="semibold", color=INK)
    save(fig, out, "e7_cpu_vs_K", note)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("dir", type=Path)
    ap.add_argument("--out", type=Path, default=None)
    a = ap.parse_args()
    summ = a.dir / "summary.csv"
    if not summ.exists():
        sys.exit(f"{summ} not found: run `npm run e7` first")
    s = pd.read_csv(summ)
    env = json.loads((a.dir / "env.json").read_text()) if (a.dir / "env.json").exists() else {}
    floor = None
    msgs = a.dir / "messages.csv"
    if msgs.exists():
        m = pd.read_csv(msgs, usecols=["suite", "ratchetData", "binaryBytes"])
        bare = m[(m.suite == "mlkem768") & (m.ratchetData == "none")].binaryBytes
        if not bare.empty:
            floor = float(bare.median())
    out = a.out or (a.dir / "figures")
    out.mkdir(parents=True, exist_ok=True)
    note = (f"{a.dir.name} · Node {env.get('node', '?')} · {env.get('messages', '?')} messages per run · "
            f"{len(env.get('snapshotsAt', []))} compromise points per run · seeds: 1 (alternation, bursts), "
            f"{len(env.get('randomSeeds', []))} (Poisson, 90/10) · {'QUICK' if env.get('quick') else 'full grid'}")
    print(f"[e7 plot] {a.dir} -> {out}")
    fig_combined(s, out, note, floor, suite="mlkem768" if (s.suite == "mlkem768").any() else str(s.suite.iloc[0]))
    fig_bytes(s, out, note)
    fig_heal(s, out, note)
    fig_cpu(s, out, note)


if __name__ == "__main__":
    main()
