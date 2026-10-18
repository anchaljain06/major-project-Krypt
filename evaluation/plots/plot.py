"""Figures for the Krypt C3 evaluation (strategy section 6.1).

Usage:
    .venv/bin/python plots/plot.py results/<dir>          # reads summary.csv, e5-bytes.csv
    .venv/bin/python plots/plot.py results/<dir> --out figs

Writes PNG (200 dpi) and SVG for each figure into <dir>/figures/ by default:

    e1e2_ops_by_browser   ops/s by algorithm and browser (noble), log scale, p5-p95 bars
    backend_comparison    noble vs liboqs-wasm vs native WebCrypto (vs node:crypto), per source
    pq_vs_classical       PQ / classical slowdown (noble PQ vs best classical available)
    aes_throughput        AES-256-GCM MB/s vs payload size, log-log
    e5_bytes              stacked bytes per handshake and per message, raw vs binary vs JSON
    e10_node              Node: native vs WASM vs JS for ML-KEM / ML-DSA
    heatmap_device_op     source x operation median latency (noble)

Figures that need data not present (e.g. no Node file) are skipped with a note.
Colors: fixed categorical slots, validated for CVD separation (see README).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from matplotlib.colors import LogNorm  # noqa: E402

# ---------------------------------------------------------------------------
# Palette: one fixed colour per entity, the same in every figure.
# Validated with the dataviz skill's validate_palette.js (light mode, adjacent pairs).
# ---------------------------------------------------------------------------
SOURCE_ORDER = ["chromium", "firefox", "webkit", "safari", "android", "node"]
SOURCE_COLORS = {
    "chromium": "#2a78d6",
    "firefox": "#eb6834",
    "webkit": "#1baf7a",
    "node": "#e87ba4",
    "safari": "#6250d6",
    "android": "#008300",
}
BACKEND_ORDER = ["noble", "liboqs-wasm", "webcrypto-native", "node-crypto"]
BACKEND_COLORS = {
    "noble": "#008300",
    "liboqs-wasm": "#eda100",
    "webcrypto-native": "#e34948",
    "node-crypto": "#6250d6",
}
BACKEND_LABELS = {
    "noble": "noble (pure JS)",
    "liboqs-wasm": "liboqs-js (WASM)",
    "webcrypto-native": "native WebCrypto",
    "node-crypto": "node:crypto (OpenSSL)",
}
COMPONENT_ORDER = [
    "KEM public key",
    "KEM ciphertext",
    "signature",
    "signature public key",
    "AEAD (iv+tag)",
    "headers & routing",
    "framing",
]
COMPONENT_COLORS = dict(
    zip(COMPONENT_ORDER, ["#2a78d6", "#eb6834", "#1baf7a", "#e87ba4", "#008300", "#6250d6", "#eda100"])
)
PLAINTEXT_COLOR = "#c9c8c1"
INK = "#0b0b0b"
INK_2 = "#52514e"
GRID = "#e4e3de"

plt.rcParams.update(
    {
        "figure.facecolor": "white",
        "axes.facecolor": "white",
        "axes.edgecolor": INK_2,
        "axes.labelcolor": INK,
        "axes.titlesize": 11,
        "axes.titleweight": "semibold",
        "axes.labelsize": 9.5,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.grid": True,
        "axes.grid.axis": "y",
        "grid.color": GRID,
        "grid.linewidth": 0.6,
        "xtick.color": INK_2,
        "ytick.color": INK_2,
        "xtick.labelsize": 8.5,
        "ytick.labelsize": 8.5,
        "legend.fontsize": 8.5,
        "legend.frameon": False,
        "font.family": "sans-serif",
        "svg.fonttype": "none",
    }
)


def save(fig, out: Path, name: str, note: str = "") -> None:
    if note:
        # place the provenance note just below everything already drawn (tick labels included)
        bb = fig.get_tightbbox(fig.canvas.get_renderer())
        fig.text(0.01, (bb.y0 - 0.08) / fig.get_figheight(), note, fontsize=7, color=INK_2, ha="left", va="top")
    out.mkdir(parents=True, exist_ok=True)
    for ext in ("png", "svg"):
        fig.savefig(out / f"{name}.{ext}", dpi=200, bbox_inches="tight")
    plt.close(fig)
    print(f"  wrote {name}.png/.svg")


def present(order: list[str], values) -> list[str]:
    vals = set(values)
    return [x for x in order if x in vals] + sorted(vals - set(order))


def grouped_bars(ax, categories, series, get, colors, labels=None, err=None, log=True):
    """Draw grouped bars. get(series, category) -> value or NaN; err -> (lo, hi) or None."""
    n = len(series)
    width = 0.8 / max(n, 1)
    x = np.arange(len(categories))
    for i, s in enumerate(series):
        vals = np.array([get(s, c) for c in categories], dtype=float)
        xs = x - 0.4 + width * (i + 0.5)
        ax.bar(xs, np.nan_to_num(vals, nan=0.0), width * 0.92, color=colors[s], label=(labels or {}).get(s, s),
               edgecolor="white", linewidth=0.8, zorder=3)
        if err is not None:
            lo_hi = np.array([err(s, c) for c in categories], dtype=float)
            ok = ~np.isnan(vals) & ~np.isnan(lo_hi[:, 0])
            if ok.any():
                yerr = np.vstack([vals[ok] - lo_hi[ok, 0], lo_hi[ok, 1] - vals[ok]])
                ax.errorbar(xs[ok], vals[ok], yerr=np.clip(yerr, 0, None), fmt="none", ecolor=INK_2,
                            elinewidth=0.8, capsize=1.8, zorder=4)
        for xi, v in zip(xs, vals):
            if np.isnan(v):
                ax.text(xi, 0.02, "n/a", transform=ax.get_xaxis_transform(), ha="center", va="bottom",
                        fontsize=6.5, color=INK_2, rotation=90)
    ax.set_xticks(x)
    ax.set_xticklabels(categories, rotation=30, ha="right")
    if log:
        ax.set_yscale("log")
    ax.set_axisbelow(True)


# ---------------------------------------------------------------------------
def fig_ops_by_browser(s: pd.DataFrame, out: Path, note: str) -> None:
    d = s[(s.backend == "noble") & (s.status == "ok") & s.exp.isin(["E1", "E2"])]
    if d.empty:
        print("  skip e1e2_ops_by_browser (no noble E1/E2 rows)")
        return
    sources = present(SOURCE_ORDER, d.source)
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.2), gridspec_kw={"width_ratios": [4, 3]})
    for ax, fams, title in [
        (axes[0], ["ML-KEM", "X-Wing"], "E1 · ML-KEM and X-Wing (noble)"),
        (axes[1], ["ML-DSA"], "E2 · ML-DSA (noble)"),
    ]:
        dd = d[d.family.isin(fams)]
        cats = list(dict.fromkeys(f"{a} {o}" for a, o in zip(dd.alg, dd.op)))
        idx = {(r.source, f"{r.alg} {r.op}"): r for r in dd.itertuples()}
        grouped_bars(
            ax, cats, sources,
            get=lambda src, c: idx[(src, c)].ops_s if (src, c) in idx else np.nan,
            err=lambda src, c: (idx[(src, c)].ops_s_p95, idx[(src, c)].ops_s_p5) if (src, c) in idx else (np.nan, np.nan),
            colors=SOURCE_COLORS,
        )
        ax.set_title(title, loc="left")
        ax.set_ylabel("operations per second (log)")
    h, l = axes[0].get_legend_handles_labels()
    fig.legend(h, l, ncol=len(sources), loc="upper left", bbox_to_anchor=(0.01, 1.04))
    fig.suptitle("Post-quantum primitives by browser: higher is faster; bars = median, whiskers = p5–p95 of batches",
                 x=0.01, ha="left", fontsize=10, color=INK_2, y=1.10)
    save(fig, out, "e1e2_ops_by_browser", note)


def fig_backend_comparison(s: pd.DataFrame, out: Path, note: str) -> None:
    d = s[s.alg.isin(["ML-KEM-768", "ML-DSA-65"])]
    if d.empty:
        return
    sources = present(SOURCE_ORDER, d.source)
    backends = present(BACKEND_ORDER, d.backend)
    fig, axes = plt.subplots(1, len(sources), figsize=(3.6 * len(sources), 4.0), sharey=True, squeeze=False)
    cats = ["ML-KEM-768 keygen", "ML-KEM-768 encaps", "ML-KEM-768 decaps",
            "ML-DSA-65 keygen", "ML-DSA-65 sign", "ML-DSA-65 verify"]
    for ax, src in zip(axes[0], sources):
        dd = d[d.source == src]
        idx = {(r.backend, f"{r.alg} {r.op}"): r for r in dd.itertuples() if r.status == "ok"}
        bks = [b for b in backends if (dd.backend == b).any()]
        grouped_bars(
            ax, cats, bks,
            get=lambda b, c: idx[(b, c)].ops_s if (b, c) in idx else np.nan,
            err=lambda b, c: (idx[(b, c)].ops_s_p95, idx[(b, c)].ops_s_p5) if (b, c) in idx else (np.nan, np.nan),
            colors=BACKEND_COLORS, labels=BACKEND_LABELS,
        )
        ax.set_title(src, loc="left")
    axes[0][0].set_ylabel("operations per second (log)")
    handles = [plt.Rectangle((0, 0), 1, 1, color=BACKEND_COLORS[b]) for b in backends]
    fig.legend(handles, [BACKEND_LABELS[b] for b in backends], ncol=len(backends), loc="upper left",
               bbox_to_anchor=(0.01, 1.08))
    fig.suptitle("Backend comparison (ML-KEM-768, ML-DSA-65). n/a = backend unsupported in that runtime",
                 x=0.01, ha="left", fontsize=10, color=INK_2, y=1.13)
    save(fig, out, "backend_comparison", note)


PQ_PAIRS = [
    ("KEM keygen", ("ML-KEM-768", "keygen"), ("X25519", "keygen")),
    ("KEM encaps", ("ML-KEM-768", "encaps"), ("X25519", "derive")),
    ("KEM decaps", ("ML-KEM-768", "decaps"), ("X25519", "derive")),
    ("sig keygen", ("ML-DSA-65", "keygen"), ("Ed25519", "keygen")),
    ("sign", ("ML-DSA-65", "sign"), ("Ed25519", "sign")),
    ("verify", ("ML-DSA-65", "verify"), ("Ed25519", "verify")),
    ("sign (Cat-5)", ("ML-DSA-87", "sign"), ("Ed25519", "sign")),
]


def fig_pq_vs_classical(s: pd.DataFrame, out: Path, note: str) -> None:
    ok = s[s.status == "ok"]
    rows = []
    for src in present(SOURCE_ORDER, ok.source):
        dd = ok[ok.source == src]

        def med(alg, op, backends):
            for b in backends:
                r = dd[(dd.alg == alg) & (dd.op == op) & (dd.backend == b)]
                if not r.empty:
                    return float(r.median_ns.iloc[0]), b
            return np.nan, None

        for label, pq, cl in PQ_PAIRS:
            p, _ = med(*pq, ["noble"])
            c, cb = med(*cl, ["webcrypto-native", "node-crypto", "noble"])
            rows.append({"source": src, "pair": label, "ratio": p / c if c else np.nan, "classical_backend": cb})
    r = pd.DataFrame(rows)
    if r.empty or r.ratio.isna().all():
        print("  skip pq_vs_classical")
        return
    sources = present(SOURCE_ORDER, r.source)
    cats = [p[0] for p in PQ_PAIRS]
    idx = {(x.source, x.pair): x.ratio for x in r.itertuples()}
    fig, ax = plt.subplots(figsize=(10, 4.2))
    grouped_bars(ax, cats, sources, get=lambda src, c: idx.get((src, c), np.nan), colors=SOURCE_COLORS)
    ax.axhline(1, color=INK_2, linewidth=0.8, linestyle="--", zorder=2)
    ax.set_ylabel("slowdown: PQ median ÷ classical median (log)")
    ax.set_title("PQ ÷ classical cost", loc="left")
    fig.text(0.01, 1.0, "PQ = noble ML-KEM-768 / ML-DSA-65 (87 where marked Cat-5); classical = X25519 / Ed25519 via "
             "native WebCrypto (node:crypto in Node). Dashed line = parity.", fontsize=8, color=INK_2, ha="left")
    ax.legend(ncol=len(sources), loc="upper left")
    r.to_csv(out / "pq_vs_classical.csv", index=False)
    save(fig, out, "pq_vs_classical", note)


def fig_aes(s: pd.DataFrame, out: Path, note: str) -> None:
    d = s[(s.alg == "AES-256-GCM") & (s.status == "ok")]
    if d.empty:
        return
    fig, axes = plt.subplots(1, 2, figsize=(10, 3.8), sharey=True)
    for ax, op in zip(axes, ["encrypt", "decrypt"]):
        for src in present(SOURCE_ORDER, d.source):
            dd = d[(d.source == src) & (d.op == op)].sort_values("bytes")
            if dd.empty:
                continue
            ax.plot(dd.bytes, dd.mbps, marker="o", markersize=5, linewidth=2, color=SOURCE_COLORS[src], label=src,
                    markeredgecolor="white", markeredgewidth=1)
        ax.set_xscale("log", base=2)
        ax.set_yscale("log")
        ticks = [64, 1024, 16384, 262144, 1048576]
        ax.set_xticks(ticks)
        ax.set_xticklabels(["64 B", "1 KB", "16 KB", "256 KB", "1 MB"])
        ax.set_title(f"AES-256-GCM {op} (WebCrypto)", loc="left")
        ax.set_xlabel("payload size")
        ax.grid(True, which="major", axis="both")
    axes[0].set_ylabel("throughput, MB/s (log)")
    axes[0].legend(loc="lower right")
    save(fig, out, "aes_throughput", note)


SHORT_VERSION = {"v1-mlkem768": "768*", "v1-xwing": "XW*"}


def fig_e5(e5: pd.DataFrame | None, out: Path) -> None:
    if e5 is None or e5.empty:
        print("  skip e5_bytes (no e5-bytes.csv)")
        return
    e5 = e5.copy()
    e5["component"] = e5.component.replace({"routing": "headers & routing", "header fields": "headers & routing"})
    hs = e5[e5.phase.isin(["bundle", "first-message"])].assign(phase="handshake")
    st = e5[e5.phase == "steady-message"]
    versions = [v for v in ["v0", "v1", "v1-mlkem768", "v1-xwing"] if v in set(e5.version)]
    fig, axes = plt.subplots(1, 2, figsize=(3.4 * len(versions), 4.4), gridspec_kw={"width_ratios": [1, 1]})
    encs = ["raw", "binary", "json-base64"]
    for ax, data, title in [(axes[0], hs, "Per handshake (bundle fetch + first message)"),
                            (axes[1], st, "Per steady-state message (v1 at K = 1)")]:
        g = data.groupby(["version", "encoding", "component"]).bytes.sum()
        xs, labels = [], []
        pos = 0.0
        for v in versions:
            for e in encs:
                xs.append(pos)
                labels.append(f"{SHORT_VERSION.get(v, v)}\n{ {'raw': 'raw', 'binary': 'bin', 'json-base64': 'json'}[e]}")
                pos += 1
            pos += 0.6
        bottoms = np.zeros(len(xs))
        for comp in COMPONENT_ORDER + ["plaintext"]:
            vals = np.array([g.get((v, e, comp), 0) for v in versions for e in encs], dtype=float)
            if not vals.any():
                continue
            ax.bar(xs, vals, 0.8, bottom=bottoms, color=COMPONENT_COLORS.get(comp, PLAINTEXT_COLOR),
                   edgecolor="white", linewidth=1.0, label=comp, zorder=3)
            bottoms += vals
        for x, b in zip(xs, bottoms):
            ax.text(x, b, f"{b / 1000:.1f} k" if b >= 1000 else f"{b:.0f}", ha="center", va="bottom", fontsize=7,
                    color=INK)
        ax.set_xticks(xs)
        ax.set_xticklabels(labels, fontsize=7.5)
        ax.set_ylabel("bytes")
        ax.set_title(title, loc="left")
        ax.set_axisbelow(True)
    h, l = axes[0].get_legend_handles_labels()
    fig.legend(h, l, ncol=8, loc="upper left", bbox_to_anchor=(0.01, 1.07), fontsize=8)
    save(fig, out, "e5_bytes", "E5 byte accounting: v1 measured from the shipped encoder, v0 modelled; 768* / XW* = v1 resized to an ML-KEM-768 / X-Wing ratchet (comparison only); json = Socket.io text frame; "
                               "plaintext = 100 B; bin = length-prefixed binary frame.")


def fig_e10(s: pd.DataFrame, out: Path, note: str) -> None:
    d = s[(s.source == "node") & s.alg.isin(["ML-KEM-768", "ML-KEM-1024", "ML-DSA-65", "ML-DSA-87"])]
    if d.empty:
        print("  skip e10_node (no node results)")
        return
    backends = present(BACKEND_ORDER, d.backend)
    cats = list(dict.fromkeys(f"{a} {o}" for a, o in zip(d.alg, d.op)))
    idx = {(r.backend, f"{r.alg} {r.op}"): r for r in d.itertuples() if r.status == "ok"}
    fig, ax = plt.subplots(figsize=(11, 4.2))
    grouped_bars(
        ax, cats, backends,
        get=lambda b, c: idx[(b, c)].ops_s if (b, c) in idx else np.nan,
        err=lambda b, c: (idx[(b, c)].ops_s_p95, idx[(b, c)].ops_s_p5) if (b, c) in idx else (np.nan, np.nan),
        colors=BACKEND_COLORS, labels=BACKEND_LABELS,
    )
    ax.set_ylabel("operations per second (log)")
    ver = s[s.source == "node"].get("version")
    ax.set_title("E10 · Node: native (OpenSSL) vs WASM vs pure JS", loc="left")
    ax.legend(ncol=len(backends), loc="upper right", bbox_to_anchor=(1.0, 1.15))
    save(fig, out, "e10_node", note)


def fig_heatmap(s: pd.DataFrame, out: Path, note: str) -> None:
    d = s[(s.backend == "noble") & (s.status == "ok") & s.exp.isin(["E1", "E2", "E3"])]
    if d.empty:
        return
    d = d.assign(opname=d.alg + " " + d.op)
    piv = d.pivot_table(index="source", columns="opname", values="median_ns", aggfunc="first")
    piv = piv.reindex(present(SOURCE_ORDER, piv.index))
    cols = list(dict.fromkeys(d.opname))
    piv = piv[cols] / 1000.0  # µs
    fig, ax = plt.subplots(figsize=(max(8, 0.55 * len(cols)), 0.6 * len(piv) + 2.2))
    im = ax.imshow(piv.values, cmap="Blues", norm=LogNorm(vmin=np.nanmin(piv.values), vmax=np.nanmax(piv.values)),
                   aspect="auto")
    ax.set_xticks(range(len(cols)))
    ax.set_xticklabels(cols, rotation=55, ha="right", fontsize=7.5)
    ax.set_yticks(range(len(piv)))
    ax.set_yticklabels(piv.index)
    ax.grid(False)
    mid = np.sqrt(np.nanmin(piv.values) * np.nanmax(piv.values))
    for i in range(piv.shape[0]):
        for j in range(piv.shape[1]):
            v = piv.values[i, j]
            if np.isnan(v):
                continue
            ax.text(j, i, f"{v:.0f}" if v >= 10 else f"{v:.1f}", ha="center", va="center", fontsize=6.5,
                    color="white" if v > mid else INK)
    cb = fig.colorbar(im, ax=ax, fraction=0.025, pad=0.01)
    cb.set_label("median µs per op (log)")
    ax.set_title("Device × operation: median latency, noble backend (µs; darker = slower)", loc="left")
    save(fig, out, "heatmap_device_op", note)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("dir", type=Path)
    ap.add_argument("--out", type=Path, default=None)
    a = ap.parse_args()
    summ = a.dir / "summary.csv"
    if not summ.exists():
        sys.exit(f"{summ} not found: run `npm run aggregate -- {a.dir}` first")
    s = pd.read_csv(summ)
    env = pd.read_csv(a.dir / "env.csv") if (a.dir / "env.csv").exists() else None
    e5 = pd.read_csv(a.dir / "e5-bytes.csv") if (a.dir / "e5-bytes.csv").exists() else None
    out = a.out or (a.dir / "figures")
    out.mkdir(parents=True, exist_ok=True)
    quick = env is not None and env.quick.astype(str).str.lower().eq("true").any()
    runs = int(s.runs.max()) if "runs" in s else 1
    note = f"{a.dir.name} · {'QUICK mode' if quick else 'full method'} · runs per source ≤ {runs}"
    print(f"[plot] {a.dir} -> {out}")
    fig_ops_by_browser(s, out, note)
    fig_backend_comparison(s, out, note)
    fig_pq_vs_classical(s, out, note)
    fig_aes(s, out, note)
    fig_e5(e5, out)
    fig_e10(s, out, note)
    fig_heatmap(s, out, note)


if __name__ == "__main__":
    main()
