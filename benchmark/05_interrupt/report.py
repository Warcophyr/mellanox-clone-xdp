#!/usr/bin/env python3
"""
05_interrupt/report.py

Reads result.json (from analyse.py) and renders REPORT.md with:
  - ASCII heat-map: p99 latency across (rx-usecs × rx-frames) grid
  - ASCII heat-map: throughput (Gbps) across the same grid
  - Optimal settings call-out box
  - IRQ affinity comparison table
  - softirq distribution table
  - Baseline regression diff
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_LIB = Path(__file__).parent.parent / "lib"
sys.path.insert(0, str(_LIB))

from baseline import ThresholdConfig, Regression, compare, load_baseline, overall_status, save_baseline
from report   import md_table, render_report, write_report


# ── Thresholds ────────────────────────────────────────────────────────────────

THRESHOLDS: dict[str, ThresholdConfig] = {
    # Latency: going up is bad
    "optimal_p99_us"     : ThresholdConfig(direction="higher_is_bad", warn=5.0,  regress=15.0),
    "busypoll_benefit_us": ThresholdConfig(direction="lower_is_bad",  warn=5.0,  regress=15.0),
    # Throughput: going down is bad
    "max_gbps"           : ThresholdConfig(direction="lower_is_bad",  warn=2.0,  regress=5.0),
}


# ── ASCII heat-map renderer ───────────────────────────────────────────────────

def _heat_cell(value: float | None,
               lo: float, hi: float, width: int = 7) -> str:
    """
    Return a fixed-width cell string.
    Values closer to `lo` get a ✅ marker; closer to `hi` get 🔴.
    """
    if value is None:
        return f"{'—':>{width}}"
    fmt = f"{value:>{width}.1f}"
    if hi == lo:
        return fmt
    norm = (value - lo) / (hi - lo)   # 0 = best, 1 = worst
    if norm <= 0.20:   return f"✅{fmt}"
    if norm >= 0.80:   return f"🔴{fmt}"
    if norm >= 0.55:   return f"⚠️{fmt}"
    return f"  {fmt}"


def ascii_heatmap(
    title       : str,
    rx_usecs    : list[int],
    rx_frames   : list[int],
    matrix      : list[list],        # [usec_idx][frame_idx]
    unit        : str,
    invert      : bool = False,      # True = lower value is "best" (latency)
) -> str:
    """
    Render a Markdown table that looks like a 2D heat-map.
    Uses emoji markers to encode magnitude without requiring colour terminals.
    """
    flat = [v for row in matrix for v in row if v is not None]
    if not flat:
        return f"## {title}\n\n_No data available._\n"

    lo, hi = min(flat), max(flat)
    if invert:
        lo, hi = hi, lo   # flip so ✅ = low value

    # Column headers
    frame_headers = [f"**f={f}**" for f in rx_frames]
    header_row    = ["**rx-usecs ↓ / rx-frames →**"] + frame_headers

    rows = []
    for ui, usecs in enumerate(rx_usecs):
        row = [f"**{usecs} µs**"]
        for fi in range(len(rx_frames)):
            v = matrix[ui][fi] if ui < len(matrix) and fi < len(matrix[ui]) else None
            row.append(_heat_cell(v, lo, hi))
        rows.append(row)

    legend = (
        f"\n> ✅ best (≤20th pct) · ⚠️ above median · 🔴 worst (≥80th pct)"
        f" · values in **{unit}**\n"
    )
    return f"## {title}\n\n{md_table(header_row, rows)}{legend}"


# ── Section: optimal settings ────────────────────────────────────────────────

def optimal_section(optimal: dict) -> str:
    if not optimal:
        return ""
    lines = ["## Recommended Coalescing Settings\n"]

    for key, label, note in [
        ("min_p99",       "🏆 Minimum p99 latency",
         "Use this for latency-sensitive workloads (storage, HPC, trading)."),
        ("max_tput",      "🚀 Maximum throughput",
         "Use this for bulk-transfer workloads. Accept higher tail latency."),
        ("best_tradeoff", "⚖️  Best latency / throughput trade-off",
         "Balanced default. Good starting point for most production workloads."),
    ]:
        point = optimal.get(key)
        if not point:
            continue
        p99  = point.get("p99_us",  "?")
        gbps = point.get("gbps",    "?")
        u    = point.get("rx_usecs", "?")
        f    = point.get("rx_frames","?")
        lines += [
            f"### {label}",
            f"```",
            f"ethtool -C <iface> rx-usecs {u} rx-frames {f}",
            f"```",
            f"p99 = **{p99} µs** · throughput = **{gbps} Gbps**",
            f"_{note}_\n",
        ]
    return "\n".join(lines)


# ── Section: IRQ affinity comparison ─────────────────────────────────────────

def affinity_section(affinity: dict) -> str:
    if not affinity:
        return ""
    mode_labels = {
        "irqbalance" : "irqbalance (default daemon)",
        "numa_pinned": "NUMA-pinned (all IRQs on NIC node)",
        "percpu"     : "per-CPU pinned (one IRQ per queue)",
    }
    rows = []
    values = [v["p99_us"] for v in affinity.values() if "p99_us" in v]
    best   = min(values) if values else None

    for mode, data in affinity.items():
        p99    = data.get("p99_us")
        is_best= "⭐" if p99 is not None and p99 == best else ""
        rows.append([
            mode_labels.get(mode, mode),
            f"{p99:.1f} µs" if p99 is not None else "—",
            is_best,
        ])

    return (
        "## IRQ Affinity Comparison (p99 @ 64B 10k msg/s)\n\n"
        + md_table(["Mode", "p99 Latency", "Best"], rows)
        + "\n> Measured with the same coalescing settings across all modes.\n"
    )


# ── Section: softirq distribution ────────────────────────────────────────────

def softirq_section(softirq: dict) -> str:
    if not softirq:
        return ""

    rows = []
    total_rx = sum(v.get("NET_RX_delta", 0) for v in softirq.values())
    total_tx = sum(v.get("NET_TX_delta", 0) for v in softirq.values())

    for cpu, data in sorted(softirq.items(), key=lambda x: int(x[0][3:])):
        rx    = data.get("NET_RX_delta", 0)
        tx    = data.get("NET_TX_delta", 0)
        rx_pct= f"{rx/total_rx*100:.1f}%" if total_rx > 0 else "—"
        tx_pct= f"{tx/total_tx*100:.1f}%" if total_tx > 0 else "—"
        rows.append([cpu, f"{rx:,}", rx_pct, f"{tx:,}", tx_pct])

    # Flag imbalance: CV > 0.3 on NET_RX is a concern
    rx_vals = [v.get("NET_RX_delta", 0) for v in softirq.values()]
    cv_note = ""
    if len(rx_vals) > 1 and total_rx > 0:
        import statistics
        mean_ = statistics.mean(rx_vals)
        cv    = statistics.stdev(rx_vals) / mean_ if mean_ > 0 else 0
        if cv > 0.3:
            cv_note = (f"\n\n> ⚠️ **High NET_RX imbalance** (CV={cv:.2f}). "
                       f"Consider tuning RSS hash key or reviewing IRQ affinity.")
        else:
            cv_note = f"\n\n> ✅ NET_RX distribution is balanced (CV={cv:.2f})."

    return (
        "## softirq Distribution (NET_RX / NET_TX)\n\n"
        "> Measured during a 20s iperf3 run with NUMA-pinned IRQs and "
        "`rx-usecs=50 rx-frames=16`.\n\n"
        + md_table(
            ["CPU", "NET_RX Δ", "NET_RX %", "NET_TX Δ", "NET_TX %"],
            rows,
        )
        + cv_note
    )


# ── Baseline flattening ───────────────────────────────────────────────────────

def flatten_for_baseline(result: dict) -> dict[str, float]:
    metrics: dict[str, float] = {}
    opt = result.get("optimal", {})

    if opt.get("min_p99"):
        metrics["optimal_p99_us"] = opt["min_p99"]["p99_us"]
    if opt.get("max_tput"):
        metrics["max_gbps"] = opt["max_tput"]["gbps"]

    # Affinity best p99
    aff_vals = [v["p99_us"] for v in result.get("affinity", {}).values()
                if "p99_us" in v]
    if aff_vals:
        metrics["affinity_best_p99_us"] = min(aff_vals)

    return metrics


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--result",   required=True)
    ap.add_argument("--baseline", required=True)
    ap.add_argument("--env",      required=True)
    ap.add_argument("--output",   required=True)
    args = ap.parse_args()

    result = json.loads(Path(args.result).read_text())
    env    = json.loads(Path(args.env).read_text())

    grid     = result["grid"]
    optimal  = result.get("optimal", {})
    affinity = result.get("affinity", {})
    softirq  = result.get("softirq", {})

    current_metrics = flatten_for_baseline(result)

    baseline_path = Path(args.baseline)
    baseline_data = load_baseline(baseline_path)
    is_baseline_run = not bool(baseline_data)

    regressions: list[Regression] = []
    if is_baseline_run:
        save_baseline(baseline_path, current_metrics)
        print("[report] No baseline found — saving current run as baseline.")
    else:
        regressions = compare(current_metrics, baseline_data, THRESHOLDS)

    sections: list[str] = []
    if is_baseline_run:
        sections.append(
            "## ℹ️ Baseline Run\n\n"
            "No prior baseline found. This run has been saved. "
            "Future runs will compare optimal p99 and max throughput against these values."
        )

    sections += [
        optimal_section(optimal),
        ascii_heatmap(
            title     = "Coalescing Sweep — p99 Latency (µs)",
            rx_usecs  = grid["rx_usecs"],
            rx_frames = grid["rx_frames"],
            matrix    = grid["latency_p99_us"],
            unit      = "µs",
            invert    = True,   # lower = better
        ),
        ascii_heatmap(
            title     = "Coalescing Sweep — Throughput (Gbps)",
            rx_usecs  = grid["rx_usecs"],
            rx_frames = grid["rx_frames"],
            matrix    = grid["throughput_gbps"],
            unit      = "Gbps",
            invert    = False,  # higher = better
        ),
        affinity_section(affinity),
        softirq_section(softirq),
    ]

    report = render_report(
        suite_name  = "05_interrupt",
        title       = "Interrupt Handling — Coalescing & IRQ Affinity Report",
        sections    = [s for s in sections if s],
        regressions = regressions,
        env         = env,
    )
    write_report(args.output, report)

    status = "BASELINE" if is_baseline_run else overall_status(regressions)
    print(f"[report] Status: {status} | Regressions: {len(regressions)}")


if __name__ == "__main__":
    main()
