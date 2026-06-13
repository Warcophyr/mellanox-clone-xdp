#!/usr/bin/env python3
"""
03_latency/report.py

Reads result.json, diffs p99 against baseline, and writes REPORT.md.
Includes:
  - Percentile table (all scenarios)
  - No-load size-sweep table     (how latency grows with frame size)
  - Loaded vs no-load delta      (load-induced latency penalty)
  - Busy-poll vs interrupt delta (SO_BUSY_POLL benefit)
  - ASCII bar histograms         (one per scenario that has raw samples)
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_LIB = Path(__file__).parent.parent / "lib"
sys.path.insert(0, str(_LIB))

from baseline import ThresholdConfig, Regression, Severity, compare, load_baseline, overall_status, save_baseline
from report   import md_table, render_report, write_report


# ── Baseline thresholds (keyed by "<scenario_name>.p99") ─────────────────────
# Default: p99 going up >5% is a WARNING, >15% is a REGRESSION
_DEFAULT_LAT_THRESHOLD = ThresholdConfig(direction="higher_is_bad", warn=5.0, regress=15.0)


# ── Formatting ────────────────────────────────────────────────────────────────

def _us(v: float | None) -> str:
    if v is None:
        return "—"
    return f"{v:.1f} µs"


def _delta_cell(a: float | None, b: float | None) -> str:
    """Return Δ string (b - a), with icon."""
    if a is None or b is None:
        return "—"
    d = b - a
    pct = d / a * 100 if a != 0 else 0
    icon = "🔴" if pct > 15 else ("⚠️" if pct > 5 else ("✅" if d < 0 else ""))
    return f"{icon} {d:+.1f} µs ({pct:+.0f}%)"


# ── Section: full percentile table ───────────────────────────────────────────

def percentile_table_section(scenarios: dict) -> str:
    headers = ["Scenario", "n", "min", "p50", "p95", "p99", "p99.9", "max"]
    rows = []
    for name, sc in sorted(scenarios.items()):
        p = sc.get("percentiles", {})
        obs = sc.get("n_samples", 0)
        rows.append([
            f"`{name}`",
            f"{obs:,}" if obs else "—",
            _us(p.get("min")),
            _us(p.get("p50")),
            _us(p.get("p95")),
            _us(p.get("p99")),
            _us(p.get("p99_9")),
            _us(p.get("max")),
        ])
    return "## Percentile Summary — All Scenarios\n\n" + md_table(headers, rows)


# ── Section: no-load frame-size sweep ────────────────────────────────────────

def size_sweep_section(scenarios: dict) -> str:
    sizes = [64, 512, 1400, 4096]
    rows = []
    for size in sizes:
        name = f"no_load_{size}B"
        sc   = scenarios.get(name)
        if not sc:
            continue
        p = sc.get("percentiles", {})
        rows.append([
            f"{size} B",
            _us(p.get("min")),
            _us(p.get("p50")),
            _us(p.get("p99")),
            _us(p.get("max")),
        ])
    if not rows:
        return ""
    return (
        "## No-Load Latency vs Frame Size\n\n"
        "> Measured at 1 msg/s — isolates pure driver + NIC latency contribution "
        "with zero queue pressure.\n\n"
        + md_table(["Frame size", "min", "p50", "p99", "max"], rows)
    )


# ── Section: load-induced penalty ────────────────────────────────────────────

def load_penalty_section(scenarios: dict) -> str:
    comparisons = [
        ("64 B @ 1 msg/s",   "no_load_64B",     "loaded_10k_64B",  "loaded_100k_64B"),
        ("1400 B @ 1 msg/s", "no_load_1400B",   "loaded_10k_1400B", None),
    ]
    rows = []
    for label, base_name, rate10k_name, rate100k_name in comparisons:
        base = scenarios.get(base_name, {}).get("percentiles", {})
        r10k = scenarios.get(rate10k_name, {}).get("percentiles", {})
        r100 = scenarios.get(rate100k_name, {}).get("percentiles", {}) if rate100k_name else {}

        rows.append([
            label,
            _us(base.get("p99")),
            _delta_cell(base.get("p99"), r10k.get("p99")),
            _delta_cell(base.get("p99"), r100.get("p99")) if r100 else "—",
        ])

    if not rows:
        return ""
    return (
        "## Load-Induced Latency Penalty (p99)\n\n"
        "> How much latency degrades as message rate increases. "
        "Large deltas indicate queue saturation or coalescing effects.\n\n"
        + md_table(["Base scenario", "p99 @ 1 msg/s", "Δ @ 10k msg/s", "Δ @ 100k msg/s"], rows)
    )


# ── Section: busy-poll vs interrupt ──────────────────────────────────────────

def busypoll_section(scenarios: dict) -> str:
    pairs = [
        ("64 B @ 10k msg/s",   "interrupt_10k_64B",   "busypoll_10k_64B"),
        ("1400 B @ 10k msg/s", "interrupt_10k_1400B", "busypoll_10k_1400B"),
    ]
    rows = []
    for label, intr_name, bp_name in pairs:
        intr = scenarios.get(intr_name, {}).get("percentiles", {})
        bp   = scenarios.get(bp_name,   {}).get("percentiles", {})
        if not intr and not bp:
            continue
        rows.append([
            label,
            _us(intr.get("p99")),
            _us(bp.get("p99")),
            _delta_cell(intr.get("p99"), bp.get("p99")),
        ])

    if not rows:
        return ""
    return (
        "## Interrupt Mode vs Busy-Poll (p99 @ 10k msg/s)\n\n"
        "> `SO_BUSY_POLL` trades CPU for latency. "
        "Negative Δ = busy-poll is faster (expected for latency-sensitive workloads).\n\n"
        + md_table(["Scenario", "Interrupt mode", "Busy-poll mode", "Δ"], rows)
    )


# ── Section: ASCII histogram bars ────────────────────────────────────────────

def ascii_histogram(histogram: list[list], title: str, width: int = 40) -> str:
    if not histogram:
        return ""
    max_count = max(c for _, c in histogram)
    total     = sum(c for _, c in histogram)
    lines     = [f"### {title}", "```"]
    for upper, count in histogram:
        bar_len = int(count / max_count * width) if max_count > 0 else 0
        bar     = "█" * bar_len
        pct     = count / total * 100
        lines.append(f"{upper:>10.1f} µs │{bar:<{width}}│ {count:>6,} ({pct:4.1f}%)")
    lines.append("```")
    return "\n".join(lines)


def histograms_section(scenarios: dict) -> str:
    parts = []
    # Only render histograms for scenarios that have raw full-log data
    for name in sorted(scenarios):
        sc = scenarios[name]
        if sc.get("source") != "fulllog" or not sc.get("histogram"):
            continue
        parts.append(ascii_histogram(sc["histogram"], f"Latency distribution — `{name}`"))

    if not parts:
        return ""
    return "## Latency Distributions (log-scale buckets)\n\n" + "\n\n".join(parts)


# ── Baseline flattening ───────────────────────────────────────────────────────

def flatten_for_baseline(scenarios: dict) -> dict[str, float]:
    """
    Export one value per scenario: "<name>.p99".
    This gives a fine-grained baseline so a single scenario regression is caught.
    """
    return {
        f"{name}.p99": sc["percentiles"]["p99"]
        for name, sc in scenarios.items()
        if sc.get("percentiles", {}).get("p99") is not None
    }


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--result",   required=True)
    ap.add_argument("--baseline", required=True)
    ap.add_argument("--env",      required=True)
    ap.add_argument("--output",   required=True)
    args = ap.parse_args()

    result    = json.loads(Path(args.result).read_text())
    env       = json.loads(Path(args.env).read_text())
    scenarios = result["scenarios"]

    current_metrics = flatten_for_baseline(scenarios)

    # Per-scenario thresholds (all use the same default — customise as needed)
    thresholds = {k: _DEFAULT_LAT_THRESHOLD for k in current_metrics}

    baseline_path = Path(args.baseline)
    baseline_data = load_baseline(baseline_path)
    is_baseline_run = not bool(baseline_data)

    regressions: list[Regression] = []
    if is_baseline_run:
        save_baseline(baseline_path, current_metrics)
        print("[report] No baseline found — saving current run as baseline.")
    else:
        regressions = compare(current_metrics, baseline_data, thresholds)

    sections: list[str] = []
    if is_baseline_run:
        sections.append(
            "## ℹ️ Baseline Run\n\n"
            "No prior baseline found. This run has been saved. "
            "Future runs will compare per-scenario p99 latency against these values."
        )

    sections += [
        percentile_table_section(scenarios),
        size_sweep_section(scenarios),
        load_penalty_section(scenarios),
        busypoll_section(scenarios),
        histograms_section(scenarios),
    ]

    report = render_report(
        suite_name  = "03_latency",
        title       = "Latency — sockperf ping-pong Report",
        sections    = [s for s in sections if s],
        regressions = regressions,
        env         = env,
    )
    write_report(args.output, report)

    status = "BASELINE" if is_baseline_run else overall_status(regressions)
    print(f"[report] Status: {status} | Regressions: {len(regressions)}")


if __name__ == "__main__":
    main()
