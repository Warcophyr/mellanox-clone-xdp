#!/usr/bin/env python3
"""
01_hw_counters/report.py

Read result.json (from collect.py), compare against baseline.json,
and write REPORT.md.

If baseline.json does not exist, the current result IS saved as the new
baseline and the report is marked as "BASELINE RUN".
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Allow importing from lib/ regardless of working directory
_LIB = Path(__file__).parent.parent / "lib"
sys.path.insert(0, str(_LIB))

from baseline import (
    ThresholdConfig, compare, load_baseline, overall_status, save_baseline,
)
from report import md_table, render_report, write_report


# ── Thresholds ────────────────────────────────────────────────────────────────

# We build a flat dict of  metric_name → delta (for any counter that moved).
# The thresholds below apply to "interesting" counters; everything else gets
# the default (5 % warn / 15 % regression, higher_is_bad).

THRESHOLDS: dict[str, ThresholdConfig] = {
    # Drop counters: any increase from zero is bad; 1 % of total pkts is bad
    "rx_dropped"              : ThresholdConfig(direction="higher_is_bad", warn=0.1,  regress=1.0),
    "tx_dropped"              : ThresholdConfig(direction="higher_is_bad", warn=0.1,  regress=1.0),
    "rx_missed_errors"        : ThresholdConfig(direction="higher_is_bad", warn=0.1,  regress=1.0),
    # Throughput: lower is bad
    "tx_gbps"                 : ThresholdConfig(direction="lower_is_bad",  warn=2.0,  regress=5.0),
    "rx_gbps"                 : ThresholdConfig(direction="lower_is_bad",  warn=2.0,  regress=5.0),
    # Error counters: any growth is a warning
    "rx_crc_errors"           : ThresholdConfig(direction="higher_is_bad", warn=0.0,  regress=1.0),
    "rx_symbol_errors"        : ThresholdConfig(direction="higher_is_bad", warn=0.0,  regress=1.0),
    "link_down_events"        : ThresholdConfig(direction="higher_is_bad", warn=0.0,  regress=1.0),
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _flag(c: dict) -> str:
    """Return a cell icon for a counter row."""
    if c["zero_to_nonzero"]:
        return "🔴"
    if c["delta"] < 0:
        return "⬇️"
    if c["delta"] > 0:
        return "⬆️"
    return "—"


def _fmt_rate(r: float) -> str:
    if r == 0:
        return "—"
    if r >= 1e6:
        return f"{r/1e6:.2f} M/s"
    if r >= 1e3:
        return f"{r/1e3:.2f} K/s"
    return f"{r:.1f} /s"


# ── Section builders ──────────────────────────────────────────────────────────

def throughput_section(tp: dict) -> str:
    if not tp:
        return "## Throughput\n\n_No iperf3 data available._\n"
    rows = [[k.replace("_", " "), str(v)] for k, v in tp.items()]
    return "## Throughput (iperf3)\n\n" + md_table(["Metric", "Value"], rows)


def counters_section(counters: dict, group_filter: str | None = None) -> str:
    """
    Render a Markdown table for all counters (optionally filtered by group).
    Only shows counters where delta != 0 to keep the report readable.
    """
    title = f"## Counters — {group_filter.upper()}" if group_filter else "## All Counters (changed only)"

    active = {
        name: c for name, c in counters.items()
        if c["delta"] != 0 and (group_filter is None or c["group"] == group_filter)
    }

    if not active:
        return f"{title}\n\n✅ No counter changes in this group.\n"

    rows = []
    for name, c in sorted(active.items()):
        rows.append([
            _flag(c),
            f"`{name}`",
            f"{c['t0']:,}",
            f"{c['t1']:,}",
            f"{c['delta']:+,}",
            _fmt_rate(c["rate_per_s"]),
            c["group"],
        ])

    return (
        title + "\n\n"
        + md_table(["", "Counter", "T0", "T1", "Δ", "Rate", "Group"], rows)
    )


def zero_nonzero_section(counters: dict) -> str:
    flagged = {n: c for n, c in counters.items() if c["zero_to_nonzero"]}
    if not flagged:
        return "## Zero → Non-Zero Counters\n\n✅ No counters transitioned from zero.\n"

    rows = [[f"`{n}`", f"{c['t1']:,}", c["group"]] for n, c in sorted(flagged.items())]
    return (
        "## Zero → Non-Zero Counters\n\n"
        "> These counters were **zero before** the test run and are now non-zero. "
        "Investigate immediately — this almost always indicates an error condition.\n\n"
        + md_table(["Counter", "Value", "Group"], rows)
    )


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

    counters   = result["counters"]
    throughput = result.get("throughput", {})

    # ── Flatten metrics for baseline comparison ────────────────────────────────
    # We compare per-second rates (normalised, comparable across run durations)
    current_metrics: dict[str, float] = {
        name: c["rate_per_s"]
        for name, c in counters.items()
        if c["delta"] != 0
    }
    current_metrics.update(throughput)  # add tx_gbps, rx_gbps etc.

    # ── Baseline: save if first run, else compare ──────────────────────────────
    baseline_path = Path(args.baseline)
    baseline_data = load_baseline(baseline_path)
    is_baseline_run = not bool(baseline_data)

    regressions = []
    if is_baseline_run:
        save_baseline(baseline_path, current_metrics)
        print("[report] No baseline found — saving current run as baseline.")
    else:
        regressions = compare(current_metrics, baseline_data, THRESHOLDS)

    # ── Build sections ─────────────────────────────────────────────────────────
    sections = [
        throughput_section(throughput),
        zero_nonzero_section(counters),
        counters_section(counters, "rx"),
        counters_section(counters, "tx"),
        counters_section(counters, "error"),
        counters_section(counters, "pfc"),
        counters_section(counters, "link"),
    ]

    if is_baseline_run:
        sections.insert(0,
            "## ℹ️ Baseline Run\n\n"
            "No prior baseline was found. This run has been saved as the new "
            "baseline. Future runs will diff against it."
        )

    # ── Render ────────────────────────────────────────────────────────────────
    status = "BASELINE" if is_baseline_run else overall_status(regressions)
    report = render_report(
        suite_name  = "01_hw_counters",
        title       = "HW Counters — ethtool -S Report",
        sections    = sections,
        regressions = regressions,
        env         = env,
    )
    write_report(args.output, report)
    print(f"[report] Status: {status} | Regressions: {len(regressions)}")


if __name__ == "__main__":
    main()
