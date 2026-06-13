#!/usr/bin/env python3
"""
02_cpu_microarch/report.py

Read result.json (from analyse.py), compare derived metrics against
baseline.json, and write REPORT.md.

Baseline comparison uses the AVERAGE across all scenarios for each
derived metric, so a single rogue scenario doesn't mask improvements.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from statistics import mean

_LIB = Path(__file__).parent.parent / "lib"
sys.path.insert(0, str(_LIB))

from baseline import ThresholdConfig, compare, load_baseline, overall_status, save_baseline
from report   import md_table, render_report, write_report


# ── Thresholds for derived metrics ────────────────────────────────────────────

THRESHOLDS: dict[str, ThresholdConfig] = {
    # Miss rates: going up is bad
    "cache_miss_rate_pct"    : ThresholdConfig(direction="higher_is_bad", warn=5.0,  regress=15.0),
    "llc_miss_rate_pct"      : ThresholdConfig(direction="higher_is_bad", warn=5.0,  regress=15.0),
    "branch_miss_rate_pct"   : ThresholdConfig(direction="higher_is_bad", warn=5.0,  regress=15.0),
    "dtlb_miss_rate_pct"     : ThresholdConfig(direction="higher_is_bad", warn=5.0,  regress=15.0),
    "itlb_miss_rate_pct"     : ThresholdConfig(direction="higher_is_bad", warn=5.0,  regress=15.0),
    # IPC: going down is bad
    "ipc"                    : ThresholdConfig(direction="lower_is_bad",  warn=5.0,  regress=10.0),
    # Context switches per 1k cycles: going up is bad
    "context_switches_per_kcycles": ThresholdConfig(direction="higher_is_bad", warn=10.0, regress=30.0),
}

# Human-readable labels for all derived metrics
_DERIVED_LABELS: dict[str, str] = {
    "ipc"                          : "IPC (instructions/cycle)",
    "cache_miss_rate_pct"          : "Cache miss rate",
    "llc_miss_rate_pct"            : "LLC miss rate",
    "branch_miss_rate_pct"         : "Branch miss rate",
    "dtlb_miss_rate_pct"           : "dTLB miss rate",
    "itlb_miss_rate_pct"           : "iTLB miss rate",
    "context_switches_per_kcycles" : "Ctx-switches / 1k cycles",
}

# For each raw event, a short human label
_RAW_LABELS: dict[str, str] = {
    "cycles"              : "Cycles",
    "instructions"        : "Instructions",
    "cache-references"    : "Cache refs",
    "cache-misses"        : "Cache misses",
    "LLC-loads"           : "LLC loads",
    "LLC-load-misses"     : "LLC load misses",
    "branch-instructions" : "Branches",
    "branch-misses"       : "Branch misses",
    "dTLB-loads"          : "dTLB loads",
    "dTLB-load-misses"    : "dTLB misses",
    "iTLB-loads"          : "iTLB loads",
    "iTLB-load-misses"    : "iTLB misses",
    "context-switches"    : "Context switches",
    "cpu-migrations"      : "CPU migrations",
}


# ── Formatting helpers ────────────────────────────────────────────────────────

def _fmt(v: float | int | None, pct: bool = False) -> str:
    if v is None:
        return "—"
    if pct:
        return f"{v:.2f}%"
    if isinstance(v, int) or v >= 1000:
        return f"{int(v):,}"
    return f"{v:.4f}"


# ── Section builders ──────────────────────────────────────────────────────────

def derived_summary_section(scenarios: dict) -> str:
    """
    One row per scenario, columns for each derived metric.
    Highlights the most important quality-of-life numbers at a glance.
    """
    headers = ["Scenario", "IPC", "Cache miss%", "LLC miss%",
               "Branch miss%", "dTLB miss%", "iTLB miss%", "Packets"]
    rows = []
    for name, sc in sorted(scenarios.items()):
        d = sc.get("derived", {})
        rows.append([
            f"`{name}`",
            _fmt(d.get("ipc")),
            _fmt(d.get("cache_miss_rate_pct"), pct=True),
            _fmt(d.get("llc_miss_rate_pct"),   pct=True),
            _fmt(d.get("branch_miss_rate_pct"), pct=True),
            _fmt(d.get("dtlb_miss_rate_pct"),   pct=True),
            _fmt(d.get("itlb_miss_rate_pct"),   pct=True),
            f"{sc.get('packets', 0):,}",
        ])

    return "## Derived Metrics Summary\n\n" + md_table(headers, rows)


def raw_counters_section(scenario_name: str, sc: dict) -> str:
    """Per-scenario table: raw counter, per-packet normalised, not-counted events."""
    raw        = sc.get("raw", {})
    per_packet = sc.get("per_packet", {})
    errors     = sc.get("errors", [])
    packets    = sc.get("packets", 0)

    rows = []
    for event, label in _RAW_LABELS.items():
        v   = raw.get(event)
        pp  = per_packet.get(event)
        rows.append([
            label,
            _fmt(v) if v is not None else "—",
            _fmt(pp) if pp is not None else ("—" if packets == 0 else "0"),
        ])

    title  = f"### Scenario: `{scenario_name}`"
    table  = md_table(["Event", "Total", "Per packet"], rows)
    errors_note = ""
    if errors:
        errors_note = (
            f"\n\n> ⚠️ **Not counted / not supported:** "
            + ", ".join(f"`{e}`" for e in errors)
            + "  \n> These events are unavailable on this CPU. Results are still valid for counted events."
        )
    return f"{title}\n\n{table}{errors_note}"


def per_packet_comparison_section(scenarios: dict) -> str:
    """
    Cross-scenario comparison of the most important per-packet costs.
    Helps identify which traffic pattern is most expensive for the driver.
    """
    key_events = ["cycles", "instructions", "cache-misses", "LLC-load-misses",
                  "branch-misses", "dTLB-load-misses"]

    scenario_names = sorted(scenarios.keys())
    headers = ["Event"] + [f"`{n}`" for n in scenario_names]

    rows = []
    for event in key_events:
        label = _RAW_LABELS.get(event, event)
        row   = [label]
        for name in scenario_names:
            pp = scenarios[name].get("per_packet", {})
            row.append(_fmt(pp.get(event)))
        rows.append(row)

    return (
        "## Per-Packet Cost Comparison\n\n"
        "> Normalised by total TX+RX packet count during the measurement window.\n\n"
        + md_table(headers, rows)
    )


def errors_section(scenarios: dict) -> str:
    all_errors: dict[str, list[str]] = {}
    for name, sc in scenarios.items():
        for e in sc.get("errors", []):
            all_errors.setdefault(e, []).append(name)
    if not all_errors:
        return ""
    rows = [[f"`{ev}`", ", ".join(f"`{s}`" for s in scens)]
            for ev, scens in sorted(all_errors.items())]
    return (
        "## Unavailable perf Events\n\n"
        "> These events were reported as `<not counted>` or `<not supported>` "
        "by the kernel. This is normal for counters not present on your CPU.\n\n"
        + md_table(["Event", "Affected Scenarios"], rows)
    )


# ── Flatten metrics for baseline comparison ───────────────────────────────────

def flatten_for_baseline(scenarios: dict) -> dict[str, float]:
    """
    Average each derived metric across all scenarios.
    This gives a single stable scalar per metric for the baseline diff.
    """
    all_derived: dict[str, list[float]] = {}
    for sc in scenarios.values():
        for k, v in sc.get("derived", {}).items():
            all_derived.setdefault(k, []).append(v)
    return {k: round(mean(vals), 6) for k, vals in all_derived.items() if vals}


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

    # ── Baseline handling ─────────────────────────────────────────────────────
    baseline_path = Path(args.baseline)
    baseline_data = load_baseline(baseline_path)
    is_baseline_run = not bool(baseline_data)

    regressions = []
    if is_baseline_run:
        save_baseline(baseline_path, current_metrics)
        print("[report] No baseline found — saving current run as baseline.")
    else:
        regressions = compare(current_metrics, baseline_data, THRESHOLDS)

    # ── Sections ──────────────────────────────────────────────────────────────
    raw_sections = [
        raw_counters_section(name, sc)
        for name, sc in sorted(scenarios.items())
    ]

    sections: list[str] = []

    if is_baseline_run:
        sections.append(
            "## ℹ️ Baseline Run\n\n"
            "No prior baseline found. This run has been saved as the new baseline. "
            "Future runs will compare derived metrics against these averages."
        )

    sections += [
        derived_summary_section(scenarios),
        per_packet_comparison_section(scenarios),
        "## Raw Counters per Scenario\n\n" + "\n\n".join(raw_sections),
        errors_section(scenarios),
    ]

    # ── Render ────────────────────────────────────────────────────────────────
    report = render_report(
        suite_name  = "02_cpu_microarch",
        title       = "CPU Micro-Architecture — perf stat Report",
        sections    = [s for s in sections if s],  # drop empty sections
        regressions = regressions,
        env         = env,
    )
    write_report(args.output, report)

    status = "BASELINE" if is_baseline_run else overall_status(regressions)
    print(f"[report] Status: {status} | Regressions: {len(regressions)}")


if __name__ == "__main__":
    main()
