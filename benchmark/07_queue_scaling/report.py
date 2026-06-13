#!/usr/bin/env python3
"""07_queue_scaling/report.py"""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path

_LIB = Path(__file__).parent.parent / "lib"
sys.path.insert(0, str(_LIB))
from baseline import ThresholdConfig, compare, load_baseline, overall_status, save_baseline
from report   import md_table, render_report, write_report, write_meta

THRESHOLDS = {
    "max_throughput_gbps": ThresholdConfig(direction="lower_is_bad", warn=2.0, regress=5.0),
    "rss_cv"             : ThresholdConfig(direction="higher_is_bad", warn=10.0, regress=30.0),
}


def scaling_section(qs: dict) -> str:
    if not qs: return ""
    rows = []
    for key in sorted(qs, key=lambda x: int(x[1:])):
        v   = qs[key]
        eff = v.get("efficiency", 0)
        icon = "✅" if eff >= 0.80 else ("⚠️" if eff >= 0.50 else "🔴")
        rows.append([str(v["queues"]), f"{v['tx_gbps']} Gbps",
                     f"{icon} {eff:.0%}"])
    return (
        "## Queue Count Scaling\n\n"
        "> Efficiency = gbps(N) / (N × gbps(1)). 100% = perfect linear scaling.\n\n"
        + md_table(["Queues", "Throughput", "Scaling efficiency"], rows)
    )


def ring_section(rs: dict) -> str:
    if not rs: return ""
    rows = []
    for key in sorted(rs, key=lambda x: int(x)):
        v     = rs[key]
        drop  = v["drops"]
        dcell = f"🔴 {drop:,}" if drop > 0 else "✅ 0"
        rows.append([str(v["ring"]), f"{v['tx_gbps']} Gbps", dcell])
    return (
        "## Ring Buffer Depth vs Throughput\n\n"
        "> Find the minimum depth with zero drops — smaller rings = less memory + better cache behaviour.\n\n"
        + md_table(["Ring depth", "Throughput", "Drops"], rows)
    )


def rss_section(rss: dict) -> str:
    if rss.get("unavailable"):
        return (
            "## RSS Queue Distribution\n\n"
            "> Per-queue counters not found in `ethtool -S` output. "
            "Check driver for `rx_queue_N_packets` or `rxN_packets` counters.\n"
        )
    cv      = rss.get("cv", 0)
    total   = rss.get("total", 1)
    per_q   = rss.get("per_queue", {})
    icon    = "✅" if cv < 0.15 else ("⚠️" if cv < 0.30 else "🔴")
    rows    = []
    for q in sorted(per_q, key=lambda x: int(x[1:])):
        pct = round(per_q[q] / total * 100, 1) if total else 0
        bar = "█" * int(pct / 2)
        rows.append([q, f"{per_q[q]:,}", f"{pct:.1f}%", bar])
    return (
        "## RSS Hash Distribution\n\n"
        f"> CV = **{cv:.3f}** {icon} (0 = perfect balance, >0.3 = imbalanced)\n\n"
        + md_table(["Queue", "Packets", "%", "Distribution"], rows)
        + "\n> CV (coefficient of variation) = stdev / mean across queues.\n"
    )


def flatten(result: dict) -> dict[str, float]:
    m: dict[str, float] = {}
    all_gbps = [v["tx_gbps"] for v in result.get("queue_scaling", {}).values()]
    if all_gbps: m["max_throughput_gbps"] = max(all_gbps)
    cv = result.get("rss", {}).get("cv")
    if cv is not None: m["rss_cv"] = cv * 100
    return m


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--result"); ap.add_argument("--baseline")
    ap.add_argument("--env");    ap.add_argument("--output")
    ap.add_argument("--meta", default=None)
    args = ap.parse_args()

    result   = json.loads(Path(args.result).read_text())
    env      = json.loads(Path(args.env).read_text())
    current  = flatten(result)

    baseline_path = Path(args.baseline)
    base_data     = load_baseline(baseline_path)
    is_baseline   = not bool(base_data)
    regressions   = []

    if is_baseline:
        save_baseline(baseline_path, current)
    else:
        regressions = compare(current, base_data, THRESHOLDS)

    cv = result.get("rss", {}).get("cv", "?")
    key_metric = f"RSS CV={cv}  max={current.get('max_throughput_gbps','?')} Gbps"

    sections = [
        scaling_section(result.get("queue_scaling", {})),
        ring_section(result.get("ring_sweep", {})),
        rss_section(result.get("rss", {})),
    ]
    if is_baseline:
        sections.insert(0, "## ℹ️ Baseline Run\n\nSaved as new baseline.")

    report = render_report("07_queue_scaling", "Queue Scaling & RSS Report",
                           [s for s in sections if s], regressions, env)
    write_report(args.output, report)

    status = "BASELINE" if is_baseline else overall_status(regressions)
    if args.meta:
        write_meta(args.meta, "07_queue_scaling", status, key_metric)
    print(f"[report] Status: {status}")


if __name__ == "__main__":
    main()
