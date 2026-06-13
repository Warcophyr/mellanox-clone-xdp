#!/usr/bin/env python3
"""04_throughput/report.py"""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path

_LIB = Path(__file__).parent.parent / "lib"
sys.path.insert(0, str(_LIB))
from baseline import ThresholdConfig, compare, load_baseline, overall_status, save_baseline
from report   import md_table, render_report, write_report, write_meta

THRESHOLDS = {
    "tcp_p1_tx_gbps"    : ThresholdConfig(direction="lower_is_bad", warn=2.0, regress=5.0),
    "tcp_p4_tx_gbps"    : ThresholdConfig(direction="lower_is_bad", warn=2.0, regress=5.0),
    "pktgen_64B_mpps"   : ThresholdConfig(direction="lower_is_bad", warn=3.0, regress=8.0),
    "cpu_per_gbps_100pct": ThresholdConfig(direction="higher_is_bad", warn=5.0, regress=15.0),
}


def tcp_streams_section(streams: dict) -> str:
    if not streams:
        return ""
    rows = []
    for key in ["p1", "p4", "p8", "p16", "p32"]:
        s = streams.get(key)
        if not s:
            continue
        rows.append([
            key.replace("p", ""),
            f"{s.get('tx_gbps','—')} Gbps",
            f"{s.get('rx_gbps','—')} Gbps",
            f"{s.get('retransmits','—')}",
        ])
    return (
        "## TCP Stream Scaling\n\n"
        + md_table(["Parallel streams", "TX", "RX", "Retransmits"], rows)
    )


def pktgen_section(pktgen: dict) -> str:
    if not pktgen:
        return ""
    rows = []
    for key in ["64B","128B","256B","512B","1024B","1500B","9000B"]:
        p = pktgen.get(key)
        if not p:
            continue
        err_cell = f"🔴 {p['errors']:,}" if p["errors"] > 0 else "✅ 0"
        rows.append([key, f"{p['mpps']:.3f}", f"{p['pps']:,}", err_cell])
    return (
        "## UDP PPS Sweep (pktgen)\n\n"
        "> TX-only, zero-copy kernel packet generator, single thread, single queue.\n\n"
        + md_table(["Frame size", "Mpps", "PPS", "Errors"], rows)
    )


def bidir_section(bidir: dict) -> str:
    if not bidir:
        return ""
    rows = [
        ["TX", f"{bidir.get('tx_gbps','—')} Gbps"],
        ["RX", f"{bidir.get('rx_gbps','—')} Gbps"],
        ["Combined", f"{round((bidir.get('tx_gbps',0) + bidir.get('rx_gbps',0)), 2)} Gbps"],
    ]
    return "## Bidirectional TCP (4 streams each direction)\n\n" + md_table(["Direction", "Throughput"], rows)


def cpu_cost_section(cpu_cost: dict) -> str:
    if not cpu_cost:
        return ""
    rows = []
    for pct in ["25pct", "50pct", "75pct", "100pct"]:
        c = cpu_cost.get(pct)
        if not c:
            continue
        rows.append([
            pct.replace("pct", "%"),
            f"{c.get('tx_gbps','—')} Gbps",
            f"{c.get('cpu_total_pct','—')}%",
            f"{c.get('cpu_soft_pct','—')}%",
            f"{c.get('cpu_per_gbps','—')} %/Gbps",
        ])
    return (
        "## CPU Cost vs Line Rate\n\n"
        "> `%/Gbps` = CPU% ÷ throughput — lower is more efficient.\n\n"
        + md_table(["Target load", "Actual throughput", "Total CPU%", "Softirq%", "CPU %/Gbps"], rows)
    )


def flatten_for_baseline(result: dict) -> dict[str, float]:
    m: dict[str, float] = {}
    for k, v in result.get("tcp_streams", {}).items():
        if v.get("tx_gbps"):
            m[f"tcp_{k}_tx_gbps"] = v["tx_gbps"]
    for k, v in result.get("pktgen_pps", {}).items():
        m[f"pktgen_{k}_mpps"] = v["mpps"]
    for k, v in result.get("cpu_cost", {}).items():
        if v.get("cpu_per_gbps"):
            m[f"cpu_per_gbps_{k}"] = v["cpu_per_gbps"]
    return m


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--result");   ap.add_argument("--baseline")
    ap.add_argument("--env");      ap.add_argument("--output")
    ap.add_argument("--meta", default=None)
    args = ap.parse_args()

    result  = json.loads(Path(args.result).read_text())
    env     = json.loads(Path(args.env).read_text())
    current = flatten_for_baseline(result)

    baseline_path = Path(args.baseline)
    baseline_data = load_baseline(baseline_path)
    is_baseline   = not bool(baseline_data)
    regressions   = []

    if is_baseline:
        save_baseline(baseline_path, current)
        print("[report] No baseline — saving.")
    else:
        regressions = compare(current, baseline_data, THRESHOLDS)

    # Key metric: single-stream TCP throughput
    key_metric = f"{result.get('tcp_streams', {}).get('p1', {}).get('tx_gbps', '?')} Gbps (TCP p=1)"

    sections = [
        tcp_streams_section(result.get("tcp_streams", {})),
        bidir_section(result.get("bidir", {})),
        pktgen_section(result.get("pktgen_pps", {})),
        cpu_cost_section(result.get("cpu_cost", {})),
    ]
    if is_baseline:
        sections.insert(0, "## ℹ️ Baseline Run\n\nThis run has been saved as the new baseline.")

    report = render_report("04_throughput", "Throughput Report",
                           [s for s in sections if s], regressions, env)
    write_report(args.output, report)

    status = "BASELINE" if is_baseline else overall_status(regressions)
    if args.meta:
        write_meta(args.meta, "04_throughput", status, key_metric)
    print(f"[report] Status: {status} | Regressions: {len(regressions)}")


if __name__ == "__main__":
    main()
