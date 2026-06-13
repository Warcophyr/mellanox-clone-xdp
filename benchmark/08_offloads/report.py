#!/usr/bin/env python3
"""08_offloads/report.py"""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path

_LIB = Path(__file__).parent.parent / "lib"
sys.path.insert(0, str(_LIB))
from baseline import ThresholdConfig, compare, load_baseline, overall_status, save_baseline
from report   import md_table, render_report, write_report, write_meta

THRESHOLDS = {
    "baseline_tx_gbps"     : ThresholdConfig(direction="lower_is_bad",  warn=2.0,  regress=5.0),
    "baseline_cpu_per_gbps": ThresholdConfig(direction="higher_is_bad", warn=5.0,  regress=15.0),
}

_OFFLOAD_LABELS = {
    "tso"         : "TSO (TX Segmentation)",
    "gro"         : "GRO (Generic Receive)",
    "lro"         : "LRO (Large Receive)",
    "rx_csum"     : "RX Checksum",
    "tx_csum"     : "TX Checksum",
    "rxvlan"      : "RX VLAN",
    "txvlan"      : "TX VLAN",
    "sg"          : "Scatter-Gather",
    "combo_no_csum": "All Checksum OFF (combo)",
}


def impact_table_section(meas: dict) -> str:
    baseline = meas.get("baseline", {})
    base_gbps = baseline.get("tx_gbps", 0) or 1
    base_cpu  = baseline.get("cpu_per_gbps") or 1

    rows = []
    for label in ["baseline"] + sorted(k for k in meas if k != "baseline"):
        m    = meas.get(label, {})
        gbps = m.get("tx_gbps")
        cpu  = m.get("cpu_per_gbps")
        soft = m.get("cpu_soft_pct")

        if label == "baseline":
            gbps_cell = f"**{gbps}**"
            cpu_cell  = f"**{cpu}**"
            delta_g   = "—"
            delta_c   = "—"
        else:
            offload = label.replace("_off", "")
            dg = round((gbps - base_gbps) / base_gbps * 100, 1) if gbps and base_gbps else None
            dc = round((cpu  - base_cpu ) / base_cpu  * 100, 1) if cpu  and base_cpu  else None
            gbps_cell = f"{gbps or '—'}"
            cpu_cell  = f"{cpu  or '—'}"
            delta_g   = (f"🔴 {dg:+.1f}%" if dg is not None and dg < -3
                         else f"⚠️ {dg:+.1f}%" if dg is not None and dg < 0
                         else f"✅ {dg:+.1f}%" if dg is not None
                         else "—")
            delta_c   = (f"🔴 {dc:+.1f}%" if dc is not None and dc > 10
                         else f"⚠️ {dc:+.1f}%" if dc is not None and dc > 3
                         else f"✅ {dc:+.1f}%" if dc is not None
                         else "—")

        disp_label = _OFFLOAD_LABELS.get(label.replace("_off", ""), label)
        state      = "OFF" if "_off" in label else ("COMBO" if "combo" in label else "ON (baseline)")
        rows.append([disp_label, state, gbps_cell, delta_g,
                     cpu_cell, delta_c, f"{soft or '—'}%"])

    return (
        "## Offload Impact Table\n\n"
        "> Δ columns show change vs all-on baseline. "
        "🔴 = throughput drop or CPU increase > 10%.\n\n"
        + md_table(
            ["Offload", "State", "Throughput", "Δ tput", "CPU %/Gbps", "Δ CPU", "Softirq%"],
            rows,
        )
    )


def flatten(meas: dict) -> dict[str, float]:
    b = meas.get("baseline", {})
    r: dict[str, float] = {}
    if b.get("tx_gbps"):      r["baseline_tx_gbps"]      = b["tx_gbps"]
    if b.get("cpu_per_gbps"): r["baseline_cpu_per_gbps"] = b["cpu_per_gbps"]
    return r


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--result"); ap.add_argument("--baseline")
    ap.add_argument("--env");    ap.add_argument("--output")
    ap.add_argument("--meta", default=None)
    args = ap.parse_args()

    result = json.loads(Path(args.result).read_text())
    env    = json.loads(Path(args.env).read_text())
    meas   = result.get("measurements", {})
    current = flatten(meas)

    baseline_path = Path(args.baseline)
    base_data     = load_baseline(baseline_path)
    is_baseline   = not bool(base_data)
    regressions   = []

    if is_baseline:
        save_baseline(baseline_path, current)
    else:
        regressions = compare(current, base_data, THRESHOLDS)

    b = meas.get("baseline", {})
    key_metric = (f"Baseline {b.get('tx_gbps','?')} Gbps, "
                  f"{b.get('cpu_per_gbps','?')} %/Gbps")

    sections = [impact_table_section(meas)]
    if is_baseline:
        sections.insert(0, "## ℹ️ Baseline Run\n\nSaved as new baseline.")

    report = render_report("08_offloads", "Hardware Offload Impact Report",
                           sections, regressions, env)
    write_report(args.output, report)

    status = "BASELINE" if is_baseline else overall_status(regressions)
    if args.meta:
        write_meta(args.meta, "08_offloads", status, key_metric)
    print(f"[report] Status: {status}")


if __name__ == "__main__":
    main()
