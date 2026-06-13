#!/usr/bin/env python3
"""06_memory_dma/report.py"""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path

_LIB = Path(__file__).parent.parent / "lib"
sys.path.insert(0, str(_LIB))
from baseline import ThresholdConfig, compare, load_baseline, overall_status, save_baseline
from report   import md_table, render_report, write_report, write_meta

THRESHOLDS = {
    "numa_penalty_pct" : ThresholdConfig(direction="higher_is_bad", warn=3.0, regress=10.0),
    "numa_local_gbps"  : ThresholdConfig(direction="lower_is_bad",  warn=2.0, regress=5.0),
}


def dma_section(dma: dict) -> str:
    if not dma or dma.get("unavailable"):
        return (
            "## DMA Alloc/Map Latency\n\n"
            "> ⚠️ bpftrace and ftrace were not available. "
            "Install `bpftrace` for automated DMA timing:\n"
            "> `apt install bpftrace` (kernel ≥ 4.9)\n"
        )
    counts = dma.get("counts", {})
    rows = [["dma_alloc_coherent calls", f"{counts.get('alloc', 0):,}"],
            ["dma_map_single calls",     f"{counts.get('map',   0):,}"]]
    out = "## DMA Alloc/Map Latency (bpftrace)\n\n" + md_table(["Metric", "Value"], rows)

    for hist_key, hist_data in dma.get("histograms", {}).items():
        if not hist_data:
            continue
        label = hist_key.replace("dma_", "").replace("_lat_ns", "").replace("_", " ")
        total = sum(h["count"] for h in hist_data)
        out  += f"\n\n### {label} latency distribution\n\n```\n"
        for h in hist_data:
            bar = "█" * min(40, int(h["count"] / max(1, total) * 40))
            out += f"{h['lo_ns']:>8} – {h['hi_ns']:>8} ns │{bar:<40}│ {h['count']:,}\n"
        out += "```"
    return out


def numa_section(numa: dict) -> str:
    if numa.get("single_node"):
        return "## NUMA Placement\n\n> Single-NUMA system — cross-NUMA test skipped.\n"
    rows = [
        ["Local-NUMA (cpu=mem=NIC node)", f"{numa.get('local_gbps','—')} Gbps", "—"],
        ["Cross-NUMA (cpu=NIC, mem=remote)", f"{numa.get('remote_gbps','—')} Gbps",
         f"🔴 -{numa['penalty_pct']}%" if (numa.get("penalty_pct") or 0) > 5
         else f"✅ -{numa.get('penalty_pct','?')}%"],
    ]
    note = ("> Large cross-NUMA penalty means DMA buffers are being allocated on "
            "the wrong node.\n> Check your driver's `dev_alloc_skb` / `dma_alloc_coherent` NUMA hints.")
    return (
        "## NUMA Placement Impact\n\n"
        + md_table(["Configuration", "Throughput", "Penalty"], rows)
        + f"\n\n{note}\n"
    )


def hugepage_section(hp: dict) -> str:
    none_g = hp.get("none_gbps")
    two_g  = hp.get("2m_gbps")
    if none_g is None and two_g is None:
        return ""
    delta = round(two_g - none_g, 3) if (none_g and two_g) else None
    rows = [
        ["4K pages (default)", f"{none_g or '—'} Gbps"],
        ["2M hugepages",       f"{two_g or '—'} Gbps",
         f"{delta:+.3f} Gbps" if delta is not None else "—"],
    ]
    return (
        "## Hugepage Impact\n\n"
        + md_table(["Mode", "Throughput", "Δ vs 4K pages"], [r[:3] if len(r)==3 else r+["—"] for r in rows])
        + "\n> A positive delta means hugepages reduce TLB pressure in the DMA path.\n"
    )


def slab_section(slab: list) -> str:
    if not slab:
        return "## Slab Memory\n\n✅ No significant slab growth detected during the traffic run.\n"
    rows = [[f"`{e['cache']}`", f"{e['t0']:,}", f"{e['t1']:,}", f"+{e['delta']:,}"] for e in slab]
    note = (
        "> These slab caches grew during the traffic run. "
        "A growing `skbuff_head_cache` or `kmalloc-*` that doesn't shrink after traffic "
        "stops is a strong indicator of a memory leak."
    )
    return (
        "## Slab Growth (potential leaks)\n\n"
        + md_table(["Cache", "T0 objects", "T1 objects", "Δ"], rows)
        + f"\n\n{note}\n"
    )


def flatten(result: dict) -> dict[str, float]:
    m: dict[str, float] = {}
    numa = result.get("numa", {})
    if numa.get("local_gbps"):
        m["numa_local_gbps"] = numa["local_gbps"]
    if numa.get("penalty_pct") is not None:
        m["numa_penalty_pct"] = numa["penalty_pct"]
    return m


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--result"); ap.add_argument("--baseline")
    ap.add_argument("--env");    ap.add_argument("--output")
    ap.add_argument("--meta", default=None)
    args = ap.parse_args()

    result = json.loads(Path(args.result).read_text())
    env    = json.loads(Path(args.env).read_text())
    current = flatten(result)

    baseline_path = Path(args.baseline)
    base_data     = load_baseline(baseline_path)
    is_baseline   = not bool(base_data)
    regressions   = []

    if is_baseline:
        save_baseline(baseline_path, current)
    else:
        regressions = compare(current, base_data, THRESHOLDS)

    numa    = result.get("numa", {})
    penalty = numa.get("penalty_pct")
    key_metric = (f"NUMA penalty: {penalty}%" if penalty is not None
                  else f"Local: {numa.get('local_gbps','?')} Gbps")

    sections = [
        dma_section(result.get("dma_timing", {})),
        numa_section(numa),
        hugepage_section(result.get("hugepage", {})),
        slab_section(result.get("slab_delta", [])),
    ]
    if is_baseline:
        sections.insert(0, "## ℹ️ Baseline Run\n\nSaved as new baseline.")

    report = render_report("06_memory_dma", "Memory & DMA Report",
                           [s for s in sections if s], regressions, env)
    write_report(args.output, report)

    status = "BASELINE" if is_baseline else overall_status(regressions)
    if args.meta:
        write_meta(args.meta, "06_memory_dma", status, key_metric)
    print(f"[report] Status: {status} | Regressions: {len(regressions)}")


if __name__ == "__main__":
    main()
