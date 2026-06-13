#!/usr/bin/env python3
"""11_ebpf_xdp/report.py"""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from statistics import mean

_LIB = Path(__file__).parent.parent / "lib"
sys.path.insert(0, str(_LIB))
from baseline import ThresholdConfig, Regression, compare, load_baseline, overall_status, save_baseline
from report   import md_table, render_report, write_report, write_meta

THRESHOLDS = {
    # Hook overhead: XDP_PASS should not add more than 5% latency vs no XDP
    "xdp_pass_drv_p99_overhead_pct" : ThresholdConfig(direction="higher_is_bad", warn=5.0,  regress=15.0),
    "xdp_pass_skb_p99_overhead_pct" : ThresholdConfig(direction="higher_is_bad", warn=5.0,  regress=15.0),
    # Throughput should not drop with XDP_PASS attached
    "xdp_pass_drv_tput_loss_pct"    : ThresholdConfig(direction="higher_is_bad", warn=2.0,  regress=5.0),
    # RX ceiling PPS (higher is better)
    "rx_ceiling_drv_mpps"           : ThresholdConfig(direction="lower_is_bad",  warn=5.0,  regress=10.0),
    # RSS balance
    "rss_bpf_cv"                    : ThresholdConfig(direction="higher_is_bad", warn=10.0, regress=30.0),
}


# ── Section: driver XDP capability banner ─────────────────────────────────────

def capability_section(result: dict) -> str:
    native = result.get("native_xdp")
    modes  = result.get("mode_comparison", {})
    xdp_tx = result.get("xdp_tx", {})

    rows = [
        ["Native XDP (xdpdrv)",
         "✅ Supported" if native else ("🔴 **Not supported** — falls back to generic" if native is False else "❓ Unknown")],
        ["Generic XDP (xdpgeneric)",  "✅ Always available (kernel fallback)"],
        ["HW offload XDP (xdphw)",
         "✅ Supported" if modes.get("hw", {}).get("supported") else "—  Not available"],
        ["XDP_TX (buffer recycle)",
         "✅ Supported" if xdp_tx.get("supported") else "⚠️  Not supported by driver"],
    ]
    note = ""
    if native is False:
        note = (
            "\n\n> 🔴 **Driver does not support native XDP.** "
            "All XDP programs will run in `xdpgeneric` (skb) mode, "
            "which processes packets *after* SKB allocation — "
            "negating most XDP performance benefits. "
            "Implement `ndo_bpf` and `ndo_xdp_xmit` in your driver to enable native mode."
        )
    return "## Driver XDP Capability\n\n" + md_table(["Capability", "Status"], rows) + note


# ── Section: hook overhead ────────────────────────────────────────────────────

def hook_overhead_section(hook: dict) -> str:
    base_p99  = hook.get("no_xdp",       {}).get("p99_us")
    base_gbps = hook.get("no_xdp",       {}).get("tx_gbps")
    drv_p99   = hook.get("xdp_pass_drv", {}).get("p99_us")
    drv_gbps  = hook.get("xdp_pass_drv", {}).get("tx_gbps")
    skb_p99   = hook.get("xdp_pass_skb", {}).get("p99_us")
    skb_gbps  = hook.get("xdp_pass_skb", {}).get("tx_gbps")

    def _delta_pct(a, b):
        if a and b: return round((b - a) / a * 100, 1)
        return None

    def _fmt(v, unit=""):
        return f"{v}{unit}" if v is not None else "—"

    def _pct_cell(pct):
        if pct is None: return "—"
        icon = "🔴" if abs(pct) > 10 else ("⚠️" if abs(pct) > 3 else "✅")
        return f"{icon} {pct:+.1f}%"

    rows = [
        ["No XDP (baseline)",
         _fmt(base_p99, " µs"), "—", _fmt(base_gbps, " Gbps"), "—"],
        ["XDP_PASS (native drv)",
         _fmt(drv_p99, " µs"),
         _pct_cell(_delta_pct(base_p99,  drv_p99)),
         _fmt(drv_gbps, " Gbps"),
         _pct_cell(_delta_pct(base_gbps, drv_gbps))],
        ["XDP_PASS (generic skb)",
         _fmt(skb_p99, " µs"),
         _pct_cell(_delta_pct(base_p99,  skb_p99)),
         _fmt(skb_gbps, " Gbps"),
         _pct_cell(_delta_pct(base_gbps, skb_gbps))],
    ]
    return (
        "## XDP Hook Overhead (XDP_PASS)\n\n"
        "> The delta between 'No XDP' and 'XDP_PASS native' is the **pure driver hook cost** — "
        "the penalty your driver pays for any XDP program being attached, regardless of what it does.\n\n"
        + md_table(["Mode", "p99 latency", "Δ latency", "Throughput", "Δ throughput"], rows)
    )


# ── Section: RX ceiling ───────────────────────────────────────────────────────

def rx_ceiling_section(ceiling: dict, hook: dict) -> str:
    if not ceiling: return ""

    base_gbps = hook.get("no_xdp", {}).get("tx_gbps")   # iperf3 RX without XDP
    rows = []
    for label, data in ceiling.items():
        mode = "Native (drv)" if "drv" in label else "Generic (skb)"
        gbps = data.get("rx_gbps", 0)
        overhead = None
        if base_gbps and gbps:
            overhead = round((gbps - base_gbps) / base_gbps * 100, 1)
        rows.append([
            mode,
            f"{data.get('rx_mpps','—')} Mpps",
            f"{gbps} Gbps",
            f"{overhead:+.1f}% vs iperf3 RX" if overhead is not None else "—",
        ])

    return (
        "## RX Ceiling — XDP_DROP\n\n"
        "> XDP_DROP removes SKB allocation and the entire network stack. "
        "PPS here = **driver + DMA processing capacity only**.\n\n"
        "> A much higher PPS vs normal iperf3 RX means SKB/GRO allocation is "
        "a significant fraction of your driver's CPU budget — consider XDP_DROP "
        "or zero-copy paths for high packet-rate workloads.\n\n"
        + md_table(["Mode", "PPS", "Throughput", "vs iperf3 RX"], rows)
    )


# ── Section: RSS validation ───────────────────────────────────────────────────

def rss_section(rss: dict) -> str:
    if not rss: return "## RSS Validation (XDP_COUNTER)\n\n> No BPF counter data available.\n"

    bpf_cpu   = rss.get("bpf_per_cpu", {})
    eth_queue = rss.get("ethtool_per_q", {})
    cv        = rss.get("bpf_cv", 0)
    match_pct = rss.get("match_pct")
    imbal     = rss.get("imbalanced", False)

    cv_icon    = "🔴" if cv > 0.30 else ("⚠️" if cv > 0.15 else "✅")
    match_icon = "🔴" if (match_pct or 100) < 90 else "✅"

    summary_rows = [
        ["BPF CV (per-CPU balance)",
         f"{cv_icon} {cv:.3f} ({'imbalanced' if imbal else 'balanced'})"],
        ["BPF vs ethtool total match", f"{match_icon} {match_pct or '?'}%"],
    ]
    out = (
        "## RSS Validation (XDP_COUNTER vs ethtool)\n\n"
        "> The BPF counter runs in XDP context — it counts packets the driver "
        "delivers to XDP before the kernel stack. "
        "Comparing against `ethtool -S` per-queue stats validates that "
        "RSS steering in the driver is correct and consistent.\n\n"
        + md_table(["Check", "Result"], summary_rows)
    )

    # Per-CPU distribution chart
    if bpf_cpu:
        total = sum(bpf_cpu.values()) or 1
        out  += "\n\n### BPF per-CPU packet distribution\n\n```\n"
        for cpu in sorted(bpf_cpu, key=int):
            cnt = bpf_cpu[cpu]
            pct = cnt / total * 100
            bar = "█" * int(pct / 2)
            out += f"CPU {cpu:>3} │{bar:<50}│ {cnt:>10,} ({pct:5.1f}%)\n"
        out += "```"

    if match_pct is not None and match_pct < 90:
        out += (
            "\n\n> ⚠️ BPF counter saw significantly fewer packets than ethtool reports. "
            "This suggests some RX queues are **bypassing the XDP hook** — check that "
            "`ndo_bpf` is properly implemented for all active queues in your driver."
        )
    return out


# ── Section: mode comparison ──────────────────────────────────────────────────

def mode_section(modes: dict) -> str:
    if not modes: return ""
    rows = []
    gbps_vals = [v.get("tx_gbps", 0) for v in modes.values()
                 if v.get("supported") and v.get("tx_gbps")]
    max_gbps  = max(gbps_vals) if gbps_vals else 1

    for label, data in modes.items():
        supp = data.get("supported", False)
        gbps = data.get("tx_gbps")
        actual = data.get("actual_mode", "—")
        eff  = round(gbps / max_gbps * 100, 1) if gbps and supp else None
        rows.append([
            f"**{label}** (`ip link xdp{label}`)",
            "✅" if supp else "—  Not available",
            f"{gbps} Gbps" if gbps else "—",
            f"{eff}% of max" if eff else "—",
            f"`{actual}`",
        ])

    return (
        "## XDP Attachment Mode Comparison\n\n"
        "> Same `xdp_pass.o` program attached three ways. "
        "Throughput difference = driver overhead per mode.\n\n"
        + md_table(["Mode", "Supported", "Throughput", "Relative", "Actual mode seen"], rows)
    )


# ── Baseline flattening ───────────────────────────────────────────────────────

def flatten(result: dict) -> dict[str, float]:
    m: dict[str, float] = {}
    hook    = result.get("hook_overhead", {})
    ceiling = result.get("rx_ceiling", {})
    rss     = result.get("rss_validation", {})

    base_p99  = hook.get("no_xdp", {}).get("p99_us")
    base_gbps = hook.get("no_xdp", {}).get("tx_gbps")
    drv_p99   = hook.get("xdp_pass_drv", {}).get("p99_us")
    drv_gbps  = hook.get("xdp_pass_drv", {}).get("tx_gbps")
    skb_p99   = hook.get("xdp_pass_skb", {}).get("p99_us")

    if base_p99 and drv_p99:
        m["xdp_pass_drv_p99_overhead_pct"] = (drv_p99 - base_p99) / base_p99 * 100
    if base_p99 and skb_p99:
        m["xdp_pass_skb_p99_overhead_pct"] = (skb_p99 - base_p99) / base_p99 * 100
    if base_gbps and drv_gbps:
        m["xdp_pass_drv_tput_loss_pct"] = (base_gbps - drv_gbps) / base_gbps * 100

    drv_ceil = ceiling.get("drop_drv", {})
    if drv_ceil.get("rx_mpps"):
        m["rx_ceiling_drv_mpps"] = drv_ceil["rx_mpps"]

    if rss.get("bpf_cv") is not None:
        m["rss_bpf_cv"] = rss["bpf_cv"] * 100

    return m


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--result");   ap.add_argument("--baseline")
    ap.add_argument("--env");      ap.add_argument("--output")
    ap.add_argument("--meta", default=None)
    args = ap.parse_args()

    result   = json.loads(Path(args.result).read_text())
    env      = json.loads(Path(args.env).read_text())
    current  = flatten(result)

    baseline_path = Path(args.baseline)
    base_data     = load_baseline(baseline_path)
    is_baseline   = not bool(base_data)
    regressions: list[Regression] = []

    if is_baseline:
        save_baseline(baseline_path, current)
    else:
        regressions = compare(current, base_data, THRESHOLDS)

    native    = result.get("native_xdp")
    ceil_drv  = result.get("rx_ceiling", {}).get("drop_drv", {})
    key_metric = (
        f"Native XDP: {'yes' if native else 'NO'}  "
        f"RX ceiling: {ceil_drv.get('rx_mpps','?')} Mpps"
    )

    sections = [
        capability_section(result),
        hook_overhead_section(result.get("hook_overhead", {})),
        rx_ceiling_section(result.get("rx_ceiling", {}), result.get("hook_overhead", {})),
        rss_section(result.get("rss_validation", {})),
        mode_section(result.get("mode_comparison", {})),
    ]
    if is_baseline:
        sections.insert(0, "## ℹ️ Baseline Run\n\nSaved as new baseline.")

    report = render_report("11_ebpf_xdp", "eBPF / XDP Driver Report",
                           [s for s in sections if s], regressions, env)
    write_report(args.output, report)

    status = "BASELINE" if is_baseline else overall_status(regressions)
    if args.meta:
        write_meta(args.meta, "11_ebpf_xdp", status, key_metric)
    print(f"[report] Status: {status}")


if __name__ == "__main__":
    main()
