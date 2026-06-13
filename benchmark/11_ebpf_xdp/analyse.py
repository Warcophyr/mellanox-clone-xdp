#!/usr/bin/env python3
"""
11_ebpf_xdp/analyse.py

Parse all test outputs and build result.json with:
  - hook_overhead : {no_xdp, xdp_pass_drv, xdp_pass_skb} → {tx_gbps, p99_us}
  - rx_ceiling    : {drop_drv, drop_generic}              → {rx_pps, rx_mpps, cpu%}
  - rss_validation: {bpf_percpu, ethtool_per_queue}       → {cv, match_pct}
  - mode_comparison:{drv, skb, hw}                        → {tx_gbps, supported}
  - xdp_tx        : {supported, rtt_ms}
  - native_xdp    : bool
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from statistics import mean, stdev


# ── iperf3 ────────────────────────────────────────────────────────────────────
def _iperf_gbps(path: Path) -> float | None:
    if not path.exists(): return None
    try:
        d    = json.loads(path.read_text())
        end  = d.get("end", {})
        sent = end.get("sum_sent") or end.get("sum", {})
        bps  = sent.get("bits_per_second", 0)
        return round(bps / 1e9, 3) if bps else None
    except Exception: return None


# ── sockperf summary ──────────────────────────────────────────────────────────
_P99_RE = re.compile(r'Percentile\s+99\.0+\s*=\s*([\d.]+)')
_MIN_RE = re.compile(r'<MIN>\s*observation\s*=\s*([\d.]+)')

def _sockperf_p99(path: Path) -> float | None:
    if not path.exists(): return None
    text = path.read_text(errors="replace")
    m    = _P99_RE.search(text)
    return float(m.group(1)) if m else None


# ── ethtool -S delta ──────────────────────────────────────────────────────────
_ETH_RE = re.compile(r'^\s+(\S+):\s+(\d+)')

def _ethtool_snap(path: Path) -> dict[str, int]:
    if not path.exists(): return {}
    r: dict[str, int] = {}
    for line in path.read_text().splitlines():
        m = _ETH_RE.match(line)
        if m: r[m.group(1)] = int(m.group(2))
    return r

def _rx_pps(t0_path: Path, t1_path: Path, duration: float) -> dict | None:
    t0 = _ethtool_snap(t0_path)
    t1 = _ethtool_snap(t1_path)
    if not t0 or not t1: return None

    rx_pkts = (t1.get("rx_packets", 0) or t1.get("rx_ucast_packets", 0)) - \
              (t0.get("rx_packets", 0) or t0.get("rx_ucast_packets", 0))
    rx_bytes = (t1.get("rx_bytes", 0)) - (t0.get("rx_bytes", 0))

    pps = rx_pkts / duration if duration > 0 else 0
    return {
        "rx_packets"  : rx_pkts,
        "rx_pps"      : round(pps),
        "rx_mpps"     : round(pps / 1e6, 3),
        "rx_gbps"     : round(rx_bytes * 8 / 1e9 / duration, 3) if duration > 0 else 0,
    }


# ── bpftool per-CPU map parser ────────────────────────────────────────────────
# bpftool map dump outputs JSON like:
# [{"key": "0x00000000", "values": [{"cpu": 0, "value": "0x1234"}, ...]}, ...]

def _bpf_percpu(path: Path) -> dict[int, int]:
    """Return {cpu_id: count} from bpftool percpu array dump."""
    if not path.exists(): return {}
    try:
        data    = json.loads(path.read_text())
        per_cpu: dict[int, int] = {}
        for entry in data:
            for item in entry.get("values", []):
                cpu_id = int(item.get("cpu", 0))
                val    = int(item.get("value", "0x0"), 16)
                per_cpu[cpu_id] = per_cpu.get(cpu_id, 0) + val
        return per_cpu
    except Exception:
        return {}


def _ethtool_queue_counts(t0_path: Path, t1_path: Path) -> dict[int, int]:
    """Extract per-queue RX packet deltas from ethtool -S snapshots."""
    t0 = _ethtool_snap(t0_path)
    t1 = _ethtool_snap(t1_path)
    queue_re = re.compile(
        r'^(?:rx_queue_(\d+)_packets|rx(\d+)_packets|queue_(\d+)_rx_packets)$'
    )
    counts: dict[int, int] = {}
    for name in t1:
        m = queue_re.match(name)
        if m:
            qnum  = int(next(g for g in m.groups() if g is not None))
            delta = t1[name] - t0.get(name, 0)
            if delta > 0:
                counts[qnum] = delta
    return counts


def _cv(values: list[int]) -> float:
    """Coefficient of variation: 0 = perfect balance."""
    if len(values) < 2 or mean(values) == 0: return 0.0
    return round(stdev(values) / mean(values), 4)


def _rss_match_pct(bpf: dict[int, int], ethtool: dict[int, int]) -> float | None:
    """
    Compare BPF total vs ethtool total.
    Perfect match = 100%.  A large gap means the driver is not calling the
    XDP hook for all packets (e.g. some queues bypass XDP).
    """
    bpf_total = sum(bpf.values())
    eth_total = sum(ethtool.values())
    if eth_total == 0: return None
    return round(bpf_total / eth_total * 100, 1)


# ── Main ──────────────────────────────────────────────────────────────────────
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True)
    ap.add_argument("--iface",       default="unknown")
    ap.add_argument("--duration",    type=float, default=20.0)
    ap.add_argument("--output",      required=True)
    args = ap.parse_args()
    d    = Path(args.results_dir)
    dur  = args.duration

    # ── Hook overhead ──────────────────────────────────────────────────────────
    hook: dict[str, dict] = {}
    for label in ["no_xdp", "xdp_pass_drv", "xdp_pass_skb"]:
        gbps = _iperf_gbps(d / f"iperf_{label}.json")
        p99  = _sockperf_p99(d / f"sockperf_{label}.txt")
        if gbps or p99:
            hook[label] = {k: v for k, v in
                           [("tx_gbps", gbps), ("p99_us", p99)] if v is not None}
            print(f"[analyse] hook {label:20s}  "
                  f"gbps={gbps or '?'}  p99={p99 or '?'} µs")

    # ── RX ceiling ────────────────────────────────────────────────────────────
    ceiling: dict[str, dict] = {}
    for label in ["drop_drv", "drop_generic"]:
        r = _rx_pps(d / f"{label}_t0.txt", d / f"{label}_t1.txt", dur)
        if r:
            ceiling[label] = r
            print(f"[analyse] ceiling {label:15s}  {r['rx_mpps']} Mpps  {r['rx_gbps']} Gbps")

    # ── RSS validation ────────────────────────────────────────────────────────
    bpf_cpu   = _bpf_percpu(d / "counter_bpf_percpu.json")
    eth_queue = _ethtool_queue_counts(
        d / "counter_ethtool_t0.txt", d / "counter_ethtool_t1.txt"
    )
    rss: dict = {}
    if bpf_cpu:
        bpf_cv   = _cv(list(bpf_cpu.values()))
        match    = _rss_match_pct(bpf_cpu, eth_queue)
        rss = {
            "bpf_per_cpu"  : bpf_cpu,
            "ethtool_per_q": eth_queue,
            "bpf_cv"       : bpf_cv,
            "match_pct"    : match,
            "imbalanced"   : bpf_cv > 0.30,
        }
        print(f"[analyse] RSS  bpf_cv={bpf_cv}  match={match}%")

    # ── Mode comparison ───────────────────────────────────────────────────────
    modes: dict[str, dict] = {}
    for label in ["drv", "skb", "hw"]:
        actual_path = d / f"mode_{label}_actual.txt"
        actual      = actual_path.read_text().strip() if actual_path.exists() else "unknown"
        gbps        = _iperf_gbps(d / f"iperf_mode_{label}.json")
        supported   = actual not in ("unsupported", "unknown")
        modes[label] = {"actual_mode": actual, "tx_gbps": gbps, "supported": supported}
        print(f"[analyse] mode {label:8s}  supported={supported}  gbps={gbps or '?'}  actual={actual}")

    # ── Native XDP support ────────────────────────────────────────────────────
    native_path = d / "native_xdp_supported.txt"
    native_xdp  = (native_path.read_text().strip() == "drv") if native_path.exists() else None

    # ── XDP_TX ────────────────────────────────────────────────────────────────
    xdp_tx_path  = d / "xdp_tx_result.txt"
    xdp_tx_supp  = not (xdp_tx_path.exists() and "unsupported" in xdp_tx_path.read_text())
    xdp_tx_delta = _rx_pps(d / "xdp_tx_t0.txt", d / "xdp_tx_t1.txt", dur)

    result = {
        "iface"          : args.iface,
        "native_xdp"     : native_xdp,
        "hook_overhead"  : hook,
        "rx_ceiling"     : ceiling,
        "rss_validation" : rss,
        "mode_comparison": modes,
        "xdp_tx"         : {"supported": xdp_tx_supp, "stats": xdp_tx_delta},
    }

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))
    print(f"[analyse] Result → {out}")


if __name__ == "__main__":
    main()
