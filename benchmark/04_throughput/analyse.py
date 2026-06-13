#!/usr/bin/env python3
"""
04_throughput/analyse.py

Parse iperf3 JSON files, pktgen result files, and mpstat output.
Produces result.json with:
  - tcp_streams:  { parallel_N: { tx_gbps, rx_gbps, retransmits } }
  - bidir:        { tx_gbps, rx_gbps }
  - pktgen_pps:   { 64B: { pps, mpps, errors }, ... }
  - cpu_cost:     { 25pct: { pct_load, tx_gbps, cpu_total_pct, cpu_per_gbps }, ... }
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from statistics import mean


# ── iperf3 JSON ───────────────────────────────────────────────────────────────

def parse_iperf3(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        d    = json.loads(path.read_text())
        end  = d.get("end", {})
        sent = end.get("sum_sent")     or end.get("sum", {})
        recv = end.get("sum_received") or {}
        result: dict = {}
        if sent:
            result["tx_gbps"]      = round(sent.get("bits_per_second", 0) / 1e9, 3)
            result["retransmits"]  = sent.get("retransmits", 0)
        if recv:
            result["rx_gbps"]      = round(recv.get("bits_per_second", 0) / 1e9, 3)
        result["duration_s"]       = end.get("sum_sent", {}).get("seconds", 0) or \
                                     end.get("sum", {}).get("seconds", 0)
        return result
    except Exception as e:
        print(f"[warn] iperf3 parse error {path}: {e}", file=sys.stderr)
        return None


# ── pktgen result ─────────────────────────────────────────────────────────────
# /proc/net/pktgen/<iface>@0 after a run contains:
#   Result: OK: Npkts(cNnanosec) ...errors: N
#   ...pps: N
#   ...ideal_pps: N

_PKTGEN_PPS_RE    = re.compile(r'pps:\s+(\d+)')
_PKTGEN_ERRORS_RE = re.compile(r'errors:\s+(\d+)')
_PKTGEN_PKTS_RE   = re.compile(r'Result: OK:\s+(\d+)\(c(\d+) nanosec\)')

def parse_pktgen(path: Path) -> dict | None:
    if not path.exists():
        return None
    text = path.read_text(errors="replace")
    pps_m    = _PKTGEN_PPS_RE.search(text)
    err_m    = _PKTGEN_ERRORS_RE.search(text)
    pkts_m   = _PKTGEN_PKTS_RE.search(text)
    if not pps_m:
        return None
    pps = int(pps_m.group(1))
    return {
        "pps"    : pps,
        "mpps"   : round(pps / 1e6, 3),
        "errors" : int(err_m.group(1)) if err_m else 0,
        "packets": int(pkts_m.group(1)) if pkts_m else 0,
    }


# ── mpstat ────────────────────────────────────────────────────────────────────
# mpstat -P ALL 1 N output contains an "Average:" line per CPU and one for "all":
#   Average:     all   5.23    0.00    8.45    0.00    1.23    3.45    0.00 ... 81.64
# Columns (sysstat ≥11): %usr %nice %sys %iowait %irq %soft %steal %guest %gnice %idle

_MPSTAT_AVG_RE = re.compile(
    r'^Average:\s+all\s+'
    r'([\d.]+)\s+'   # %usr
    r'([\d.]+)\s+'   # %nice
    r'([\d.]+)\s+'   # %sys
    r'([\d.]+)\s+'   # %iowait
    r'([\d.]+)\s+'   # %irq
    r'([\d.]+)',      # %soft
    re.MULTILINE
)

def parse_mpstat(path: Path) -> dict | None:
    if not path.exists():
        return None
    text = path.read_text(errors="replace")
    m    = _MPSTAT_AVG_RE.search(text)
    if not m:
        return None
    usr, nice, sys_, iowait, irq, soft = (float(m.group(i)) for i in range(1, 7))
    total = usr + nice + sys_ + irq + soft  # exclude iowait and idle
    return {
        "cpu_usr_pct"  : usr,
        "cpu_sys_pct"  : sys_,
        "cpu_irq_pct"  : irq,
        "cpu_soft_pct" : soft,
        "cpu_total_pct": round(total, 2),
    }


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True)
    ap.add_argument("--iface",       default="unknown")
    ap.add_argument("--output",      required=True)
    args = ap.parse_args()

    d = Path(args.results_dir)

    # TCP streams
    tcp_streams: dict[str, dict] = {}
    for p in [1, 4, 8, 16, 32]:
        r = parse_iperf3(d / f"tcp_p{p}.json")
        if r:
            tcp_streams[f"p{p}"] = r
            print(f"[analyse] tcp p{p:>2}  TX={r.get('tx_gbps','?')} Gbps  "
                  f"retx={r.get('retransmits','?')}")

    # Bidir
    bidir = parse_iperf3(d / "tcp_bidir.json") or {}
    if bidir:
        print(f"[analyse] bidir    TX={bidir.get('tx_gbps','?')} Gbps  "
              f"RX={bidir.get('rx_gbps','?')} Gbps")

    # pktgen PPS sweep
    pktgen: dict[str, dict] = {}
    for size in [64, 128, 256, 512, 1024, 1500, 9000]:
        r = parse_pktgen(d / f"pktgen_{size}B.txt")
        if r:
            pktgen[f"{size}B"] = r
            print(f"[analyse] pktgen {size:>4}B  {r['mpps']:.2f} Mpps  "
                  f"errors={r['errors']}")

    # CPU cost
    cpu_cost: dict[str, dict] = {}
    for pct in [25, 50, 75, 100]:
        iperf = parse_iperf3(d / f"cpu_cost_{pct}pct.json")
        mstat = parse_mpstat(d / f"cpu_cost_{pct}pct_mpstat.txt")
        if iperf and mstat:
            gbps = iperf.get("tx_gbps", 0)
            cpu  = mstat["cpu_total_pct"]
            cpu_per_gbps = round(cpu / gbps, 3) if gbps > 0 else None
            entry = {**iperf, **mstat, "cpu_per_gbps": cpu_per_gbps}
            cpu_cost[f"{pct}pct"] = entry
            print(f"[analyse] cpu_cost {pct}%  {gbps} Gbps  "
                  f"CPU={cpu:.1f}%  {cpu_per_gbps} %/Gbps")

    result = {
        "iface"      : args.iface,
        "tcp_streams": tcp_streams,
        "bidir"      : bidir,
        "pktgen_pps" : pktgen,
        "cpu_cost"   : cpu_cost,
    }
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))
    print(f"[analyse] Result → {out}")


if __name__ == "__main__":
    main()
