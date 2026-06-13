#!/usr/bin/env python3
"""
02_cpu_microarch/analyse.py

Parse all perf_<scenario>.txt files in --perf-dir, extract hardware
counter values, compute derived metrics (IPC, miss rates, etc.),
and write result.json.

Output schema (result.json):
{
  "duration_s" : 20,
  "iface"      : "eth0",
  "scenarios"  : {
    "<name>": {
      "raw"     : { "<event>": int },    # raw counter values from perf
      "derived" : {
        "ipc"                : float,    # instructions per cycle
        "cache_miss_rate_pct": float,
        "llc_miss_rate_pct"  : float,
        "branch_miss_rate_pct":float,
        "dtlb_miss_rate_pct" : float,
        "itlb_miss_rate_pct" : float,
      },
      "per_packet" : { "<event>": float },  # raw / total_packets
      "packets"    : int,                   # TX+RX packets during window
      "errors"     : [ str ],               # events that <not counted>
    }
  }
}
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


# ── perf stat output parser ───────────────────────────────────────────────────

# perf stat --output writes something like:
#
#  Performance counter stats for 'system wide':
#
#        12345678765      cycles
#         9876543210      instructions   #    0.80  insn per cycle
#           12345678      cache-references
#            1234567      cache-misses   #   10.00% of all cache refs
#    <not counted>        LLC-loads
#  ...
#       20.001234567 seconds time elapsed

_VALUE_RE    = re.compile(r'^\s+([\d]+)\s+(\S[\S ]*\S|\S)\s*(?:#.*)?$')
_NOT_COUNT_RE= re.compile(r'^\s+<not counted>\s+(\S+)')
_NOT_SUPP_RE = re.compile(r'^\s+<not supported>\s+(\S+)')
_ELAPSED_RE  = re.compile(r'^\s+([\d.]+)\s+seconds time elapsed')


def parse_perf_stat(path: Path) -> tuple[dict[str, int], list[str], float]:
    """
    Returns:
        counters  : dict event_name → int value
        errors    : list of event names that were <not counted>/<not supported>
        elapsed   : measured time in seconds
    """
    counters: dict[str, int] = {}
    errors: list[str] = []
    elapsed = 0.0

    text = path.read_text(errors="replace")
    for line in text.splitlines():
        m = _VALUE_RE.match(line)
        if m:
            value = int(m.group(1).replace(",", ""))
            event = m.group(2).strip().split()[0]  # take first word (strip trailing units)
            counters[event] = value
            continue

        m = _NOT_COUNT_RE.match(line)
        if m:
            errors.append(m.group(1))
            continue

        m = _NOT_SUPP_RE.match(line)
        if m:
            errors.append(m.group(1))
            continue

        m = _ELAPSED_RE.match(line)
        if m:
            elapsed = float(m.group(1))

    return counters, errors, elapsed


# ── ethtool packet counter helpers ───────────────────────────────────────────

_ETHTOOL_RE = re.compile(r'^\s+(\S+):\s+(\d+)\s*$')

def parse_ethtool_snap(path: Path | None) -> dict[str, int]:
    if path is None or not path.exists():
        return {}
    result: dict[str, int] = {}
    for line in path.read_text().splitlines():
        m = _ETHTOOL_RE.match(line)
        if m:
            result[m.group(1)] = int(m.group(2))
    return result


def extract_packet_count(t0: dict[str, int], t1: dict[str, int]) -> int:
    """Return total (TX + RX) packet delta between two ethtool snapshots."""
    def get(d: dict, *keys: str) -> int:
        for k in keys:
            if k in d:
                return d[k]
        return 0

    tx0 = get(t0, "tx_packets", "tx_ucast_packets")
    tx1 = get(t1, "tx_packets", "tx_ucast_packets")
    rx0 = get(t0, "rx_packets", "rx_ucast_packets")
    rx1 = get(t1, "rx_packets", "rx_ucast_packets")
    return max(0, (tx1 - tx0) + (rx1 - rx0))


# ── Derived metric computation ────────────────────────────────────────────────

def compute_derived(raw: dict[str, int]) -> dict[str, float]:
    def get(name: str) -> float:
        return float(raw.get(name, 0))

    derived: dict[str, float] = {}

    cycles       = get("cycles")
    instructions = get("instructions")
    cache_refs   = get("cache-references")
    cache_misses = get("cache-misses")
    llc_loads    = get("LLC-loads")
    llc_misses   = get("LLC-load-misses")
    branches     = get("branch-instructions")
    br_misses    = get("branch-misses")
    dtlb_loads   = get("dTLB-loads")
    dtlb_misses  = get("dTLB-load-misses")
    itlb_loads   = get("iTLB-loads")
    itlb_misses  = get("iTLB-load-misses")

    if cycles > 0 and instructions > 0:
        derived["ipc"] = round(instructions / cycles, 4)

    if cache_refs > 0:
        derived["cache_miss_rate_pct"] = round(cache_misses / cache_refs * 100, 3)

    if llc_loads > 0:
        derived["llc_miss_rate_pct"] = round(llc_misses / llc_loads * 100, 3)

    if branches > 0:
        derived["branch_miss_rate_pct"] = round(br_misses / branches * 100, 3)

    if dtlb_loads > 0:
        derived["dtlb_miss_rate_pct"] = round(dtlb_misses / dtlb_loads * 100, 3)

    if itlb_loads > 0:
        derived["itlb_miss_rate_pct"] = round(itlb_misses / itlb_loads * 100, 3)

    if cycles > 0:
        derived["context_switches_per_kcycles"] = round(
            float(raw.get("context-switches", 0)) / cycles * 1000, 4
        )

    return derived


def compute_per_packet(raw: dict[str, int], packets: int) -> dict[str, float]:
    if packets == 0:
        return {}
    return {
        event: round(value / packets, 4)
        for event, value in raw.items()
        if value > 0
    }


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--perf-dir", required=True, help="Directory with perf_<scenario>.txt files")
    ap.add_argument("--duration", type=float, default=20.0)
    ap.add_argument("--iface",    default="unknown")
    ap.add_argument("--output",   required=True)
    args = ap.parse_args()

    perf_dir = Path(args.perf_dir)
    perf_files = sorted(perf_dir.glob("perf_*.txt"))

    if not perf_files:
        sys.exit(f"[error] No perf_*.txt files found in {perf_dir}")

    scenarios: dict[str, dict] = {}

    for pf in perf_files:
        # Filename convention: perf_<scenario_name>.txt
        scenario_name = pf.stem[len("perf_"):]  # strip "perf_" prefix

        raw, errors, elapsed = parse_perf_stat(pf)

        if not raw:
            print(f"[warn] No counters parsed from {pf} — skipping", file=sys.stderr)
            continue

        # Packet count from matching ethtool snapshots (best-effort)
        t0_path = perf_dir / f"pkts_{scenario_name}_t0.txt"
        t1_path = perf_dir / f"pkts_{scenario_name}_t1.txt"
        t0 = parse_ethtool_snap(t0_path)
        t1 = parse_ethtool_snap(t1_path)
        packets = extract_packet_count(t0, t1)

        derived    = compute_derived(raw)
        per_packet = compute_per_packet(raw, packets)

        scenarios[scenario_name] = {
            "raw"        : raw,
            "derived"    : derived,
            "per_packet" : per_packet,
            "packets"    : packets,
            "elapsed_s"  : elapsed or args.duration,
            "errors"     : errors,
        }

        print(
            f"[analyse] {scenario_name:25s}  "
            f"IPC={derived.get('ipc', '?'):>6}  "
            f"cache-miss={derived.get('cache_miss_rate_pct', '?'):>6}%  "
            f"branch-miss={derived.get('branch_miss_rate_pct', '?'):>6}%  "
            f"pkts={packets:,}"
        )

    result = {
        "duration_s" : args.duration,
        "iface"      : args.iface,
        "scenarios"  : scenarios,
    }

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))
    print(f"[analyse] Result → {out}  ({len(scenarios)} scenarios)")


if __name__ == "__main__":
    main()
