#!/usr/bin/env python3
"""
01_hw_counters/collect.py

Parse two ethtool -S snapshots (T0 and T1), compute per-counter deltas
and rates, extract iperf3 throughput, and write result.json.

Output schema (result.json):
{
  "duration_s"    : 30,
  "iface"         : "eth0",
  "throughput"    : { "tx_gbps": …, "rx_gbps": …, "tx_pps": …, "rx_pps": … },
  "counters"      : {
    "<name>": {
      "t0": int, "t1": int, "delta": int, "rate_per_s": float,
      "group": str,           # tx | rx | error | pfc | link | other
      "zero_to_nonzero": bool # True = was 0, now > 0 (instant flag)
    }
  },
  "groups": { "<group>": { "<name>": <delta> } }
}
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


# ── Counter classification ────────────────────────────────────────────────────

_GROUP_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("tx",    re.compile(r'^tx_|_tx_|_transmitted')),
    ("rx",    re.compile(r'^rx_|_rx_|_received')),
    ("error", re.compile(r'error|crc|symbol|align|discard|corrupt|bad_')),
    ("pfc",   re.compile(r'pfc|pause|xon|xoff')),
    ("link",  re.compile(r'link|carrier|flap|down|reset')),
]

def classify(name: str) -> str:
    lower = name.lower()
    for group, pat in _GROUP_PATTERNS:
        if pat.search(lower):
            return group
    return "other"


# ── ethtool -S parser ─────────────────────────────────────────────────────────

def parse_ethtool_s(path: Path) -> dict[str, int]:
    """
    Parse 'ethtool -S <iface>' output.
    Lines look like:  '     rx_packets: 12345678'
    Returns dict name → value.
    """
    counters: dict[str, int] = {}
    pattern = re.compile(r'^\s+(\S+):\s+(\d+)\s*$')
    for line in path.read_text().splitlines():
        m = pattern.match(line)
        if m:
            counters[m.group(1)] = int(m.group(2))
    return counters


# ── iperf3 JSON parser ────────────────────────────────────────────────────────

def parse_iperf3(path: Path | None) -> dict[str, float]:
    """
    Extract throughput summary from iperf3 --json output.
    Returns dict with tx_gbps, rx_gbps, tx_pps, rx_pps (where available).
    """
    if path is None or not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
        end  = data.get("end", {})
        result: dict[str, float] = {}

        # Sum (sender side)
        sender = end.get("sum_sent") or end.get("sum", {})
        if sender:
            bps = sender.get("bits_per_second", 0)
            result["tx_gbps"] = round(bps / 1e9, 3)

        # Receiver side
        receiver = end.get("sum_received") or {}
        if receiver:
            bps = receiver.get("bits_per_second", 0)
            result["rx_gbps"] = round(bps / 1e9, 3)

        # Retransmits (TCP)
        if "retransmits" in sender:
            result["tcp_retransmits"] = sender["retransmits"]

        return result
    except Exception as e:
        print(f"[warn] Could not parse iperf3 JSON: {e}", file=sys.stderr)
        return {}


# ── Main ──────────────────────────────────────────────────────────────────────

def build_result(
    t0       : dict[str, int],
    t1       : dict[str, int],
    duration : float,
    iface    : str,
    iperf    : dict[str, float],
) -> dict:
    counters: dict[str, dict] = {}
    groups: dict[str, dict[str, int]] = {}

    all_keys = sorted(set(t0) | set(t1))
    for name in all_keys:
        v0    = t0.get(name, 0)
        v1    = t1.get(name, 0)
        delta = v1 - v0
        rate  = delta / duration if duration > 0 else 0.0
        group = classify(name)

        counters[name] = {
            "t0"             : v0,
            "t1"             : v1,
            "delta"          : delta,
            "rate_per_s"     : round(rate, 3),
            "group"          : group,
            "zero_to_nonzero": (v0 == 0 and v1 > 0),
        }
        groups.setdefault(group, {})[name] = delta

    return {
        "duration_s" : duration,
        "iface"      : iface,
        "throughput" : iperf,
        "counters"   : counters,
        "groups"     : groups,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Compute ethtool counter deltas")
    ap.add_argument("--t0",       required=True, help="ethtool -S snapshot before traffic")
    ap.add_argument("--t1",       required=True, help="ethtool -S snapshot after traffic")
    ap.add_argument("--iperf",    default=None,  help="iperf3 --json output file")
    ap.add_argument("--duration", type=float, default=30.0)
    ap.add_argument("--iface",    default="unknown")
    ap.add_argument("--output",   required=True)
    args = ap.parse_args()

    t0 = parse_ethtool_s(Path(args.t0))
    t1 = parse_ethtool_s(Path(args.t1))

    if not t0:
        sys.exit(f"[error] No counters parsed from T0 file: {args.t0}")
    if not t1:
        sys.exit(f"[error] No counters parsed from T1 file: {args.t1}")

    iperf  = parse_iperf3(Path(args.iperf) if args.iperf else None)
    result = build_result(t0, t1, args.duration, args.iface, iperf)

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))

    # Quick summary to stdout
    n_nonzero = sum(1 for c in result["counters"].values() if c["zero_to_nonzero"])
    n_drops   = sum(
        c["delta"] for name, c in result["counters"].items()
        if "drop" in name.lower() and c["delta"] > 0
    )
    print(f"[collect] Parsed {len(t0)} counters")
    print(f"[collect] Zero→non-zero events : {n_nonzero}")
    print(f"[collect] Total drops (delta)  : {n_drops}")
    if iperf:
        print(f"[collect] Throughput           : "
              f"TX {iperf.get('tx_gbps','?')} Gbps / "
              f"RX {iperf.get('rx_gbps','?')} Gbps")
    print(f"[collect] Result → {out}")


if __name__ == "__main__":
    main()
