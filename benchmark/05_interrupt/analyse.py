#!/usr/bin/env python3
"""
05_interrupt/analyse.py

Parse all sweep measurement files, the IRQ affinity comparison files,
and the softirq snapshots. Build the 2D coalescing matrix and write result.json.

Output schema (result.json):
{
  "iface"  : "eth0",
  "grid"   : {
    "rx_usecs"  : [0, 5, 10, ...],
    "rx_frames" : [0, 1, 4, ...],
    "latency_p99_us" : [[float|null, ...], ...],   # indexed [usec_idx][frame_idx]
    "throughput_gbps": [[float|null, ...], ...],
  },
  "optimal" : {
    "min_p99"    : {"rx_usecs": int, "rx_frames": int, "p99_us": float, "gbps": float},
    "max_tput"   : {"rx_usecs": int, "rx_frames": int, "p99_us": float, "gbps": float},
    "best_tradeoff": {"rx_usecs": int, "rx_frames": int, "score": float, ...},
  },
  "affinity": {
    "irqbalance" : {"p99_us": float},
    "numa_pinned": {"p99_us": float},
    "percpu"     : {"p99_us": float},
  },
  "softirq": {
    "cpu0": {"NET_RX_delta": int, "NET_TX_delta": int},
    ...
  }
}
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


# ── sockperf summary parser ───────────────────────────────────────────────────

_P99_RE  = re.compile(r'Percentile\s+99\.0+\s*=\s*([\d.]+)')
_MIN_RE  = re.compile(r'<MIN>\s*observation\s*=\s*([\d.]+)')
_MAX_OBS = re.compile(r'<MAX>\s*observation\s*=\s*([\d.]+)')


def parse_p99(path: Path) -> float | None:
    if not path.exists():
        return None
    text = path.read_text(errors="replace")
    m = _P99_RE.search(text)
    return float(m.group(1)) if m else None


# ── iperf3 throughput parser ──────────────────────────────────────────────────

def parse_gbps(path: Path) -> float | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        bps  = (data.get("end", {})
                    .get("sum_received", {})
                    .get("bits_per_second", 0))
        return round(bps / 1e9, 3) if bps else None
    except Exception:
        return None


# ── softirq delta ─────────────────────────────────────────────────────────────

def compute_softirq_delta(
    t0_path: Path, t1_path: Path
) -> dict[str, dict[str, int]]:
    if not t0_path.exists() or not t1_path.exists():
        return {}
    t0 = json.loads(t0_path.read_text())
    t1 = json.loads(t1_path.read_text())
    result: dict[str, dict[str, int]] = {}
    for cpu in sorted(set(t0) | set(t1), key=lambda x: int(x[3:])):
        c0 = t0.get(cpu, {})
        c1 = t1.get(cpu, {})
        net_rx = c1.get("NET_RX", 0) - c0.get("NET_RX", 0)
        net_tx = c1.get("NET_TX", 0) - c0.get("NET_TX", 0)
        if net_rx > 0 or net_tx > 0:
            result[cpu] = {"NET_RX_delta": net_rx, "NET_TX_delta": net_tx}
    return result


# ── Trade-off score ───────────────────────────────────────────────────────────
# Score = throughput_fraction - latency_penalty
# throughput_fraction = gbps / max_gbps
# latency_penalty     = (p99 - min_p99) / min_p99
# Higher score = better trade-off

def compute_tradeoff_score(p99: float, gbps: float,
                            min_p99: float, max_gbps: float) -> float:
    if min_p99 == 0 or max_gbps == 0:
        return 0.0
    tput_frac    = gbps / max_gbps
    lat_penalty  = (p99 - min_p99) / min_p99
    return round(tput_frac - lat_penalty, 4)


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True)
    ap.add_argument("--rx-usecs",    required=True, help="Space-separated list")
    ap.add_argument("--rx-frames",   required=True, help="Space-separated list")
    ap.add_argument("--iface",       default="unknown")
    ap.add_argument("--output",      required=True)
    args = ap.parse_args()

    results_dir = Path(args.results_dir)
    rx_usecs    = list(map(int, args.rx_usecs.split()))
    rx_frames   = list(map(int, args.rx_frames.split()))

    # ── Build 2D grid ─────────────────────────────────────────────────────────
    lat_matrix  = [[None] * len(rx_frames) for _ in rx_usecs]
    tput_matrix = [[None] * len(rx_frames) for _ in rx_usecs]

    for ui, usecs in enumerate(rx_usecs):
        for fi, frames in enumerate(rx_frames):
            tag      = f"u{usecs}_f{frames}"
            lat_path = results_dir / f"sweep_{tag}_lat.txt"
            tpt_path = results_dir / f"sweep_{tag}_tput.json"

            p99  = parse_p99(lat_path)
            gbps = parse_gbps(tpt_path)

            lat_matrix[ui][fi]  = p99
            tput_matrix[ui][fi] = gbps

            if p99 is not None or gbps is not None:
                print(f"  u={usecs:>3} f={frames:>2} → p99={p99} µs  gbps={gbps}")

    # ── Find optimal points ───────────────────────────────────────────────────
    all_p99  = [v for row in lat_matrix  for v in row if v is not None]
    all_gbps = [v for row in tput_matrix for v in row if v is not None]
    min_p99  = min(all_p99)  if all_p99  else 0.0
    max_gbps = max(all_gbps) if all_gbps else 0.0

    best_lat      = None
    best_tput     = None
    best_tradeoff = None
    best_score    = -999.0

    for ui, usecs in enumerate(rx_usecs):
        for fi, frames in enumerate(rx_frames):
            p99  = lat_matrix[ui][fi]
            gbps = tput_matrix[ui][fi]
            if p99 is None or gbps is None:
                continue

            point = {"rx_usecs": usecs, "rx_frames": frames,
                     "p99_us": p99, "gbps": gbps}

            if p99 == min_p99:
                best_lat = point

            if gbps == max_gbps:
                best_tput = point

            score = compute_tradeoff_score(p99, gbps, min_p99, max_gbps)
            if score > best_score:
                best_score    = score
                best_tradeoff = {**point, "score": score}

    # ── IRQ affinity comparison ───────────────────────────────────────────────
    affinity: dict[str, dict] = {}
    for mode in ("irqbalance", "numa_pinned", "percpu"):
        path = results_dir / f"affinity_{mode}.txt"
        p99  = parse_p99(path)
        if p99 is not None:
            affinity[mode] = {"p99_us": p99}

    # ── softirq delta ─────────────────────────────────────────────────────────
    softirq = compute_softirq_delta(
        results_dir / "softirq_t0.json",
        results_dir / "softirq_t1.json",
    )

    # ── Assemble result ───────────────────────────────────────────────────────
    result = {
        "iface" : args.iface,
        "grid"  : {
            "rx_usecs"        : rx_usecs,
            "rx_frames"       : rx_frames,
            "latency_p99_us"  : lat_matrix,
            "throughput_gbps" : tput_matrix,
        },
        "optimal"  : {
            "min_p99"      : best_lat,
            "max_tput"     : best_tput,
            "best_tradeoff": best_tradeoff,
        },
        "affinity" : affinity,
        "softirq"  : softirq,
    }

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))

    print(f"\n[analyse] Optimal settings:")
    if best_lat:
        print(f"  Min latency  : rx-usecs={best_lat['rx_usecs']} "
              f"rx-frames={best_lat['rx_frames']} → p99={best_lat['p99_us']} µs")
    if best_tput:
        print(f"  Max throughput: rx-usecs={best_tput['rx_usecs']} "
              f"rx-frames={best_tput['rx_frames']} → {best_tput['gbps']} Gbps")
    if best_tradeoff:
        print(f"  Best tradeoff: rx-usecs={best_tradeoff['rx_usecs']} "
              f"rx-frames={best_tradeoff['rx_frames']} (score={best_tradeoff['score']})")
    print(f"[analyse] Result → {out}")


if __name__ == "__main__":
    main()
