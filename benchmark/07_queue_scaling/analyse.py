#!/usr/bin/env python3
"""07_queue_scaling/analyse.py"""
from __future__ import annotations
import argparse, json, re, sys
from pathlib import Path
from statistics import mean, stdev


def _parse_iperf_gbps(path: Path) -> float | None:
    if not path.exists(): return None
    try:
        d = json.loads(path.read_text())
        end = d.get("end", {})
        sent = end.get("sum_sent") or end.get("sum", {})
        bps  = sent.get("bits_per_second", 0)
        return round(bps / 1e9, 3) if bps else None
    except Exception: return None


_ETHTOOL_RE = re.compile(r'^\s+(\S+):\s+(\d+)')

def _parse_ethtool_snap(path: Path) -> dict[str, int]:
    if not path.exists(): return {}
    r = {}
    for line in path.read_text().splitlines():
        m = _ETHTOOL_RE.match(line)
        if m: r[m.group(1)] = int(m.group(2))
    return r


def _rss_distribution(t0_path: Path, t1_path: Path) -> dict:
    """
    Extract per-queue RX packet counts from ethtool -S delta.
    Looks for counters matching patterns like: rx0_packets, rx_queue_0_packets, etc.
    """
    t0 = _parse_ethtool_snap(t0_path)
    t1 = _parse_ethtool_snap(t1_path)
    per_queue: dict[str, int] = {}

    queue_re = re.compile(
        r'^(?:rx_queue_(\d+)_packets|rx(\d+)_packets|queue_(\d+)_rx_packets)$'
    )
    for name in t1:
        m = queue_re.match(name)
        if m:
            qnum = next(g for g in m.groups() if g is not None)
            delta = t1[name] - t0.get(name, 0)
            if delta > 0:
                per_queue[f"q{qnum}"] = delta

    if not per_queue:
        return {"unavailable": True}

    vals  = list(per_queue.values())
    total = sum(vals)
    cv    = round(stdev(vals) / mean(vals), 4) if len(vals) > 1 and mean(vals) > 0 else 0

    return {
        "per_queue"  : per_queue,
        "total"      : total,
        "cv"         : cv,       # coefficient of variation: 0 = perfect balance
        "imbalanced" : cv > 0.30,
    }


def _ring_drops(t0_path: Path, t1_path: Path) -> int:
    t0 = _parse_ethtool_snap(t0_path)
    t1 = _parse_ethtool_snap(t1_path)
    return sum(
        t1.get(k, 0) - t0.get(k, 0)
        for k in t1 if "drop" in k.lower() and t1.get(k, 0) > t0.get(k, 0)
    )


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True)
    ap.add_argument("--iface",       default="unknown")
    ap.add_argument("--max-queues",  type=int, default=8)
    ap.add_argument("--output",      required=True)
    args = ap.parse_args()
    d = Path(args.results_dir)

    # Queue scaling
    queue_scaling: dict[str, dict] = {}
    for path in sorted(d.glob("qscale_q*.json")):
        q   = re.search(r'q(\d+)\.json', path.name)
        if not q: continue
        gbps = _parse_iperf_gbps(path)
        if gbps is not None:
            queue_scaling[f"q{q.group(1)}"] = {"queues": int(q.group(1)), "tx_gbps": gbps}

    # Scaling efficiency: gbps(N) / (N * gbps(1))
    baseline_gbps = queue_scaling.get("q1", {}).get("tx_gbps", 1) or 1
    for v in queue_scaling.values():
        eff = v["tx_gbps"] / (v["queues"] * baseline_gbps)
        v["efficiency"] = round(min(eff, 1.0), 3)

    # Ring buffer sweep
    ring_sweep: dict[str, dict] = {}
    for path in sorted(d.glob("ring_*.json")):
        ring = re.search(r'ring_(\d+)\.json', path.name)
        if not ring: continue
        r = int(ring.group(1))
        gbps  = _parse_iperf_gbps(path)
        drops = _ring_drops(d / f"ring_{r}_t0.txt", d / f"ring_{r}_t1.txt")
        if gbps is not None:
            ring_sweep[f"{r}"] = {"ring": r, "tx_gbps": gbps, "drops": drops}

    # RSS distribution
    rss = _rss_distribution(d / "rss_t0.txt", d / "rss_t1.txt")

    for k, v in queue_scaling.items():
        print(f"[analyse] {k:>4} queues  {v['tx_gbps']} Gbps  eff={v['efficiency']:.1%}")
    for k, v in ring_sweep.items():
        print(f"[analyse] ring {k:>4}  {v['tx_gbps']} Gbps  drops={v['drops']}")
    if not rss.get("unavailable"):
        print(f"[analyse] RSS CV={rss.get('cv', '?')}  "
              f"{'IMBALANCED' if rss.get('imbalanced') else 'balanced'}")

    result = {
        "iface"        : args.iface,
        "max_queues"   : args.max_queues,
        "queue_scaling": queue_scaling,
        "ring_sweep"   : ring_sweep,
        "rss"          : rss,
    }
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))
    print(f"[analyse] Result → {out}")


if __name__ == "__main__":
    main()
