#!/usr/bin/env python3
"""
06_memory_dma/analyse.py

Parse DMA timing (bpftrace/ftrace), NUMA comparison iperf3 JSONs,
hugepage iperf3 JSONs, and slab T0/T1 snapshots.
"""
from __future__ import annotations
import argparse, json, re, sys
from pathlib import Path


# ── bpftrace histogram parser ─────────────────────────────────────────────────
# bpftrace prints histograms like:
# @dma_alloc_lat_ns:
# [256, 512)            1234 |@@@@@@@@@@|
# [512, 1K)              567 |@@@@|
_BPF_HIST_RE = re.compile(
    r'^\[(\d+(?:\.\d+)?[KMG]?),\s*(\d+(?:\.\d+)?[KMG]?)\)\s+(\d+)', re.MULTILINE
)
_BPF_COUNT_RE = re.compile(r'dma_(\w+)_count:\s+(\d+)')

def _bpf_unit(s: str) -> int:
    m = re.match(r'(\d+(?:\.\d+)?)([KMG]?)', s)
    v = float(m.group(1))
    u = {"K": 1e3, "M": 1e6, "G": 1e9}.get(m.group(2), 1.0)
    return int(v * u)

def parse_dma_bpftrace(path: Path) -> dict:
    if not path.exists():
        return {}
    text = path.read_text(errors="replace")
    if "UNAVAILABLE" in text:
        return {"unavailable": True}

    counts = {m.group(1): int(m.group(2)) for m in _BPF_COUNT_RE.finditer(text)}
    histograms: dict[str, list] = {}
    current_key = None
    for line in text.splitlines():
        if line.startswith("@dma_"):
            current_key = re.search(r'@(dma_\w+_lat_ns)', line)
            current_key = current_key.group(1) if current_key else None
            if current_key:
                histograms[current_key] = []
        elif current_key:
            m = _BPF_HIST_RE.match(line)
            if m:
                histograms[current_key].append({
                    "lo_ns" : _bpf_unit(m.group(1)),
                    "hi_ns" : _bpf_unit(m.group(2)),
                    "count" : int(m.group(3)),
                })

    return {"counts": counts, "histograms": histograms}


def _parse_iperf(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        d   = json.loads(path.read_text())
        end = d.get("end", {})
        if d.get("single_numa"):
            return {"single_numa": True}
        sent = end.get("sum_sent") or end.get("sum", {})
        return {"tx_gbps": round(sent.get("bits_per_second", 0) / 1e9, 3)} if sent else {}
    except Exception:
        return {}


def parse_slab_delta(t0_path: Path, t1_path: Path) -> list[dict]:
    """Return caches where num_objs grew meaningfully (potential leaks)."""
    if not t0_path.exists() or not t1_path.exists():
        return []
    t0 = json.loads(t0_path.read_text())
    t1 = json.loads(t1_path.read_text())
    leaks = []
    for name, s1 in t1.items():
        s0 = t0.get(name, {"active_objs": 0, "num_objs": 0})
        delta = s1["num_objs"] - s0["num_objs"]
        if delta > 100:  # filter noise
            leaks.append({"cache": name, "t0": s0["num_objs"],
                          "t1": s1["num_objs"], "delta": delta})
    return sorted(leaks, key=lambda x: -x["delta"])[:20]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True)
    ap.add_argument("--iface",       default="unknown")
    ap.add_argument("--output",      required=True)
    args = ap.parse_args()
    d = Path(args.results_dir)

    numa_local  = _parse_iperf(d / "numa_local.json")
    numa_remote = _parse_iperf(d / "numa_remote.json")

    # Compute NUMA penalty
    numa_penalty = None
    if numa_local.get("tx_gbps") and numa_remote.get("tx_gbps") and \
       not numa_remote.get("single_numa"):
        numa_penalty = round(
            (numa_local["tx_gbps"] - numa_remote["tx_gbps"]) / numa_local["tx_gbps"] * 100, 1
        )

    hp_none = _parse_iperf(d / "hugepage_none.json")
    hp_2m   = _parse_iperf(d / "hugepage_2M.json")

    slab_delta = parse_slab_delta(d / "slab_t0.json", d / "slab_t1.json")
    dma_timing = parse_dma_bpftrace(d / "dma_timing.txt")

    result = {
        "iface"       : args.iface,
        "dma_timing"  : dma_timing,
        "numa"        : {
            "local_gbps"  : numa_local.get("tx_gbps"),
            "remote_gbps" : numa_remote.get("tx_gbps"),
            "single_node" : bool(numa_remote.get("single_numa")),
            "penalty_pct" : numa_penalty,
        },
        "hugepage"    : {
            "none_gbps" : hp_none.get("tx_gbps"),
            "2m_gbps"   : hp_2m.get("tx_gbps"),
        },
        "slab_delta"  : slab_delta,
    }

    print(f"[analyse] NUMA local={numa_local.get('tx_gbps')} "
          f"remote={numa_remote.get('tx_gbps')} penalty={numa_penalty}%")
    print(f"[analyse] Hugepage none={hp_none.get('tx_gbps')} 2M={hp_2m.get('tx_gbps')}")
    print(f"[analyse] Slab: {len(slab_delta)} growing caches")

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))
    print(f"[analyse] Result → {out}")


if __name__ == "__main__":
    main()
