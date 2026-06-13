#!/usr/bin/env python3
"""08_offloads/analyse.py + report.py in one file (analyse is trivial)"""
from __future__ import annotations
import argparse, json, re, sys
from pathlib import Path

_LIB = Path(__file__).parent.parent / "lib"
sys.path.insert(0, str(_LIB))


def _parse_iperf(p: Path) -> dict:
    if not p.exists(): return {}
    try:
        d = json.loads(p.read_text())
        end  = d.get("end", {})
        sent = end.get("sum_sent") or end.get("sum", {})
        return {"tx_gbps": round(sent.get("bits_per_second", 0) / 1e9, 3)}
    except Exception: return {}


_MPSTAT_RE = re.compile(
    r'^Average:\s+all\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)',
    re.MULTILINE
)

def _parse_mpstat(p: Path) -> dict:
    if not p.exists(): return {}
    m = _MPSTAT_RE.search(p.read_text(errors="replace"))
    if not m: return {}
    usr, nice, sys_, iowait, irq, soft = (float(m.group(i)) for i in range(1, 7))
    total = usr + nice + sys_ + irq + soft
    return {"cpu_total_pct": round(total, 2), "cpu_soft_pct": round(soft, 2)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True)
    ap.add_argument("--iface",       default="unknown")
    ap.add_argument("--output",      required=True)
    args = ap.parse_args()
    d = Path(args.results_dir)

    results: dict[str, dict] = {}
    for iperf_path in sorted(d.glob("offload_*.json")):
        label     = iperf_path.stem[len("offload_"):]
        iperf     = _parse_iperf(iperf_path)
        cpu       = _parse_mpstat(d / f"offload_{label}_cpu.txt")
        gbps      = iperf.get("tx_gbps", 0)
        cpu_pct   = cpu.get("cpu_total_pct", 0)
        per_gbps  = round(cpu_pct / gbps, 3) if gbps > 0 else None
        results[label] = {**iperf, **cpu, "cpu_per_gbps": per_gbps}
        print(f"[analyse] {label:25s}  {gbps} Gbps  CPU={cpu_pct:.1f}%  {per_gbps} %/Gbps")

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"iface": args.iface, "measurements": results}, indent=2))
    print(f"[analyse] → {out}")


if __name__ == "__main__":
    main()
