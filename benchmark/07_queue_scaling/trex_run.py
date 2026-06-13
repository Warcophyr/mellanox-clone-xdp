#!/usr/bin/env python3
"""
07_queue_scaling/trex_run.py

--mode queue   : throughput at current queue count (called for each queue count)
--mode ring    : throughput at current ring depth
--mode rss     : 10k-flow flood for RSS distribution validation
"""
import argparse, json, os, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))
from trex_runner import TRexRunner

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["queue","ring","rss"], required=True)
    ap.add_argument("--label", default="")
    args = ap.parse_args()

    runner     = TRexRunner.from_env()
    duration   = int(os.environ.get("DURATION", "20"))
    output_dir = Path(os.environ.get("OUTPUT_DIR", "results"))
    output_dir.mkdir(parents=True, exist_ok=True)

    label = args.label or args.mode

    if args.mode == "rss":
        # 10k diverse flows to exercise the full RSS hash table
        r = runner.run_rss_flood(duration=duration, flow_count=10_000, size_b=64)
    else:
        r = runner.run_throughput(size_b=1400, duration=duration, label=label)

    (output_dir / f"{label}.json").write_text(r.to_iperf3_json())
    print(f"[trex_run] {label}  {r.tx_gbps} Gbps  drops={r.drops}")

if __name__ == "__main__":
    main()
