#!/usr/bin/env python3
"""01_hw_counters/trex_run.py — steady flood while ethtool counters are snapshotted."""
import json, os, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))
from trex_runner import TRexRunner

def main():
    runner     = TRexRunner.from_env()
    duration   = int(os.environ.get("DURATION", "30"))
    parallel   = int(os.environ.get("PARALLEL", "4"))
    output_dir = Path(os.environ.get("OUTPUT_DIR", "results"))
    output_dir.mkdir(parents=True, exist_ok=True)

    r = runner.run_throughput(size_b=1400, duration=duration, label="hw_counters_flood",
                              flow_count=parallel * 8)
    # Write iperf3-compat JSON for collect.py
    (output_dir / "iperf3.json").write_text(r.to_iperf3_json())
    print(f"[trex_run] {r.tx_gbps} Gbps  drops={r.drops}")

if __name__ == "__main__":
    main()
