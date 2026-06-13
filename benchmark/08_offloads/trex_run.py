#!/usr/bin/env python3
"""08_offloads/trex_run.py — precise-rate traffic for offload CPU cost measurement."""
import json, os, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))
from trex_runner import TRexRunner

def main():
    runner     = TRexRunner.from_env()
    label      = os.environ.get("OFFLOAD_LABEL", "baseline")
    duration   = int(os.environ.get("DURATION", "20"))
    output_dir = Path(os.environ.get("OUTPUT_DIR", "results"))
    output_dir.mkdir(parents=True, exist_ok=True)

    r = runner.run_throughput(size_b=1400, duration=duration, label=label)
    # Writes iperf3-compat JSON; mpstat is captured separately by run.sh
    (output_dir / f"offload_{label}.json").write_text(r.to_iperf3_json())
    print(f"[trex_run] offload={label}  {r.tx_gbps} Gbps  drops={r.drops}")

if __name__ == "__main__":
    main()
