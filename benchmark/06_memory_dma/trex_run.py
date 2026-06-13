#!/usr/bin/env python3
"""06_memory_dma/trex_run.py — traffic for NUMA, hugepage, and slab tests."""
import json, os, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))
from trex_runner import TRexRunner

def main():
    runner     = TRexRunner.from_env()
    label      = os.environ.get("TEST_LABEL", "generic")   # numa_local|numa_remote|hugepage_none|hugepage_2M|slab
    duration   = int(os.environ.get("DURATION", "30"))
    output_dir = Path(os.environ.get("OUTPUT_DIR", "results"))
    output_dir.mkdir(parents=True, exist_ok=True)

    r = runner.run_throughput(size_b=1400, duration=duration, label=label)
    (output_dir / f"{label}.json").write_text(r.to_iperf3_json())
    print(f"[trex_run] {label}  {r.tx_gbps} Gbps  drops={r.drops}")

if __name__ == "__main__":
    main()
