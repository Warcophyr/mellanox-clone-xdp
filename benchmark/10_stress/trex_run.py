#!/usr/bin/env python3
"""10_stress/trex_run.py — long-run with live stats timeline via get_live_stats()."""
import os, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))
from trex_runner import TRexRunner

def main():
    runner       = TRexRunner.from_env()
    duration     = int(os.environ.get("STRESS_DURATION",   "1800"))
    poll_interval= int(os.environ.get("POLL_INTERVAL",     "10"))
    output_dir   = Path(os.environ.get("OUTPUT_DIR",        "results"))
    output_dir.mkdir(parents=True, exist_ok=True)

    runner.run_long_with_live_stats(
        duration      = duration,
        target_gbps   = 90.0,
        size_b        = 1400,
        poll_interval = poll_interval,
        output_path   = output_dir / "monitor.jsonl",
    )
    print(f"[trex_run] stress complete → {output_dir / 'monitor.jsonl'}")

if __name__ == "__main__":
    main()
