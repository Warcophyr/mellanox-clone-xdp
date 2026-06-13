#!/usr/bin/env python3
"""09_flamegraph/trex_run.py — background flood for each flamegraph scenario."""
import argparse, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))
from trex_runner import TRexRunner

SCENARIOS = {
    "rx_flood_64" : dict(size_b=64,   flow_count=1,     rate_percent=100),
    "tx_flood_64" : dict(size_b=64,   flow_count=1,     rate_percent=100),
    "rx_bulk_9k"  : dict(size_b=9000, flow_count=1,     rate_percent=100),
    "tx_tso_bulk" : dict(size_b=1400, flow_count=1,     rate_percent=100),
    "bidir_full"  : dict(size_b=1400, flow_count=8,     rate_percent=100),
}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", required=True, choices=SCENARIOS)
    ap.add_argument("--duration", type=int, default=35)
    args = ap.parse_args()
    TRexRunner.from_env().run_background(duration=args.duration, **SCENARIOS[args.scenario])

if __name__ == "__main__":
    main()
