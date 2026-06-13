#!/usr/bin/env python3
"""
02_cpu_microarch/trex_run.py — background traffic for perf stat scenarios.

Called from run.sh as a background job:
    python3 trex_run.py --scenario rx_burst_64 &
    TREX_PID=$!
    perf stat ... -- sleep $PERF_SECS
    kill $TREX_PID

The --scenario arg selects the traffic pattern so perf measures the right path.
"""
import argparse, os, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))
from trex_runner import TRexRunner

SCENARIOS = {
    "rx_burst_64"   : dict(size_b=64,   flow_count=1,      rate_percent=100),
    "tx_burst_64"   : dict(size_b=64,   flow_count=1,      rate_percent=100),
    "bidir_mixed"   : dict(size_b=1400, flow_count=8,      rate_percent=100),
    "tx_jumbo_9k"   : dict(size_b=9000, flow_count=1,      rate_percent=100),
    "tx_many_flows" : dict(size_b=1400, flow_count=32_000, rate_percent=80),
}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", required=True, choices=SCENARIOS)
    ap.add_argument("--duration", type=int, default=60)
    args = ap.parse_args()

    runner  = TRexRunner.from_env()
    kwargs  = SCENARIOS[args.scenario]
    runner.run_background(duration=args.duration, **kwargs)

if __name__ == "__main__":
    main()
