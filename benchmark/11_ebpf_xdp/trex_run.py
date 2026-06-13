#!/usr/bin/env python3
"""11_ebpf_xdp/trex_run.py — XDP hook overhead, RX ceiling, RSS validation, bounce."""
import argparse, json, os, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))
from trex_runner import TRexRunner

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ceiling", action="store_true")
    ap.add_argument("--xdp-tx",  action="store_true")
    ap.add_argument("--rss",     action="store_true")
    args = ap.parse_args()

    runner     = TRexRunner.from_env()
    state      = os.environ.get("XDP_STATE", "unknown")
    duration   = int(os.environ.get("DURATION", "20"))
    output_dir = Path(os.environ.get("OUTPUT_DIR", "results"))
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.ceiling:
        # XDP_DROP: wire-rate flood, report TX stats as RX ceiling
        from src.addons.sweep import SweepRunner
        r = runner.run_frame_size_sweep([64,128,256,512,1024,1500,9000], duration=duration)
        (output_dir / f"trex_ceiling_{state}.json").write_text(json.dumps(r, indent=2))
        print(f"[trex_run] ceiling {state}  64B={r[0]['tx_mpps']:.3f} Mpps")

    elif args.xdp_tx:
        r = runner.run_xdp_tx_latency(size_b=64, rate_pps=1_000, duration=duration)
        (output_dir / "sockperf_xdp_tx.txt").write_text(r.to_sockperf_txt())
        print(f"[trex_run] xdp_tx p99={r.p99_us} µs")

    elif args.rss:
        # 10k diverse flows for XDP counter RSS validation
        r = runner.run_rss_flood(duration=duration, flow_count=10_000, size_b=64)
        (output_dir / f"iperf_{state}.json").write_text(r.to_iperf3_json())
        print(f"[trex_run] rss flood  {r.tx_mpps} Mpps  drops={r.drops}")

    else:
        # Hook overhead: latency probe + background flood simultaneously
        lat = runner.run_latency_under_load(
            size_b=64, probe_pps=10_000, flood_pps=5_000_000,
            duration=duration, label=state,
        )
        tput = runner.run_throughput(size_b=1400, duration=duration, label=state)
        (output_dir / f"sockperf_{state}.txt").write_text(lat.to_sockperf_txt())
        (output_dir / f"iperf_{state}.json").write_text(tput.to_iperf3_json())
        print(f"[trex_run] {state}  p99={lat.p99_us} µs  tput={tput.tx_gbps} Gbps")

if __name__ == "__main__":
    main()
