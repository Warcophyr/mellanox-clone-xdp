#!/usr/bin/env python3
"""
05_interrupt/trex_sweep.py — single coalescing grid point with simultaneous
flood + latency probe via add_stream(). Called once per (rx_usecs, rx_frames)
pair by run.sh.
"""
import json, os, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))
from trex_runner import TRexRunner

def main():
    runner    = TRexRunner.from_env()
    rx_usecs  = int(os.environ["RX_USECS"])
    rx_frames = int(os.environ["RX_FRAMES"])
    duration  = int(os.environ.get("SWEEP_SECS", "15"))
    probe_pps = int(os.environ.get("SWEEP_RATE_PPS", "10000"))
    size_b    = int(os.environ.get("SWEEP_SIZE_B", "64"))
    output_dir= Path(os.environ.get("OUTPUT_DIR", "results"))
    output_dir.mkdir(parents=True, exist_ok=True)

    # One window: flood drives operating point, probe measures p99 simultaneously
    pt = runner.run_coalesce_point(
        rx_usecs=rx_usecs, rx_frames=rx_frames, size_b=size_b,
        probe_pps=probe_pps, flood_pps=5_000_000, duration=duration,
    )

    tag = f"u{rx_usecs}_f{rx_frames}"
    # Write files in the format analyse.py expects
    (output_dir / f"sweep_{tag}_lat.txt").write_text(
        f"[trex] rx-usecs={rx_usecs} rx-frames={rx_frames}\n"
        f"Percentile 99.000 = {pt['p99_us'] or 0:.3f} (usec)\n"
        f"drops: {pt['drops']}\n"
    )
    (output_dir / f"sweep_{tag}_tput.json").write_text(json.dumps({
        "end": {"sum_received": {"bits_per_second": (pt["gbps"] or 0) * 1e9}},
        "trex_source": True,
    }))
    print(f"[trex_sweep] {tag}  p99={pt['p99_us']} µs  gbps={pt['gbps']}")

if __name__ == "__main__":
    main()
