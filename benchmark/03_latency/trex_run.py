#!/usr/bin/env python3
"""
03_latency/trex_run.py — latency measurement using add_stream() + set_warmup().

Scenarios:
  Class 1: no-load (1 msg/s)          — pure driver latency floor
  Class 2: latency under flood load   — flood + probe simultaneously
  Class 3: interrupt vs busy-poll     — same as class 2, sysctl toggled by run.sh
"""
import json, os, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))
import trex_py_venti

def main():
    runner     = TRexRunner.from_env()
    duration   = int(os.environ.get("DURATION",    "30"))
    output_dir = Path(os.environ.get("OUTPUT_DIR", "results"))
    busy_poll  = os.environ.get("BUSY_POLL", "0") == "1"
    output_dir.mkdir(parents=True, exist_ok=True)

    scenarios = []

    # Class 1: no-load at multiple frame sizes
    for size in [64, 512, 1400, 4096]:
        r = runner.run_latency(size_b=size, rate_pps=1,
                               duration=duration, label=f"no_load_{size}B")
        scenarios.append(r)

    # Class 2 & 3: latency under flood load (flood=5Mpps, probe=1k pps)
    suffix = "busypoll" if busy_poll else "interrupt"
    for size, probe_pps, label in [
        (64,   10_000, f"{suffix}_10k_64B"),
        (1400, 10_000, f"{suffix}_10k_1400B"),
        (64,  100_000, f"loaded_100k_64B"),
    ]:
        r = runner.run_latency_under_load(
            size_b=size, probe_pps=probe_pps,
            flood_pps=5_000_000, duration=duration, label=label,
        )
        r.busy_poll = busy_poll  # type: ignore[attr-defined]
        scenarios.append(r)

    # Write sockperf-format files for analyse.py (one per scenario)
    for r in scenarios:
        (output_dir / f"summary_{r.label}.txt").write_text(r.to_sockperf_txt())

    # Write unified result JSON
    result = {
        "iface"    : os.environ.get("IFACE", ""),
        "scenarios": {
            r.label: {
                "source"    : "trex",
                "n_samples" : r.total_pkts,
                "msg_size_B": r.size_b,
                "busy_poll" : getattr(r, "busy_poll", False),
                "no_load"   : r.rate_pps <= 1,
                "percentiles": {
                    "min"   : r.min_us,   "p50"   : r.p50_us,
                    "p90"   : r.p90_us,   "p95"   : r.p95_us,
                    "p99"   : r.p99_us,   "p99_9" : r.p999_us,
                    "max"   : r.max_us,
                },
                "drops": r.drops,
            } for r in scenarios
        }
    }
    (output_dir / "result.json").write_text(json.dumps(result, indent=2))
    print(f"[trex_run] {len(scenarios)} scenarios written → {output_dir}")

if __name__ == "__main__":
    main()
