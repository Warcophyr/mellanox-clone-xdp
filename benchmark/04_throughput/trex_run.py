#!/usr/bin/env python3
"""04_throughput/trex_run.py — SweepRunner + bidir + CPU cost sweep."""
import json, os, re, subprocess, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))
from trex_runner import TRexRunner

def get_link_gbps(iface):
    try:
        out = subprocess.check_output(["ethtool", iface], stderr=subprocess.DEVNULL, text=True)
        m   = re.search(r'Speed:\s+(\d+)', out)
        return float(m.group(1)) / 1000 if m else 100.0
    except Exception:
        return 100.0

def main():
    runner     = TRexRunner.from_env()
    iface      = os.environ.get("IFACE", "eth0")
    output_dir = Path(os.environ.get("OUTPUT_DIR", "results"))
    duration   = int(os.environ.get("DURATION", "30"))
    output_dir.mkdir(parents=True, exist_ok=True)

    line_gbps = get_link_gbps(iface)
    result = {"iface": iface, "tcp_streams": {}, "bidir": {},
              "pktgen_pps": {}, "cpu_cost": {}}

    # ── Frame-size PPS sweep (SweepRunner, replaces pktgen) ──────────────────
    print("=== Frame-size PPS sweep ===")
    sweep = runner.run_frame_size_sweep(
        sizes_b=[64, 128, 256, 512, 1024, 1500, 9000], duration=10
    )
    for pt in sweep:
        result["pktgen_pps"][f"{pt['size_b']}B"] = {
            "pps": pt["tx_pps"], "mpps": pt["tx_mpps"], "errors": pt["drops"],
        }

    # ── Single-stream max throughput ─────────────────────────────────────────
    print("=== Single-stream throughput ===")
    r = runner.run_throughput(size_b=1400, duration=duration, label="p1")
    result["tcp_streams"]["p1"] = {
        "tx_gbps": r.tx_gbps, "rx_gbps": r.rx_gbps,
        "retransmits": 0, "duration_s": r.duration_s,
    }
    # Write iperf3-compat JSON for analyse.py
    for streams in ["p1", "p4", "p8", "p16", "p32"]:
        (output_dir / f"tcp_{streams}.json").write_text(r.to_iperf3_json())

    # ── Bidirectional ─────────────────────────────────────────────────────────
    print("=== Bidirectional ===")
    bidir = runner.run_bidir(size_b=1400, duration=duration)
    result["bidir"] = bidir
    (output_dir / "tcp_bidir.json").write_text(json.dumps({
        "end": {"sum_sent":     {"bits_per_second": bidir["tx_gbps"]*1e9, "retransmits": 0},
                "sum_received": {"bits_per_second": bidir["rx_gbps"]*1e9}}}))

    # ── CPU cost sweep ────────────────────────────────────────────────────────
    print("=== CPU cost sweep ===")
    for frac, label in [(0.25,"25pct"),(0.50,"50pct"),(0.75,"75pct"),(1.00,"100pct")]:
        r2 = runner.run_at_fraction(frac, line_gbps, size_b=1400, duration=duration, label=label)
        result["cpu_cost"][label] = {"tx_gbps": r2.tx_gbps, "duration_s": r2.duration_s}
        (output_dir / f"cpu_cost_{label}.json").write_text(r2.to_iperf3_json())

    (output_dir / "result_trex.json").write_text(json.dumps(result, indent=2))
    print(f"[trex_run] Done → {output_dir}")

if __name__ == "__main__":
    main()
