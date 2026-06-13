#!/usr/bin/env python3
"""
10_stress/monitor.py

Background process: polls ethtool -S every --interval seconds and appends
JSON lines to --output. Runs until killed (SIGTERM / SIGINT).

Each line:
  {"ts": "<iso>", "counters": {"rx_dropped": N, ...}}
"""
from __future__ import annotations
import argparse, json, re, signal, subprocess, sys, time
from datetime import datetime, timezone
from pathlib import Path

_ETHTOOL_RE = re.compile(r'^\s+(\S+):\s+(\d+)')
running = True


def snapshot(iface: str) -> dict[str, int]:
    try:
        out = subprocess.check_output(
            ["ethtool", "-S", iface], stderr=subprocess.DEVNULL, text=True
        )
    except subprocess.CalledProcessError:
        return {}
    result: dict[str, int] = {}
    for line in out.splitlines():
        m = _ETHTOOL_RE.match(line)
        if m:
            result[m.group(1)] = int(m.group(2))
    return result


def _sig(sig, frame) -> None:
    global running
    running = False


def main() -> None:
    global running
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface",    required=True)
    ap.add_argument("--interval", type=float, default=10.0)
    ap.add_argument("--output",   required=True)
    args = ap.parse_args()

    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT,  _sig)

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)

    print(f"[monitor] Polling {args.iface} every {args.interval}s → {out}", flush=True)

    with out.open("w") as f:
        while running:
            ts      = datetime.now(timezone.utc).isoformat()
            counts  = snapshot(args.iface)
            record  = {"ts": ts, "counters": counts}
            f.write(json.dumps(record) + "\n")
            f.flush()

            # Wait, but break early on signal
            deadline = time.monotonic() + args.interval
            while running and time.monotonic() < deadline:
                time.sleep(0.25)

    print("[monitor] Stopped.", flush=True)


if __name__ == "__main__":
    main()
