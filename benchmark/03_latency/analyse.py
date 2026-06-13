#!/usr/bin/env python3
"""
03_latency/analyse.py

Parse sockperf output files (summary + optional full-log CSV) and produce
result.json with full percentile distributions per scenario.

Two parsing strategies, tried in order:
  1. full-log CSV  — raw per-sample latencies → we compute our own percentiles
  2. summary txt   — parse the percentile lines sockperf prints to stdout

Output schema (result.json):
{
  "iface": "eth0",
  "scenarios": {
    "<name>": {
      "source"       : "fulllog" | "summary",
      "n_samples"    : int,
      "msg_size_B"   : int | null,    # parsed from scenario name if possible
      "rate_mps"     : int | null,
      "busy_poll"    : bool,
      "percentiles"  : {
        "min": float, "p50": float, "p75": float,
        "p90": float, "p95": float, "p99": float,
        "p99_9": float, "p99_99": float, "max": float
      },
      "histogram"    : [[bucket_usec, count], ...]   # 20-bucket histogram
    }
  }
}
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from pathlib import Path


# ── Scenario name metadata extraction ────────────────────────────────────────

_SIZE_RE    = re.compile(r'(\d+)B')
_RATE_RE    = re.compile(r'(\d+)k_')         # e.g. 10k_, 100k_
_BUSYPOLL_RE= re.compile(r'^busypoll_')
_NOLOAD_RE  = re.compile(r'^no_load_')
_LOADED_RE  = re.compile(r'^loaded_|^interrupt_|^busypoll_')


def _parse_scenario_meta(name: str) -> dict:
    size_m = _SIZE_RE.search(name)
    rate_m = _RATE_RE.search(name)
    return {
        "msg_size_B" : int(size_m.group(1)) if size_m else None,
        "rate_mps"   : int(rate_m.group(1)) * 1000 if rate_m else (1 if _NOLOAD_RE.match(name) else None),
        "busy_poll"  : bool(_BUSYPOLL_RE.match(name)),
        "no_load"    : bool(_NOLOAD_RE.match(name)),
    }


# ── Full-log CSV parser ───────────────────────────────────────────────────────
# sockperf --full-log format (versions vary):
#   Line formats observed:
#     "  87.000 usec"
#     "3.123,87.000"          (timestamp_us, latency_us)
#     "87.000"

_LATENCY_LINE_RE = re.compile(
    r'^\s*(?:[\d.]+,)?([\d.]+)\s*(?:usec)?\s*$'
)

def parse_fulllog(path: Path) -> list[float] | None:
    """Return list of latency values (µs) or None if unparseable."""
    samples: list[float] = []
    try:
        for line in path.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith('#') or 'usec' in line.lower() and '=' in line:
                continue
            m = _LATENCY_LINE_RE.match(line)
            if m:
                samples.append(float(m.group(1)))
    except Exception:
        return None
    return samples if len(samples) > 10 else None


# ── Summary txt parser ────────────────────────────────────────────────────────
# Parses the percentile table sockperf writes to stdout

_PERCENTILE_RE = re.compile(
    r'Percentile\s+([\d.]+)\s*=\s*([\d.]+)'
)
_MAX_RE = re.compile(r'<MAX>\s*observation\s*=\s*([\d.]+)')
_MIN_RE = re.compile(r'<MIN>\s*observation\s*=\s*([\d.]+)')
_OBS_RE = re.compile(r'([\d,]+)\s+observations')

def parse_summary(path: Path) -> dict | None:
    """
    Returns dict with percentile keys or None if file is missing / unparseable.
    Keys: min p50 p75 p90 p95 p99 p99_9 p99_99 max n_samples
    """
    if not path.exists():
        return None

    text = path.read_text(errors="replace")

    pcts: dict[str, float] = {}
    for m in _PERCENTILE_RE.finditer(text):
        pct_val = float(m.group(1))
        lat_val = float(m.group(2))
        key = {
            50.0: "p50", 75.0: "p75", 90.0: "p90",
            95.0: "p95", 99.0: "p99", 99.9: "p99_9", 99.99: "p99_99"
        }.get(pct_val)
        if key:
            pcts[key] = lat_val

    mx = _MAX_RE.search(text)
    mn = _MIN_RE.search(text)
    ob = _OBS_RE.search(text)

    if mx: pcts["max"] = float(mx.group(1))
    if mn: pcts["min"] = float(mn.group(1))

    n = int(ob.group(1).replace(",", "")) if ob else 0
    return {"percentiles": pcts, "n_samples": n} if pcts else None


# ── Percentile computation from raw samples ───────────────────────────────────

def compute_percentiles(samples: list[float]) -> dict[str, float]:
    s = sorted(samples)
    n = len(s)

    def pct(p: float) -> float:
        idx = (p / 100.0) * (n - 1)
        lo  = int(idx)
        hi  = min(lo + 1, n - 1)
        return round(s[lo] + (idx - lo) * (s[hi] - s[lo]), 3)

    return {
        "min"   : round(s[0],    3),
        "p50"   : pct(50.0),
        "p75"   : pct(75.0),
        "p90"   : pct(90.0),
        "p95"   : pct(95.0),
        "p99"   : pct(99.0),
        "p99_9" : pct(99.9),
        "p99_99": pct(99.99),
        "max"   : round(s[-1],   3),
    }


def build_histogram(samples: list[float], n_buckets: int = 20) -> list[list]:
    """Return [[bucket_upper_usec, count], ...] with log-scaled buckets."""
    if not samples:
        return []
    lo  = max(0.1, min(samples))
    hi  = max(samples)
    if lo >= hi:
        return [[hi, len(samples)]]

    log_lo = math.log10(lo)
    log_hi = math.log10(hi)
    edges  = [10 ** (log_lo + i * (log_hi - log_lo) / n_buckets)
              for i in range(1, n_buckets + 1)]
    edges[-1] = hi + 1e-9  # ensure last bucket captures max

    counts = [0] * n_buckets
    for v in samples:
        for i, edge in enumerate(edges):
            if v <= edge:
                counts[i] += 1
                break

    return [[round(edges[i], 3), counts[i]] for i in range(n_buckets) if counts[i] > 0]


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True,
                    help="Directory containing summary_*.txt and raw_*.csv files")
    ap.add_argument("--iface",       default="unknown")
    ap.add_argument("--output",      required=True)
    args = ap.parse_args()

    results_dir = Path(args.results_dir)
    summary_files = sorted(results_dir.glob("summary_*.txt"))

    if not summary_files:
        sys.exit(f"[error] No summary_*.txt files found in {results_dir}")

    scenarios: dict[str, dict] = {}

    for sf in summary_files:
        # "summary_no_load_64B.txt" → "no_load_64B"
        name = sf.stem[len("summary_"):]
        meta = _parse_scenario_meta(name)

        # Try full-log first
        raw_path = results_dir / f"raw_{name}.csv"
        samples  = parse_fulllog(raw_path)

        if samples:
            percentiles = compute_percentiles(samples)
            histogram   = build_histogram(samples)
            source      = "fulllog"
            n_samples   = len(samples)
        else:
            parsed = parse_summary(sf)
            if not parsed:
                print(f"[warn] Could not parse {sf} — skipping", file=sys.stderr)
                continue
            percentiles = parsed["percentiles"]
            histogram   = []
            source      = "summary"
            n_samples   = parsed["n_samples"]

        scenarios[name] = {
            "source"    : source,
            "n_samples" : n_samples,
            **meta,
            "percentiles": percentiles,
            "histogram"  : histogram,
        }

        p = percentiles
        print(
            f"[analyse] {name:30s}  "
            f"min={p.get('min','?'):>7}  "
            f"p50={p.get('p50','?'):>7}  "
            f"p99={p.get('p99','?'):>7}  "
            f"max={p.get('max','?'):>7}  µs"
            f"  [{source}, n={n_samples:,}]"
        )

    result = {"iface": args.iface, "scenarios": scenarios}
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))
    print(f"[analyse] Result → {out}  ({len(scenarios)} scenarios)")


if __name__ == "__main__":
    main()
