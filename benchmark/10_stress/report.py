#!/usr/bin/env python3
"""10_stress/report.py — parse all stress results and render REPORT.md."""
from __future__ import annotations
import argparse, json, re, sys
from pathlib import Path
from statistics import mean, stdev

_LIB = Path(__file__).parent.parent / "lib"
sys.path.insert(0, str(_LIB))
from baseline import ThresholdConfig, compare, load_baseline, overall_status, save_baseline
from report   import md_table, render_report, write_report, write_meta


# ── Monitor JSONL parser ──────────────────────────────────────────────────────

def parse_monitor_log(path: Path) -> dict:
    """
    Read monitor.jsonl and compute:
      - total drop delta (across all drop counters)
      - zero_to_nonzero events
      - time-series of total drops for charting
    """
    if not path.exists():
        return {}

    records = []
    for line in path.read_text().splitlines():
        try:
            records.append(json.loads(line))
        except Exception:
            continue

    if len(records) < 2:
        return {"n_records": len(records)}

    # Identify drop counter names from first snapshot
    first_counters = records[0]["counters"]
    drop_keys = [k for k in first_counters if "drop" in k.lower()]

    # Compute total drops at each timestamp
    timeline = []
    for rec in records:
        total = sum(rec["counters"].get(k, 0) for k in drop_keys)
        timeline.append({"ts": rec["ts"], "total_drops": total})

    total_drop_delta = timeline[-1]["total_drops"] - timeline[0]["total_drops"]

    # Zero-to-nonzero on any error counter
    z2nz = []
    for k in first_counters:
        v0 = records[0]["counters"].get(k, 0)
        v1 = records[-1]["counters"].get(k, 0)
        if v0 == 0 and v1 > 0 and k not in drop_keys:
            z2nz.append({"counter": k, "value": v1})

    return {
        "n_records"        : len(records),
        "duration_approx_s": len(records) * 10,  # approx from poll interval
        "total_drop_delta" : total_drop_delta,
        "zero_to_nonzero"  : z2nz,
        "timeline"         : timeline[::max(1, len(timeline)//30)],  # max 30 points
    }


# ── Link flap parser ──────────────────────────────────────────────────────────

def parse_flap_log(path: Path) -> dict:
    if not path.exists():
        return {}
    records = []
    for line in path.read_text().splitlines():
        try:
            records.append(json.loads(line))
        except Exception:
            continue

    times     = [r["recovery_ms"] for r in records if r.get("recovery_ms") is not None]
    timeouts  = sum(1 for r in records if r.get("timeout"))

    return {
        "n_flaps"       : len(records),
        "timeouts"       : timeouts,
        "recovery_min_ms": min(times) if times else None,
        "recovery_avg_ms": round(mean(times), 1) if times else None,
        "recovery_max_ms": max(times) if times else None,
        "recovery_p99_ms": sorted(times)[int(len(times)*0.99)] if len(times) > 1 else None,
    }


# ── Slab leak parser ──────────────────────────────────────────────────────────

def parse_slab_delta(t0_path: Path, t1_path: Path) -> list[dict]:
    if not t0_path.exists() or not t1_path.exists():
        return []
    t0 = json.loads(t0_path.read_text())
    t1 = json.loads(t1_path.read_text())
    leaks = []
    for name, v1 in t1.items():
        v0 = t0.get(name, 0)
        delta = v1 - v0
        if delta > 500:
            leaks.append({"cache": name, "t0": v0, "t1": v1, "delta": delta})
    return sorted(leaks, key=lambda x: -x["delta"])[:15]


# ── Lock contention parser ────────────────────────────────────────────────────
# perf lock report output:
#  Name                    acquired  contended   total wait (ns)   max wait (ns)   avg wait (ns)
#  &rq->lock:                 12345       1234         123456789         12345678          12345

_LOCK_RE = re.compile(
    r'^(\S+.*?\S)\s{2,}(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)',
)

def parse_lock_report(path: Path) -> list[dict]:
    if not path.exists():
        return []
    text = path.read_text(errors="replace")
    if "NOT_AVAILABLE" in text:
        return []
    locks = []
    for line in text.splitlines():
        m = _LOCK_RE.match(line.strip())
        if m and m.group(3) != "0":  # only contended locks
            acquired   = int(m.group(2))
            contended  = int(m.group(3))
            avg_wait   = int(m.group(6))
            contention = round(contended / acquired * 100, 2) if acquired else 0
            locks.append({
                "name"         : m.group(1).strip(),
                "acquired"     : acquired,
                "contended"    : contended,
                "contention_pct": contention,
                "avg_wait_ns"  : avg_wait,
            })
    return sorted(locks, key=lambda x: -x["contention_pct"])[:10]


# ── ASCII drop timeline ───────────────────────────────────────────────────────

def ascii_drop_timeline(timeline: list[dict], width: int = 50) -> str:
    if not timeline:
        return ""
    vals  = [t["total_drops"] for t in timeline]
    hi    = max(vals)
    if hi == 0:
        return "```\n(no drops)\n```"
    lines = ["```"]
    for i, t in enumerate(timeline):
        bar_len = int(t["total_drops"] / hi * width)
        bar     = "█" * bar_len
        lines.append(f"{i*10:>5}s │{bar:<{width}}│ {t['total_drops']:,}")
    lines.append("```")
    return "\n".join(lines)


# ── Section builders ──────────────────────────────────────────────────────────

def longrun_section(mon: dict) -> str:
    if not mon:
        return "## Long-Run Packet Loss\n\n_No monitor data found._\n"

    drops  = mon.get("total_drop_delta", 0)
    n_recs = mon.get("n_records", 0)
    z2nz   = mon.get("zero_to_nonzero", [])
    icon   = "✅" if drops == 0 else ("⚠️" if drops < 100 else "🔴")

    rows = [
        ["Monitoring samples", str(n_recs)],
        ["Approximate duration", f"~{mon.get('duration_approx_s', 0)}s"],
        ["Total drops (delta)", f"{icon} {drops:,}"],
        ["Zero → non-zero counters", str(len(z2nz))],
    ]

    out = "## Long-Run Packet Loss\n\n" + md_table(["Metric", "Value"], rows)

    if z2nz:
        z_rows = [[f"`{e['counter']}`", f"{e['value']:,}"] for e in z2nz]
        out += "\n\n### Zero → Non-Zero Counters\n\n" + md_table(["Counter", "Final value"], z_rows)

    timeline = mon.get("timeline", [])
    if timeline and drops > 0:
        out += "\n\n### Drop Counter Timeline\n\n" + ascii_drop_timeline(timeline)

    return out


def flap_section(flap: dict) -> str:
    if not flap:
        return ""
    n        = flap.get("n_flaps", 0)
    timeouts = flap.get("timeouts", 0)
    t_icon   = "🔴" if timeouts > 0 else "✅"
    rows = [
        ["Total flaps", str(n)],
        ["Timeouts (>10s)",   f"{t_icon} {timeouts}"],
        ["Min recovery",      f"{flap.get('recovery_min_ms','—')} ms"],
        ["Avg recovery",      f"{flap.get('recovery_avg_ms','—')} ms"],
        ["Max recovery",      f"{flap.get('recovery_max_ms','—')} ms"],
        ["p99 recovery",      f"{flap.get('recovery_p99_ms','—')} ms"],
    ]
    note = ("> High max/p99 recovery times indicate slow driver re-init or "
            "firmware reload. Check `dmesg_flap.txt` for WARNs.")
    return "## Link Flap Recovery\n\n" + md_table(["Metric", "Value"], rows) + f"\n\n{note}\n"


def slab_section(leaks: list) -> str:
    if not leaks:
        return "## Slab Memory Leak Check\n\n✅ No significant slab growth detected.\n"
    rows = [[f"`{l['cache']}`", f"{l['t0']:,}", f"{l['t1']:,}", f"+{l['delta']:,}"]
            for l in leaks]
    return (
        "## Slab Memory Leak Check\n\n"
        "> Caches that grew by > 500 objects during the traffic run.\n\n"
        + md_table(["Slab cache", "Before", "After", "Δ"], rows)
    )


def lock_section(locks: list) -> str:
    if not locks:
        return "## Lock Contention\n\n> `perf lock` not available or no contention detected.\n"
    rows = []
    for l in locks:
        icon = "🔴" if l["contention_pct"] > 5 else ("⚠️" if l["contention_pct"] > 1 else "")
        rows.append([
            f"`{l['name'][:40]}`",
            f"{l['acquired']:,}",
            f"{icon} {l['contention_pct']:.1f}%",
            f"{l['avg_wait_ns']:,} ns",
        ])
    return (
        "## Lock Contention (top-10 contended)\n\n"
        "> Locks with >1% contention rate deserve investigation — they indicate hot-path serialisation.\n\n"
        + md_table(["Lock", "Acquired", "Contention%", "Avg wait"], rows)
    )


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True)
    ap.add_argument("--iface",       default="unknown")
    ap.add_argument("--baseline",    required=True)
    ap.add_argument("--env",         required=True)
    ap.add_argument("--output",      required=True)
    ap.add_argument("--result-out",  default=None)
    ap.add_argument("--meta",        default=None)
    args = ap.parse_args()

    d      = Path(args.results_dir)
    env    = json.loads(Path(args.env).read_text())

    mon    = parse_monitor_log(d / "monitor.jsonl")
    flap   = parse_flap_log(d / "flap_recovery.jsonl")
    leaks  = parse_slab_delta(d / "memleak_slab_t0.json", d / "memleak_slab_t1.json")
    locks  = parse_lock_report(d / "lock_report.txt")

    # Persist parsed result
    result = {"iface": args.iface, "longrun": mon, "flap": flap,
              "slab_leaks": leaks, "lock_contention": locks}
    if args.result_out:
        Path(args.result_out).write_text(json.dumps(result, indent=2))

    # Baseline
    current: dict[str, float] = {}
    drops = mon.get("total_drop_delta")
    if drops is not None: current["longrun_drops"] = float(drops)
    avg_rec = flap.get("recovery_avg_ms")
    if avg_rec: current["flap_recovery_avg_ms"] = avg_rec

    THRESHOLDS = {
        "longrun_drops"        : ThresholdConfig(direction="higher_is_bad", warn=0.0,  regress=1.0),
        "flap_recovery_avg_ms" : ThresholdConfig(direction="higher_is_bad", warn=10.0, regress=30.0),
    }

    baseline_path = Path(args.baseline)
    base_data     = load_baseline(baseline_path)
    is_baseline   = not bool(base_data)
    regressions   = []

    if is_baseline:
        save_baseline(baseline_path, current)
    else:
        regressions = compare(current, base_data, THRESHOLDS)

    drops_str = str(drops) if drops is not None else "?"
    key_metric = f"{drops_str} drops in {mon.get('duration_approx_s','?')}s"

    sections = [
        longrun_section(mon),
        flap_section(flap),
        slab_section(leaks),
        lock_section(locks),
    ]
    if is_baseline:
        sections.insert(0, "## ℹ️ Baseline Run\n\nSaved as new baseline.")

    report = render_report("10_stress", "Stress & Stability Report",
                           [s for s in sections if s], regressions, env)
    write_report(args.output, report)

    status = "BASELINE" if is_baseline else overall_status(regressions)
    if args.meta:
        write_meta(args.meta, "10_stress", status, key_metric)
    print(f"[report] Status: {status} | drops={drops_str}")


if __name__ == "__main__":
    main()
