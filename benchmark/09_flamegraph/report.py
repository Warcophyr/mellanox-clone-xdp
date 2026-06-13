#!/usr/bin/env python3
"""09_flamegraph/report.py — parse perf top-10 files and link to SVGs."""
from __future__ import annotations
import argparse, json, re, sys
from pathlib import Path

_LIB = Path(__file__).parent.parent / "lib"
sys.path.insert(0, str(_LIB))
from report import md_table, render_report, write_report, write_meta

SCENARIOS = [
    ("rx_flood_64",  "RX flood 64B",          "NAPI poll, descriptor fetch, skb alloc"),
    ("tx_flood_64",  "TX flood 64B",           "TX queue, completion cleanup"),
    ("rx_bulk_9k",   "RX bulk 9K jumbo",       "GRO path, scatter-gather"),
    ("tx_tso_bulk",  "TX TSO bulk",            "TSO segmentation path"),
    ("bidir_full",   "Bidirectional full rate", "Full TX+RX hot path combined"),
]

# Parse perf report --stdio output (top-10 lines like "  12.34%  [kernel] foo_bar")
_PERF_RE = re.compile(r'^\s+([\d.]+)%\s+\S+\s+\[(\S+)\]\s+(\S+)')

def parse_top10(path: Path) -> list[dict]:
    if not path.exists():
        return []
    results = []
    for line in path.read_text(errors="replace").splitlines():
        m = _PERF_RE.match(line)
        if m:
            results.append({
                "pct"   : float(m.group(1)),
                "module": m.group(2),
                "symbol": m.group(3),
            })
    return results[:10]


def scenario_section(name: str, label: str, hotpath_note: str,
                     top10: list[dict], has_svg: bool, script_dir: Path) -> str:
    title = f"### {label} (`{name}`)"
    note  = f"_Hot-path focus: {hotpath_note}_"

    if not top10:
        body = "> No perf data available for this scenario.\n"
    else:
        rows = []
        for i, s in enumerate(top10, 1):
            module_icon = "🐧" if "kernel" in s["module"] else "📦"
            rows.append([str(i), f"{s['pct']:.2f}%", f"`{s['symbol']}`",
                         f"{module_icon} {s['module']}"])
        body = md_table(["#", "CPU%", "Symbol", "Module"], rows)

    svg_line = ""
    if has_svg:
        svg_path = script_dir / f"{name}.svg"
        if svg_path.exists():
            svg_line = f"\n\n📊 [Open flamegraph SVG]({name}.svg)\n"
        else:
            svg_line = "\n\n> SVG not generated (FlameGraph scripts not found).\n"

    return f"{title}\n\n{note}\n\n{body}{svg_line}"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir",       required=True)
    ap.add_argument("--script-dir",        required=True)
    ap.add_argument("--flamegraph-avail",  type=int, default=0)
    ap.add_argument("--env",               required=True)
    ap.add_argument("--output",            required=True)
    ap.add_argument("--meta",              default=None)
    args = ap.parse_args()

    results_dir = Path(args.results_dir)
    script_dir  = Path(args.script_dir)
    env         = json.loads(Path(args.env).read_text())
    fg_avail    = bool(args.flamegraph_avail)

    scenario_sections = []
    total_scenarios   = 0
    has_data          = False

    for name, label, note in SCENARIOS:
        top10 = parse_top10(results_dir / f"top10_{name}.txt")
        if top10:
            has_data = True
            total_scenarios += 1
        scenario_sections.append(
            scenario_section(name, label, note, top10, fg_avail, script_dir)
        )

    svg_note = (
        "## Flamegraph SVGs\n\n"
        + ("✅ SVG files generated alongside this report (`*.svg`).\n"
           "Open them in a browser for interactive drill-down."
           if fg_avail else
           "⚠️ FlameGraph scripts were not found. Install them to enable SVG generation:\n"
           "```bash\n"
           "git clone https://github.com/brendangregg/FlameGraph /usr/local/FlameGraph\n"
           "```\n"
           "The `perf.data` files are stored in `results/` and can be processed manually.")
    )

    sections = [
        svg_note,
        "## Top-10 CPU Consumers per Scenario\n\n" + "\n\n---\n\n".join(scenario_sections),
    ]

    key_metric = (f"{total_scenarios}/5 scenarios recorded"
                  + (" + SVGs" if fg_avail else " (no SVGs)"))

    report = render_report("09_flamegraph", "Flamegraph & CPU Hot-Path Report",
                           sections, [], env)
    write_report(args.output, report)

    if args.meta:
        write_meta(args.meta, "09_flamegraph",
                   "PASS" if has_data else "WARN", key_metric)
    print(f"[report] {key_metric}")


if __name__ == "__main__":
    main()
