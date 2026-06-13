#!/usr/bin/env python3
"""
lib/report.py — shared Markdown report renderer for all benchmark suites.

Every suite's report.py adds lib/ to sys.path and calls these helpers.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from baseline import Regression, Severity, overall_status


# ── Status icons ──────────────────────────────────────────────────────────────
_STATUS_ICON = {"PASS": "✅ PASS", "WARN": "⚠️ WARN", "FAIL": "🔴 FAIL"}
_SEV_ICON    = {Severity.INFO: "ℹ️", Severity.WARNING: "⚠️", Severity.REGRESSION: "🔴"}


# ── Primitives ────────────────────────────────────────────────────────────────

def md_table(headers: list[str], rows: list[list[str]]) -> str:
    """Render a GFM Markdown table."""
    sep  = "|" + "|".join(":---" for _ in headers) + "|"
    head = "|" + "|".join(f" **{h}** " for h in headers) + "|"
    body = "\n".join(
        "|" + "|".join(f" {c} " for c in row) + "|"
        for row in rows
    )
    return f"{head}\n{sep}\n{body}"


def md_code(content: str, lang: str = "") -> str:
    return f"```{lang}\n{content}\n```"


def fmt_number(v: float, precision: int = 3) -> str:
    """Format a float, switching to scientific notation only for tiny values."""
    if v == 0:
        return "0"
    if abs(v) < 0.001:
        return f"{v:.2e}"
    return f"{v:,.{precision}g}"


# ── Section builders ─────────────────────────────────────────────────────────

def env_section(env: dict[str, Any]) -> str:
    rows = [[k.replace("_", " ").title(), str(v)] for k, v in env.items()]
    return "## Environment\n\n" + md_table(["Key", "Value"], rows)


def regressions_section(regressions: list[Regression]) -> str:
    if not regressions:
        return "## Regression Check\n\n✅ No regressions detected against baseline.\n"

    rows = []
    for r in regressions:
        sign   = "+" if r.delta_pct > 0 else ""
        rows.append([
            _SEV_ICON[r.severity],
            f"`{r.metric}`",
            fmt_number(r.current),
            fmt_number(r.baseline),
            f"{sign}{r.delta_pct:.1f}%",
            r.severity.value,
            r.note or "—",
        ])
    return (
        "## Regression Check\n\n"
        + md_table(
            ["", "Metric", "Current", "Baseline", "Δ", "Severity", "Note"],
            rows,
        )
        + "\n"
    )


# ── Top-level renderer ────────────────────────────────────────────────────────

def render_report(
    suite_name  : str,
    title       : str,
    sections    : list[str],          # list of Markdown section strings
    regressions : list[Regression],
    env         : dict[str, Any],
    run_id      : str = "",
) -> str:
    ts     = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    status = overall_status(regressions)
    icon   = _STATUS_ICON[status]

    meta = (
        f"# {title}\n\n"
        f"| | |\n|:---|:---|\n"
        f"| **Suite** | `{suite_name}` |\n"
        f"| **Status** | {icon} |\n"
        f"| **Run** | {ts} |\n"
    )
    if run_id:
        meta += f"| **Run ID** | `{run_id}` |\n"
    meta += "\n---\n"

    body = "\n\n---\n\n".join(sections)
    return "\n\n".join([meta, env_section(env), body, regressions_section(regressions)])


def write_report(path: str | Path, content: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    print(f"[report] Written → {p}")


# ── Summary row (used by run_all.sh via lib/report.py) ───────────────────────

def summary_row(suite: str, status: str, key_metric: str, vs_baseline: str) -> str:
    icon = _STATUS_ICON.get(status, status)
    return f"| `{suite}` | {icon} | {key_metric} | {vs_baseline} |"


def write_meta(
    path        : str | Path,
    suite       : str,
    status      : str,
    key_metric  : str,
    vs_baseline : str = "—",
) -> None:
    """
    Write a compact meta.json consumed by lib/summary.py to build SUMMARY.md.
    Call this at the end of every suite's report.py main().
    """
    from datetime import datetime, timezone
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({
        "suite"       : suite,
        "status"      : status,
        "key_metric"  : key_metric,
        "vs_baseline" : vs_baseline,
        "timestamp"   : datetime.now(timezone.utc).isoformat(),
    }, indent=2))
    print(f"[report] Meta  → {p}")
