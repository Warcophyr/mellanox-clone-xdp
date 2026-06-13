#!/usr/bin/env python3
"""
lib/baseline.py — load, save, and diff benchmark baselines.

Each suite stores a baseline.json after a known-good run.
Subsequent runs call compare() to surface regressions automatically.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


# ── Severity levels ───────────────────────────────────────────────────────────

class Severity(str, Enum):
    INFO       = "INFO"        # small drift, informational only
    WARNING    = "WARNING"     # noteworthy but not blocking
    REGRESSION = "REGRESSION"  # clear performance regression


SEVERITY_RANK = {Severity.INFO: 0, Severity.WARNING: 1, Severity.REGRESSION: 2}


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class Regression:
    metric    : str
    current   : float
    baseline  : float
    delta_pct : float
    severity  : Severity
    note      : str = ""

    @property
    def icon(self) -> str:
        return {"INFO": "ℹ️", "WARNING": "⚠️", "REGRESSION": "🔴"}[self.severity]


@dataclass
class ThresholdConfig:
    """
    direction : 'higher_is_bad'  → a positive delta is a regression (e.g. cache-misses)
                'lower_is_bad'   → a negative delta is a regression (e.g. throughput)
    warn      : % change that triggers WARNING
    regress   : % change that triggers REGRESSION
    """
    direction : str   = "higher_is_bad"
    warn      : float = 5.0
    regress   : float = 15.0


# ── Public API ────────────────────────────────────────────────────────────────

def load_baseline(path: str | Path) -> dict[str, Any]:
    """Return dict from baseline.json, or {} if it does not exist yet."""
    p = Path(path)
    if not p.exists():
        return {}
    with p.open() as f:
        return json.load(f)


def save_baseline(path: str | Path, data: dict[str, Any]) -> None:
    """Persist data as the new baseline."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w") as f:
        json.dump(data, f, indent=2)
    print(f"[baseline] Saved → {p}")


def compare(
    current    : dict[str, float],
    baseline   : dict[str, float],
    thresholds : dict[str, ThresholdConfig] | None = None,
) -> list[Regression]:
    """
    Compare current metric values against the stored baseline.

    Returns a sorted list of Regression objects (REGRESSION first).
    Metrics absent from baseline are silently skipped (first-run case).

    thresholds: metric_name → ThresholdConfig
                Any metric not in the dict uses default thresholds.
    """
    thresholds = thresholds or {}
    default_cfg = ThresholdConfig()
    regressions: list[Regression] = []

    for metric, cur in current.items():
        base = baseline.get(metric)
        if base is None or base == 0:
            continue

        delta_pct = (cur - base) / abs(base) * 100.0
        cfg = thresholds.get(metric, default_cfg)

        # Normalise: positive signed_delta always means "got worse"
        signed = delta_pct if cfg.direction == "higher_is_bad" else -delta_pct

        if   signed > cfg.regress: sev = Severity.REGRESSION
        elif signed > cfg.warn:    sev = Severity.WARNING
        elif abs(signed) > 1.0:    sev = Severity.INFO
        else:
            continue

        regressions.append(Regression(
            metric=metric, current=cur, baseline=base,
            delta_pct=delta_pct, severity=sev,
        ))

    regressions.sort(key=lambda r: SEVERITY_RANK[r.severity], reverse=True)
    return regressions


def overall_status(regressions: list[Regression]) -> str:
    """Return 'PASS', 'WARN', or 'FAIL' based on the worst regression."""
    if any(r.severity == Severity.REGRESSION for r in regressions):
        return "FAIL"
    if any(r.severity == Severity.WARNING for r in regressions):
        return "WARN"
    return "PASS"
