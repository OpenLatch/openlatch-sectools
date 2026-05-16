"""Canonical OpenLatch severity bucketing (D-07).

First-party tools MUST derive `severity` from `risk_score` via
`score_to_severity` so the `<40 / 40-69 / 70-89 / 90+` bucket invariant
holds by construction across every tool the platform trusts verbatim.
"""

from __future__ import annotations

from .types import SeverityHint

__all__ = ["SeverityHint", "score_to_severity"]


def score_to_severity(risk_score: int) -> SeverityHint:
    """Map a 0-100 risk score onto the canonical severity bucket."""
    if risk_score >= 90:
        return "critical"
    if risk_score >= 70:
        return "high"
    if risk_score >= 40:
        return "medium"
    return "low"
