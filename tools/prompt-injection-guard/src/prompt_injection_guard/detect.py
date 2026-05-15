# Copyright 2026 OpenLatch, Inc.
# Licensed under the Apache License, Version 2.0 (see LICENSE).
"""Prompt-injection detector — pure regex prefilter plus optional DeBERTa scan.

``run_detectors`` is the public entry-point. It is pure (no I/O) and
synchronous so the FastAPI handler can call it from the event loop without
blocking.  The optional DeBERTa scanner (INJECT-DEBERTA-01) is wrapped in
try/except and lazily imported — tests MUST NOT require a real model.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any

from openlatch_tool_sdk import CloudEvent, UserFacing

# ---------------------------------------------------------------------------
# Internal result type
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """One detection hit returned by a single rule."""

    rule_id: str
    risk_score: int
    threat_category: str  # injection_user_input | injection_tool_response
    summary: str
    user_facing: UserFacing | None
    axes: dict[str, int] = field(
        default_factory=lambda: {
            "destructive": 0,
            "exfil": 6,
            "secret": 4,
            "privesc": 4,
            "reversibility": 0,
        }
    )


# ---------------------------------------------------------------------------
# Rule registry — (rule_id, compiled_pattern, base_risk_score, axes_override)
# ---------------------------------------------------------------------------

_BASELINE_AXES: dict[str, int] = {
    "destructive": 0,
    "exfil": 6,
    "secret": 4,
    "privesc": 4,
    "reversibility": 0,
}

_RULES: list[tuple[str, re.Pattern[str], int, dict[str, int]]] = [
    (
        "INJECT-IGNORE-INSTRUCTIONS-01",
        re.compile(
            r"(ignore|disregard|forget)\s+"
            r"(all\s+)?(the\s+)?"
            r"(previous|prior|above|earlier|system)(\s+(system|all|the))?\s+"
            r"(instructions|prompt|prompts|context|rules)",
            re.IGNORECASE,
        ),
        80,
        {**_BASELINE_AXES, "privesc": 8, "exfil": 6},
    ),
    (
        "INJECT-SYSTEM-PROMPT-LEAK-01",
        re.compile(
            r"(reveal|print|repeat|show|output|leak|reproduce)\s+"
            r"(your\s+|the\s+)?"
            r"(system\s*prompt|initial\s+instructions|developer\s+message|hidden\s+prompt)",
            re.IGNORECASE,
        ),
        75,
        {**_BASELINE_AXES, "secret": 12, "exfil": 10, "privesc": 4},
    ),
    (
        "INJECT-ROLE-OVERRIDE-01",
        re.compile(
            r"(you are now\b"
            r"|act as (an?\s+)?(DAN|unrestricted|jailbroken|evil)"
            r"|from now on,? you (are|will|must)"
            r"|enable developer mode"
            r"|ignore your (guidelines|safety))",
            re.IGNORECASE,
        ),
        78,
        {**_BASELINE_AXES, "privesc": 10, "exfil": 4},
    ),
    (
        "INJECT-TOOL-RESPONSE-POISON-01",
        re.compile(
            r"(<\s*(system|important|assistant|instructions?)\s*>[^<]*(must|should|need to|you are)\b"
            r"|\[\s*system\s*\]"
            r"|(AI|assistant)[,:]\s+you (must|should|need to)\b)",
            re.IGNORECASE,
        ),
        82,
        {**_BASELINE_AXES, "privesc": 8, "exfil": 8, "destructive": 2},
    ),
]


# ---------------------------------------------------------------------------
# Direction helper
# ---------------------------------------------------------------------------


def _direction(event: CloudEvent) -> str:
    """Return the threat_category based on event type and data hints."""
    event_type = (event.event_type or "").lower()
    if "response" in event_type or "post_tool" in event_type:
        return "injection_tool_response"
    if isinstance(event.data, dict) and event.data.get("direction") == "tool_response":
        return "injection_tool_response"
    return "injection_user_input"


# ---------------------------------------------------------------------------
# Text extraction
# ---------------------------------------------------------------------------


def _extract_text(event: CloudEvent) -> str:
    """Collect all text surfaces from the event into one string."""
    parts: list[str] = []

    tc = event.tool_call
    if tc is not None:
        if tc.name:
            parts.append(tc.name)
        if tc.input:
            try:
                parts.append(json.dumps(tc.input))
            except (TypeError, ValueError):
                parts.append(str(tc.input))

    data: Any = event.data
    if data is not None:
        if isinstance(data, str):
            parts.append(data)
        else:
            try:
                parts.append(json.dumps(data))
            except (TypeError, ValueError):
                parts.append(str(data))

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Individual scanners
# ---------------------------------------------------------------------------


def _regex_scan(text: str, default_direction: str) -> list[Finding]:
    findings: list[Finding] = []
    for rule_id, pattern, risk_score, axes in _RULES:
        if not pattern.search(text):
            continue

        # Tool-response poison rule always forces injection_tool_response
        if rule_id == "INJECT-TOOL-RESPONSE-POISON-01":
            direction = "injection_tool_response"
        else:
            direction = default_direction

        findings.append(
            Finding(
                rule_id=rule_id,
                risk_score=risk_score,
                threat_category=direction,
                summary=f"prompt injection detected by {rule_id}",
                user_facing=UserFacing(
                    headline="Prompt injection attempt detected",
                    body=(
                        f"The agent input matched rule {rule_id}. "
                        "This pattern is associated with attempts to override "
                        "or bypass the agent's system instructions."
                    ),
                ),
                axes=dict(axes),
            )
        )
    return findings


def _deberta_scan(text: str, default_direction: str) -> list[Finding]:
    """Optional DeBERTa-backed scan via llm-guard.

    Only runs when:
    - ``llm_guard`` is importable (``pip install .[ml]``)
    - ``OPENLATCH_PROMPT_INJECTION_GUARD_MODEL=1``

    Never raises — any failure is silently swallowed so the regex prefilter
    result is still returned.
    """
    if os.environ.get("OPENLATCH_PROMPT_INJECTION_GUARD_MODEL") != "1":
        return []

    try:
        from llm_guard.input_scanners import PromptInjection  # type: ignore[import]

        scanner = PromptInjection()
        _sanitized, is_valid, risk_score_raw = scanner.scan(text)
        if not is_valid:
            risk = max(70, int(risk_score_raw * 100))
            return [
                Finding(
                    rule_id="INJECT-DEBERTA-01",
                    risk_score=risk,
                    threat_category=default_direction,
                    summary="prompt injection detected by llm-guard DeBERTa model",
                    user_facing=UserFacing(
                        headline="Prompt injection detected by ML model",
                        body=(
                            "The llm-guard DeBERTa prompt-injection scanner flagged "
                            "this input. Enable with OPENLATCH_PROMPT_INJECTION_GUARD_MODEL=1 "
                            "and `pip install .[ml]`."
                        ),
                    ),
                    axes=dict(_BASELINE_AXES),
                )
            ]
    except Exception:  # noqa: BLE001 — never hard-fail
        pass

    return []


# ---------------------------------------------------------------------------
# Public entry-point
# ---------------------------------------------------------------------------


def run_detectors(event: CloudEvent) -> list[Finding]:
    """Run all detectors against *event*; return every Finding (may be empty)."""
    text = _extract_text(event)
    direction = _direction(event)

    findings: list[Finding] = []
    findings.extend(_regex_scan(text, direction))
    findings.extend(_deberta_scan(text, direction))
    return findings
