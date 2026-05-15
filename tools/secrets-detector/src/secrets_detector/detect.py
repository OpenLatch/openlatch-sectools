# Copyright 2026 OpenLatch, Inc.
# Licensed under the Apache License, Version 2.0 (see LICENSE).
"""Pure-regex credential detection logic for secrets-detector.

``run_detectors`` scans the text surface of an incoming ``CloudEvent``
(tool call name + input + data) against a curated set of credential
patterns and returns a list of ``Finding`` objects, one per match.
No network I/O takes place here — all detection is in-process.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from openlatch_tool_sdk import CloudEvent


@dataclass
class Finding:
    """A single matched credential pattern."""

    rule_id: str
    risk_score: int
    threat_category: str = "credential_detection"
    summary: str = ""
    axes: dict = field(default_factory=dict)
    user_facing: Any = None


# ---------------------------------------------------------------------------
# Pattern registry
# ---------------------------------------------------------------------------

_PATTERNS: list[tuple[str, re.Pattern[str], int, int]] = [
    # (rule_id, compiled_pattern, risk_score, secret_axis)
    (
        "SECRET-PEM-01",
        re.compile(
            r"-----BEGIN (RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----",
            re.IGNORECASE,
        ),
        95,
        20,
    ),
    (
        "SECRET-AWS-AKIA-01",
        re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
        90,
        20,
    ),
    (
        "SECRET-GITHUB-PAT-01",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
        85,
        18,
    ),
    (
        "SECRET-ANTHROPIC-01",
        re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
        85,
        18,
    ),
    (
        "SECRET-SLACK-01",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        80,
        16,
    ),
    (
        "SECRET-JWT-01",
        re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
        75,
        15,
    ),
    (
        "SECRET-BEARER-01",
        re.compile(r"\bBearer\s+[A-Za-z0-9._~+/\-]{16,}=*"),
        70,
        14,
    ),
]


# ---------------------------------------------------------------------------
# Text extraction
# ---------------------------------------------------------------------------


def _extract_text(event: CloudEvent) -> str:
    """Build the combined text surface to scan from a CloudEvent."""
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

    if event.data is not None:
        if isinstance(event.data, str):
            parts.append(event.data)
        else:
            try:
                parts.append(json.dumps(event.data))
            except (TypeError, ValueError):
                parts.append(str(event.data))

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def run_detectors(event: CloudEvent) -> list[Finding]:
    """Scan the event's text surface and return one Finding per matched rule.

    If the same rule matches multiple times in the same event, only one
    Finding is returned for that rule (highest-risk match wins, but for
    these fixed-risk patterns that means dedup by rule_id).
    """
    text = _extract_text(event)
    seen: set[str] = set()
    findings: list[Finding] = []

    for rule_id, pattern, risk_score, secret_axis in _PATTERNS:
        if rule_id in seen:
            continue
        if pattern.search(text):
            seen.add(rule_id)
            findings.append(
                Finding(
                    rule_id=rule_id,
                    risk_score=risk_score,
                    threat_category="credential_detection",
                    summary=f"Potential credential detected: {rule_id}",
                    axes={
                        "destructive": 0,
                        "exfil": 0,
                        "secret": secret_axis,
                        "privesc": 0,
                        "reversibility": 0,
                    },
                )
            )

    return findings
