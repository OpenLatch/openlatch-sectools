# Copyright 2026 OpenLatch, Inc.
# Licensed under the Apache License, Version 2.0 (see LICENSE).
"""Pure detection logic for the pii-scanner tool.

No HTTP, no FastAPI — just regex recognizers + an optional Presidio pass.
``run_detectors`` is the public surface; everything else is an implementation
detail.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field

from openlatch_tool_sdk import CloudEvent, UserFacing

# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    rule_id: str
    risk_score: int
    threat_category: str
    summary: str
    axes: dict = field(default_factory=dict)
    user_facing: UserFacing | None = None


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# PII-SSN-01 — US Social Security Number.
# Exclude area codes starting with 000, 666, or 900-999 (invalid ranges).
_SSN_RE = re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")

# PII-EMAIL-01 — RFC-ish email address.
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")

# PII-PHONE-01 — North-American phone number (various separators).
# Avoid matching SSN or CC digit sequences that happen to look phone-like.
_PHONE_RE = re.compile(
    r"(?<!\d)" r"(\+?1[-.\s]?)?" r"\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}" r"(?!\d)"
)

# PII-CC-01 — Raw 13-19 digit candidate (spaces/dashes stripped separately).
# We extract runs and then apply the Luhn check.
_CC_CANDIDATE_RE = re.compile(r"(?:\d[ \-]?){12,18}\d")

# PII-IP-01 — IPv4 address, public only (RFC1918 / loopback / 0.0.0.0 excluded).
_IPV4_RE = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")

# Ranges that are NOT public IPv4
_RFC1918_10 = re.compile(r"^10\.")
_RFC1918_172 = re.compile(r"^172\.(1[6-9]|2\d|3[01])\.")
_RFC1918_192 = re.compile(r"^192\.168\.")


# ---------------------------------------------------------------------------
# Luhn algorithm
# ---------------------------------------------------------------------------


def _luhn_valid(number: str) -> bool:
    """Return True if *number* (digits-only string) passes the Luhn check."""
    digits = [int(d) for d in number]
    digits.reverse()
    total = 0
    for i, d in enumerate(digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# ---------------------------------------------------------------------------
# Individual recognizers
# ---------------------------------------------------------------------------


def _find_ssn(text: str) -> list[str]:
    return _SSN_RE.findall(text)


def _find_emails(text: str) -> list[str]:
    return _EMAIL_RE.findall(text)


def _find_phones(text: str) -> list[str]:
    # Strip matches that were already matched by SSN or email (overlap guard
    # is lightweight here because SSN has dashes in different positions and
    # email matches contain @).
    matches = []
    for m in _PHONE_RE.finditer(text):
        span_text = m.group(0)
        # Skip if the span is completely contained in an SSN match
        if _SSN_RE.search(span_text):
            continue
        matches.append(span_text)
    return matches


def _find_credit_cards(text: str) -> list[str]:
    found = []
    for m in _CC_CANDIDATE_RE.finditer(text):
        raw = m.group(0)
        digits = re.sub(r"[ \-]", "", raw)
        if 13 <= len(digits) <= 19 and _luhn_valid(digits):
            found.append(digits)
    return found


def _is_public_ipv4(a: str, b: str, c: str, d: str) -> bool:
    """Return True if the four octets represent a routable public IPv4."""
    try:
        ints = [int(x) for x in (a, b, c, d)]
    except ValueError:
        return False
    if any(x > 255 for x in ints):
        return False
    ip_str = f"{a}.{b}.{c}.{d}"
    if ip_str == "0.0.0.0":
        return False
    if ints[0] == 127:  # loopback
        return False
    if _RFC1918_10.match(ip_str):
        return False
    if _RFC1918_172.match(ip_str):
        return False
    return not _RFC1918_192.match(ip_str)


def _find_public_ips(text: str) -> list[str]:
    found = []
    for m in _IPV4_RE.finditer(text):
        a, b, c, d = m.group(1), m.group(2), m.group(3), m.group(4)
        if _is_public_ipv4(a, b, c, d):
            found.append(m.group(0))
    return found


# ---------------------------------------------------------------------------
# Threat category helper
# ---------------------------------------------------------------------------


def _threat_category(event: CloudEvent) -> str:
    """Classify the event direction as pii_inbound or pii_outbound."""
    et = (event.event_type or "").lower()
    if "response" in et or "post" in et:
        return "pii_inbound"
    if event.data and isinstance(event.data, dict) and event.data.get("direction") == "inbound":
        return "pii_inbound"
    return "pii_outbound"


# ---------------------------------------------------------------------------
# Scan-text assembly
# ---------------------------------------------------------------------------


def _build_scan_text(event: CloudEvent) -> str:
    parts: list[str] = []

    if event.tool_call is not None:
        if event.tool_call.name:
            parts.append(event.tool_call.name)
        inp = event.tool_call.input
        if isinstance(inp, dict):
            try:
                parts.append(json.dumps(inp))
            except (TypeError, ValueError):
                parts.append(str(inp))
        elif inp is not None:
            parts.append(str(inp))

    data = event.data
    if isinstance(data, str):
        parts.append(data)
    elif isinstance(data, dict | list):
        try:
            parts.append(json.dumps(data))
        except (TypeError, ValueError):
            parts.append(str(data))
    elif data is not None:
        parts.append(str(data))

    return " ".join(parts)


# ---------------------------------------------------------------------------
# Presidio optional enrichment
# ---------------------------------------------------------------------------


def _presidio_findings(text: str, category: str) -> list[Finding]:  # pragma: no cover
    """Run Microsoft Presidio if available and enabled."""
    try:
        from presidio_analyzer import AnalyzerEngine  # type: ignore[import]
    except ImportError:
        return []

    _ENTITY_TO_RULE = {
        "EMAIL_ADDRESS": ("PII-EMAIL-01", 50, 10),
        "US_SSN": ("PII-SSN-01", 80, 16),
        "CREDIT_CARD": ("PII-CC-01", 80, 16),
        "PHONE_NUMBER": ("PII-PHONE-01", 50, 10),
        "IP_ADDRESS": ("PII-IP-01", 40, 8),
    }

    engine = AnalyzerEngine()
    results = engine.analyze(text=text, language="en")
    findings = []
    for r in results:
        mapping = _ENTITY_TO_RULE.get(r.entity_type)
        if mapping is None:
            continue
        rule_id, risk, exfil = mapping
        findings.append(
            Finding(
                rule_id=rule_id,
                risk_score=risk,
                threat_category=category,
                summary=f"Presidio detected {r.entity_type} (score {r.score:.2f})",
                axes={
                    "destructive": 0,
                    "exfil": exfil,
                    "secret": 0,
                    "privesc": 0,
                    "reversibility": 0,
                },
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def run_detectors(event: CloudEvent) -> list[Finding]:
    """Return a list of ``Finding`` objects for every PII type detected."""
    text = _build_scan_text(event)
    category = _threat_category(event)
    findings: list[Finding] = []

    # --- PII-SSN-01 ---
    ssns = _find_ssn(text)
    if ssns:
        findings.append(
            Finding(
                rule_id="PII-SSN-01",
                risk_score=80,
                threat_category=category,
                summary=f"US Social Security Number detected ({len(ssns)} match(es))",
                axes={"destructive": 0, "exfil": 16, "secret": 0, "privesc": 0, "reversibility": 0},
                user_facing=UserFacing(
                    headline="Social Security Number detected",
                    body="The action contains what appears to be a US Social Security Number. "
                    "Transmitting SSNs in agent actions is a high-severity PII risk.",
                ),
            )
        )

    # --- PII-CC-01 ---
    cards = _find_credit_cards(text)
    if cards:
        findings.append(
            Finding(
                rule_id="PII-CC-01",
                risk_score=80,
                threat_category=category,
                summary=f"Credit card number detected ({len(cards)} match(es), Luhn-validated)",
                axes={"destructive": 0, "exfil": 16, "secret": 0, "privesc": 0, "reversibility": 0},
                user_facing=UserFacing(
                    headline="Credit card number detected",
                    body="The action contains a digit sequence that passes the Luhn check for a "
                    "payment card number. This is a high-severity PII risk.",
                ),
            )
        )

    # --- PII-EMAIL-01 ---
    emails = _find_emails(text)
    if emails:
        findings.append(
            Finding(
                rule_id="PII-EMAIL-01",
                risk_score=50,
                threat_category=category,
                summary=f"Email address detected ({len(emails)} match(es))",
                axes={"destructive": 0, "exfil": 10, "secret": 0, "privesc": 0, "reversibility": 0},
            )
        )

    # --- PII-PHONE-01 ---
    phones = _find_phones(text)
    if phones:
        findings.append(
            Finding(
                rule_id="PII-PHONE-01",
                risk_score=50,
                threat_category=category,
                summary=f"Phone number detected ({len(phones)} match(es))",
                axes={"destructive": 0, "exfil": 10, "secret": 0, "privesc": 0, "reversibility": 0},
            )
        )

    # --- PII-IP-01 ---
    ips = _find_public_ips(text)
    if ips:
        findings.append(
            Finding(
                rule_id="PII-IP-01",
                risk_score=40,
                threat_category=category,
                summary=f"Public IPv4 address detected ({len(ips)} match(es))",
                axes={"destructive": 0, "exfil": 8, "secret": 0, "privesc": 0, "reversibility": 0},
            )
        )

    # --- Optional: Presidio enrichment ---
    presidio_enabled = os.environ.get("OPENLATCH_PII_SCANNER_PRESIDIO", "0") == "1"
    if presidio_enabled:
        extra = _presidio_findings(text, category)
        # Only add findings whose rule_id isn't already present
        existing_rule_ids = {f.rule_id for f in findings}
        for f in extra:
            if f.rule_id not in existing_rule_ids:
                findings.append(f)

    return findings
