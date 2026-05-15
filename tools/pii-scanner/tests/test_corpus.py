# Copyright 2026 OpenLatch, Inc.
# Licensed under the Apache License, Version 2.0 (see LICENSE).
"""Parametrized corpus tests for all pii-scanner rule_ids.

Each row exercises a concrete input text, the expected rule_id (or None for
clean inputs), a minimum risk score, and the expected verdictHint.

Positive cases: ≥1 per rule_id (PII-SSN-01, PII-CC-01, PII-EMAIL-01,
               PII-PHONE-01, PII-IP-01).
Negative cases: clean text → allow, ruleId absent / None.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from pii_scanner import app

client = TestClient(app)


def _event_with_input(text: str) -> dict:
    return {
        "event_id": "evt_corpus",
        "event_type": "pre_tool_use",
        "agent": {"platform": "claude-code"},
        "tool_call": {"name": "Bash", "input": {"command": text}},
    }


def _post(text: str) -> dict:
    resp = client.post("/event", json=_event_with_input(text))
    assert resp.status_code == 200, resp.text
    return resp.json()


# ---------------------------------------------------------------------------
# Corpus table
# (input_text, expected_rule_id_or_None, expected_min_risk, expected_verdict)
# ---------------------------------------------------------------------------

CORPUS: list[tuple[str, str | None, int, str]] = [
    # --- PII-SSN-01 positives ---
    ("My SSN is 123-45-6789 please keep it safe", "PII-SSN-01", 80, "deny"),
    ("ssn=321-54-9876", "PII-SSN-01", 80, "deny"),
    # --- PII-CC-01 positives (Luhn-valid numbers) ---
    # Visa test number
    ("card: 4111111111111111", "PII-CC-01", 80, "deny"),
    # Mastercard test number
    ("charge to 5500005555555559", "PII-CC-01", 80, "deny"),
    # --- PII-EMAIL-01 positives ---
    ("send invoice to billing@example.com today", "PII-EMAIL-01", 50, "allow"),
    ("contact: user.name+tag@sub.domain.org", "PII-EMAIL-01", 50, "allow"),
    # --- PII-PHONE-01 positives ---
    ("call me at 555-867-5309", "PII-PHONE-01", 50, "allow"),
    ("phone: (800) 123-4567", "PII-PHONE-01", 50, "allow"),
    ("reach me at +1 415 555 2671", "PII-PHONE-01", 50, "allow"),
    # --- PII-IP-01 positives (public IPs) ---
    ("connecting to 8.8.8.8 for DNS", "PII-IP-01", 40, "allow"),
    ("server at 203.0.113.45", "PII-IP-01", 40, "allow"),
    # --- Negative cases — clean text, no PII ---
    ("list all files in the current directory", None, 0, "allow"),
    ("the quick brown fox jumps over the lazy dog", None, 0, "allow"),
    ("localhost 127.0.0.1 is not a public IP", None, 0, "allow"),
    ("RFC1918 address 192.168.1.1 is private", None, 0, "allow"),
    ("10.0.0.1 is also private", None, 0, "allow"),
    # Invalid SSN area codes are excluded
    ("not-ssn: 000-12-3456", None, 0, "allow"),
    ("not-ssn: 666-12-3456", None, 0, "allow"),
    ("not-ssn: 900-12-3456", None, 0, "allow"),
    # Luhn-invalid CC sequence — must NOT trigger PII-CC-01
    ("not-cc: 1234567890123456", None, 0, "allow"),
]


@pytest.mark.parametrize(
    "input_text,expected_rule_id,expected_min_risk,expected_verdict",
    CORPUS,
    ids=[f"corpus[{i}]" for i in range(len(CORPUS))],
)
def test_corpus(
    input_text: str,
    expected_rule_id: str | None,
    expected_min_risk: int,
    expected_verdict: str,
) -> None:
    body = _post(input_text)
    assert body["verdictHint"] == expected_verdict, (
        f"input={input_text!r} expected verdictHint={expected_verdict!r} "
        f"got {body['verdictHint']!r}"
    )
    if expected_rule_id is None:
        # clean — ruleId should be absent or None
        assert (
            body.get("ruleId") is None
        ), f"input={input_text!r} expected no ruleId, got {body.get('ruleId')!r}"
        assert body["riskScore"] == expected_min_risk
    else:
        assert (
            body.get("ruleId") == expected_rule_id
        ), f"input={input_text!r} expected ruleId={expected_rule_id!r} got {body.get('ruleId')!r}"
        assert (
            body["riskScore"] >= expected_min_risk
        ), f"input={input_text!r} expected riskScore>={expected_min_risk} got {body['riskScore']}"
