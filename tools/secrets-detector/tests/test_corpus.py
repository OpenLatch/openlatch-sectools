# Copyright 2026 OpenLatch, Inc.
# Licensed under the Apache License, Version 2.0 (see LICENSE).
"""Corpus tests — parametrized coverage of every rule_id in secrets-detector.

Each positive case confirms that the expected rule fires and the verdict
meets the minimum risk score. A negative (clean) case confirms that a
benign payload gets through undetected.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from secrets_detector import app

client = TestClient(app)


# ---------------------------------------------------------------------------
# Corpus
# ---------------------------------------------------------------------------

# (description, text_in_tool_input, expected_rule_id_or_None, min_risk, expected_verdict)
CORPUS = [
    # ---- Positive cases (one per rule_id) ---------------------------------
    (
        "AWS AKIA key triggers SECRET-AWS-AKIA-01",
        "AKIAIOSFODNN7EXAMPLE",
        "SECRET-AWS-AKIA-01",
        90,
        "deny",
    ),
    (
        "AWS ASIA (STS) key triggers SECRET-AWS-AKIA-01",
        "ASIAIOSFODNN7EXAMPLE",
        "SECRET-AWS-AKIA-01",
        90,
        "deny",
    ),
    (
        "GitHub user PAT triggers SECRET-GITHUB-PAT-01",
        "ghu_" + "A" * 36,
        "SECRET-GITHUB-PAT-01",
        85,
        "deny",
    ),
    (
        "GitHub OAuth token triggers SECRET-GITHUB-PAT-01",
        "gho_" + "B" * 36,
        "SECRET-GITHUB-PAT-01",
        85,
        "deny",
    ),
    (
        "GitHub server-to-server PAT triggers SECRET-GITHUB-PAT-01",
        "ghs_" + "C" * 36,
        "SECRET-GITHUB-PAT-01",
        85,
        "deny",
    ),
    (
        "Anthropic API key triggers SECRET-ANTHROPIC-01",
        "sk-ant-" + "x" * 20,
        "SECRET-ANTHROPIC-01",
        85,
        "deny",
    ),
    (
        "Slack bot token triggers SECRET-SLACK-01",
        "xoxb-1234567890-abcdefghij",
        "SECRET-SLACK-01",
        80,
        "deny",
    ),
    (
        "Slack app token triggers SECRET-SLACK-01",
        "xoxa-1234567890-abcdefghij",
        "SECRET-SLACK-01",
        80,
        "deny",
    ),
    (
        "JWT triggers SECRET-JWT-01",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "SECRET-JWT-01",
        75,
        "deny",
    ),
    (
        "Bearer token triggers SECRET-BEARER-01",
        "Bearer abcdefghijklmnopqrstuvwxyz0123456",
        "SECRET-BEARER-01",
        70,
        "deny",
    ),
    (
        "PEM RSA private key triggers SECRET-PEM-01",
        "-----BEGIN RSA PRIVATE KEY-----",
        "SECRET-PEM-01",
        95,
        "deny",
    ),
    (
        "PEM EC private key triggers SECRET-PEM-01",
        "-----BEGIN EC PRIVATE KEY-----",
        "SECRET-PEM-01",
        95,
        "deny",
    ),
    (
        "PEM OPENSSH private key triggers SECRET-PEM-01",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "SECRET-PEM-01",
        95,
        "deny",
    ),
    # ---- Negative cases ---------------------------------------------------
    (
        "Clean text does not trigger any rule",
        "echo hello world",
        None,
        0,
        "allow",
    ),
    (
        "Short AKIA prefix without enough chars is clean",
        "AKIASHORT",
        None,
        0,
        "allow",
    ),
    (
        "Bearer with short token is clean",
        "Bearer short",
        None,
        0,
        "allow",
    ),
]


def _make_event(tool_input: str) -> dict:
    return {
        "event_id": "evt_corpus",
        "event_type": "pre_tool_use",
        "agent": {"platform": "claude-code"},
        "tool_call": {"name": "Bash", "input": {"command": tool_input}},
    }


@pytest.mark.parametrize(
    "description,tool_input,expected_rule_id,min_risk,expected_verdict",
    CORPUS,
    ids=[c[0] for c in CORPUS],
)
def test_corpus(
    description: str,
    tool_input: str,
    expected_rule_id: str | None,
    min_risk: int,
    expected_verdict: str,
) -> None:
    response = client.post("/event", json=_make_event(tool_input))
    assert response.status_code == 200, response.text
    body = response.json()

    assert body["verdictHint"] == expected_verdict, (
        f"[{description}] expected verdictHint={expected_verdict!r}, "
        f"got {body['verdictHint']!r}. Full body: {body}"
    )

    if expected_rule_id is not None:
        assert (
            body["ruleId"] == expected_rule_id
        ), f"[{description}] expected ruleId={expected_rule_id!r}, got {body.get('ruleId')!r}"
        assert (
            body["riskScore"] >= min_risk
        ), f"[{description}] expected riskScore>={min_risk}, got {body['riskScore']}"
    else:
        # Clean case — riskScore should be 0 and no ruleId
        assert (
            body["riskScore"] == 0
        ), f"[{description}] expected riskScore=0, got {body['riskScore']}"
