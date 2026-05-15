# Copyright 2026 OpenLatch, Inc.
# Licensed under the Apache License, Version 2.0 (see LICENSE).
"""Parametrized corpus tests — one positive per rule_id + negative cases.

Asserts camelCase wire fields, minimum risk scores, and correct verdictHint
across a systematic set of graph scenarios.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from attack_path_guard import app

client = TestClient(app)


def _post(data: dict) -> dict:
    body = {
        "event_id": "evt_corpus",
        "event_type": "pre_tool_use",
        "data": data,
    }
    resp = client.post("/event", json=body)
    assert resp.status_code == 200, resp.text
    return resp.json()


# ---------------------------------------------------------------------------
# Positive cases — one per rule_id
# ---------------------------------------------------------------------------

POSITIVE_CASES = [
    pytest.param(
        {
            "nodes": [
                {"id": "internet", "trust": "untrusted"},
                {"id": "app-server", "trust": "internal"},
                {"id": "secrets-store", "trust": "sensitive"},
            ],
            "edges": [
                {"from": "internet", "to": "app-server"},
                {"from": "app-server", "to": "secrets-store"},
            ],
        },
        "ATTACK-PATH-REACHABLE-01",
        80,
        "deny",
        id="reachable-01-three-hop",
    ),
    pytest.param(
        {
            "nodes": [
                {"id": "internet", "trust": "untrusted"},
                {"id": "secrets-store", "trust": "sensitive"},
            ],
            "edges": [
                {"from": "internet", "to": "secrets-store"},
            ],
        },
        "ATTACK-PATH-REACHABLE-01",
        90,
        "deny",
        id="reachable-01-direct",
    ),
    pytest.param(
        {
            "nodes": [
                {"id": "external-user", "trust": "source"},
                {"id": "jump-host", "trust": "internal"},
                {"id": "root-fs", "trust": "secret"},
            ],
            "edges": [
                {"from": "external-user", "to": "jump-host", "via": "ssh"},
                {"from": "jump-host", "to": "root-fs", "via": "sudo"},
            ],
        },
        "ATTACK-PATH-PRIVESC-01",
        85,
        "deny",
        id="privesc-01-sudo",
    ),
    pytest.param(
        {
            "nodes": [
                {"id": "contractor", "trust": "external"},
                {"id": "ci-runner", "trust": "internal"},
                {"id": "prod-db", "trust": "crown_jewel"},
            ],
            "edges": [
                {"from": "contractor", "to": "ci-runner", "via": "pull-request"},
                {"from": "ci-runner", "to": "prod-db", "via": "assume-role"},
            ],
        },
        "ATTACK-PATH-PRIVESC-01",
        85,
        "deny",
        id="privesc-01-assume-role",
    ),
]


@pytest.mark.parametrize("data,expected_rule,min_risk,expected_verdict", POSITIVE_CASES)
def test_positive_corpus(data, expected_rule, min_risk, expected_verdict):
    body = _post(data)
    assert body["verdictHint"] == expected_verdict, f"got {body}"
    assert body["ruleId"] == expected_rule, f"got {body}"
    assert body["riskScore"] >= min_risk, f"got riskScore={body['riskScore']}"


# ---------------------------------------------------------------------------
# Negative cases — all should allow
# ---------------------------------------------------------------------------

NEGATIVE_CASES = [
    pytest.param(
        {"nodes": [], "edges": []},
        id="empty-graph",
    ),
    pytest.param(
        {
            "nodes": [
                {"id": "A", "trust": "internal"},
                {"id": "B", "trust": "internal"},
                {"id": "C", "trust": "internal"},
            ],
            "edges": [
                {"from": "A", "to": "B"},
                {"from": "B", "to": "C"},
            ],
        },
        id="internal-only",
    ),
    pytest.param(
        {
            "nodes": [
                {"id": "attacker", "trust": "untrusted"},
                {"id": "isolated-sink", "trust": "sensitive"},
                {"id": "barrier", "trust": "internal"},
            ],
            # attacker → barrier but no path from barrier to isolated-sink
            "edges": [{"from": "attacker", "to": "barrier"}],
        },
        id="unreachable-sink",
    ),
    pytest.param(
        {
            # Sensitive → untrusted (reversed direction only — no path from untrusted to sensitive)
            "nodes": [
                {"id": "attacker", "trust": "untrusted"},
                {"id": "vault", "trust": "sensitive"},
            ],
            "edges": [{"from": "vault", "to": "attacker"}],
        },
        id="reversed-edge-only",
    ),
    pytest.param(
        {
            # Untrusted exists, sensitive exists, no edges at all
            "nodes": [
                {"id": "hacker", "trust": "untrusted"},
                {"id": "db", "trust": "sensitive"},
            ],
            "edges": [],
        },
        id="no-edges",
    ),
]


@pytest.mark.parametrize("data", NEGATIVE_CASES)
def test_negative_corpus(data):
    body = _post(data)
    assert body["verdictHint"] == "allow", f"expected allow but got {body}"
    assert body["riskScore"] == 0
