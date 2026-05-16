# Copyright 2026 OpenLatch, Inc.
# Licensed under the Apache License, Version 2.0 (see LICENSE).
"""Smoke tests for attack-path-guard.

Covers the contract surface the supervisor relies on:
- /healthz returns 200
- /event returns a shaped Verdict for all detection branches
- JSON round-trip works
- Malformed graph input does not 500
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from attack_path_guard import app

client = TestClient(app)


def _post(data: dict) -> dict:
    body = {
        "event_id": "evt_test",
        "event_type": "pre_tool_use",
        "agent": {"platform": "claude-code"},
        "data": data,
    }
    resp = client.post("/event", json=body)
    assert resp.status_code == 200, resp.text
    return resp.json()


# ---------------------------------------------------------------------------
# /healthz
# ---------------------------------------------------------------------------


def test_healthz_returns_200():
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


# ---------------------------------------------------------------------------
# Allow paths
# ---------------------------------------------------------------------------


def test_internal_only_graph_allows():
    """A graph with only internal nodes has no untrusted source — allow."""
    body = _post(
        {
            "nodes": [
                {"id": "A", "trust": "internal"},
                {"id": "B", "trust": "internal"},
            ],
            "edges": [{"from": "A", "to": "B"}],
        }
    )
    assert body["verdictHint"] == "allow"
    assert body["riskScore"] == 0


def test_disconnected_graph_allows():
    """Untrusted and sensitive nodes that are not connected — allow."""
    body = _post(
        {
            "nodes": [
                {"id": "attacker", "trust": "untrusted"},
                {"id": "vault", "trust": "sensitive"},
            ],
            "edges": [],  # no edges → no path
        }
    )
    assert body["verdictHint"] == "allow"


# ---------------------------------------------------------------------------
# ATTACK-PATH-REACHABLE-01
# ---------------------------------------------------------------------------


def test_reachable_path_denies():
    """Untrusted → internal → sensitive: should deny with ATTACK-PATH-REACHABLE-01."""
    body = _post(
        {
            "nodes": [
                {"id": "attacker", "trust": "untrusted"},
                {"id": "proxy", "trust": "internal"},
                {"id": "db", "trust": "sensitive"},
            ],
            "edges": [
                {"from": "attacker", "to": "proxy"},
                {"from": "proxy", "to": "db"},
            ],
        }
    )
    assert body["verdictHint"] == "deny"
    assert body["ruleId"] == "ATTACK-PATH-REACHABLE-01"
    assert body["riskScore"] >= 80


def test_direct_reachable_path_escalates_risk():
    """Untrusted → sensitive (length 2, direct hop) should hit risk_score 90."""
    body = _post(
        {
            "nodes": [
                {"id": "attacker", "trust": "untrusted"},
                {"id": "vault", "trust": "sensitive"},
            ],
            "edges": [{"from": "attacker", "to": "vault"}],
        }
    )
    assert body["riskScore"] == 90
    assert body["ruleId"] == "ATTACK-PATH-REACHABLE-01"


# ---------------------------------------------------------------------------
# ATTACK-PATH-PRIVESC-01
# ---------------------------------------------------------------------------


def test_privesc_edge_detected():
    """A sudo edge on the attack path triggers ATTACK-PATH-PRIVESC-01."""
    body = _post(
        {
            "nodes": [
                {"id": "attacker", "trust": "untrusted"},
                {"id": "svc", "trust": "internal"},
                {"id": "root", "trust": "sensitive"},
            ],
            "edges": [
                {"from": "attacker", "to": "svc", "via": "http"},
                {"from": "svc", "to": "root", "via": "sudo"},
            ],
        }
    )
    assert body["ruleId"] == "ATTACK-PATH-PRIVESC-01"
    assert body["riskScore"] == 85


def test_assume_role_privesc_detected():
    """assume-role is in the privesc edge set.

    When the privesc path also creates a direct (length-2) reachable path,
    ATTACK-PATH-REACHABLE-01 at risk=90 dominates ATTACK-PATH-PRIVESC-01 at
    risk=85.  Add an internal hop so REACHABLE-01 scores 80 < 85 = PRIVESC-01.
    """
    body = _post(
        {
            "nodes": [
                {"id": "ext", "trust": "external"},
                {"id": "jump", "trust": "internal"},
                {"id": "secret_bucket", "trust": "crown_jewel"},
            ],
            "edges": [
                {"from": "ext", "to": "jump", "via": "ssh"},
                {"from": "jump", "to": "secret_bucket", "via": "assume-role"},
            ],
        }
    )
    assert body["ruleId"] == "ATTACK-PATH-PRIVESC-01"


# ---------------------------------------------------------------------------
# actions echo
# ---------------------------------------------------------------------------


def test_actions_echoed_when_present():
    """event.data.actions items should appear as ActionScore objects in the verdict."""
    body = _post(
        {
            "nodes": [
                {"id": "attacker", "trust": "untrusted"},
                {"id": "db", "trust": "sensitive"},
            ],
            "edges": [{"from": "attacker", "to": "db"}],
            "actions": [{"kind": "path", "action_ref": "path:0"}],
        }
    )
    assert body["verdictHint"] == "deny"
    assert "actions" in body
    assert isinstance(body["actions"], list)
    assert len(body["actions"]) >= 1
    first = body["actions"][0]
    assert "actionRef" in first
    assert "riskScore" in first
    assert "severity" in first


# ---------------------------------------------------------------------------
# JSON round-trip
# ---------------------------------------------------------------------------


def test_response_is_valid_json():
    body = _post(
        {
            "nodes": [
                {"id": "attacker", "trust": "untrusted"},
                {"id": "db", "trust": "sensitive"},
            ],
            "edges": [{"from": "attacker", "to": "db"}],
        }
    )
    # Round-trip serialisation — covers the SDK's Verdict shape
    json.dumps(body)


# ---------------------------------------------------------------------------
# Malformed input — must never 500
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_data",
    [
        None,
        "not a dict",
        42,
        [],
        {"nodes": "not-a-list", "edges": []},
        {"nodes": [{"id": "x"}], "edges": [{"from": "x", "to": None}]},
        {"nodes": [None, 123, {"id": "a", "trust": "untrusted"}], "edges": [{"from": None}]},
    ],
)
def test_malformed_graph_returns_allow_not_500(bad_data):
    """Malformed graph payloads must not raise 500; they should return allow."""
    body_json = {
        "event_id": "evt_malformed",
        "event_type": "pre_tool_use",
        "data": bad_data,
    }
    resp = client.post("/event", json=body_json)
    assert resp.status_code == 200
    result = resp.json()
    assert result["verdictHint"] == "allow"
