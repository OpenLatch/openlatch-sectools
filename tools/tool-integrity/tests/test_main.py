# Copyright 2026 OpenLatch, Inc.
# Licensed under the Apache License, Version 2.0 (see LICENSE).
"""Smoke tests for the tool-integrity FastAPI app.

Tests cover the supervisor contract and the main verdict branches:
- /healthz returns 200
- clean ASCII tool def → allow (risk_score=0)
- name with zero-width char → deny + ruleId=="TOOL-POISON-UNICODE-01"
- hash-drift case → deny + ruleId=="TOOL-HASH-DRIFT-01"
- no prior_config_state → no hash finding
- data.actions echoed as ActionScore list
- json round-trip of verdict
"""

from __future__ import annotations

import hashlib
import json

from fastapi.testclient import TestClient
from tool_integrity import app

client = TestClient(app)


def _post(data: dict, priorconfigstate: dict | None = None) -> dict:
    body: dict = {
        "event_id": "evt_test",
        "event_type": "pre_tool_use",
        "agent": {"platform": "claude-code"},
        "data": data,
    }
    if priorconfigstate is not None:
        body["priorconfigstate"] = priorconfigstate
    response = client.post("/event", json=body)
    assert response.status_code == 200, response.text
    return response.json()


# ------------------------------------------------------------------
# /healthz
# ------------------------------------------------------------------


def test_healthz_returns_200():
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


# ------------------------------------------------------------------
# Clean tool → allow
# ------------------------------------------------------------------


def test_clean_tool_allows():
    body = _post(
        {
            "name": "git",
            "description": "Distributed version control system.",
            "schema": {"type": "object"},
            "url": "https://git-scm.com",
        }
    )
    assert body["verdictHint"] == "allow"
    assert body["riskScore"] == 0


# ------------------------------------------------------------------
# TOOL-POISON-UNICODE-01
# ------------------------------------------------------------------


def test_zero_width_char_in_name_denies():
    # U+200B zero-width space injected into name
    name_with_zwsp = "git​helper"
    body = _post({"name": name_with_zwsp, "description": "A helper tool."})
    assert body["verdictHint"] == "deny"
    assert body["ruleId"] == "TOOL-POISON-UNICODE-01"
    assert body["riskScore"] >= 85


# ------------------------------------------------------------------
# TOOL-HASH-DRIFT-01
# ------------------------------------------------------------------


def _make_hash(name: str, description: str, schema: object) -> str:
    payload = f"{name}|{description}|{json.dumps(schema, sort_keys=True, default=str)}"
    return hashlib.sha256(payload.encode()).hexdigest()


def test_hash_drift_denies():
    name = "safe-tool"
    description = "Does something safe."
    schema = {"type": "object", "properties": {}}

    # The prior state was computed from DIFFERENT content
    prior_name = "safe-tool"
    prior_desc = "Does something safe."
    prior_schema: dict = {}  # different schema → hash will differ
    prior_hash = _make_hash(prior_name, prior_desc, prior_schema)

    body = _post(
        data={"name": name, "description": description, "schema": schema},
        priorconfigstate={
            "prior_artifact_payload": {"tool_hash": prior_hash},
        },
    )
    assert body["verdictHint"] == "deny"
    assert body["ruleId"] == "TOOL-HASH-DRIFT-01"
    assert body["riskScore"] >= 70


def test_no_prior_config_state_no_hash_finding():
    """Without prior_config_state, hash-drift check must not fire."""
    body = _post(
        data={
            "name": "safe-tool",
            "description": "Does something safe.",
            "schema": {"type": "object"},
        }
        # no priorconfigstate key
    )
    # The tool is clean — no other finding should fire either
    assert body["verdictHint"] == "allow"
    assert body.get("ruleId") is None


# ------------------------------------------------------------------
# data.actions echoed as ActionScore list
# ------------------------------------------------------------------


def test_actions_echoed_when_finding_present():
    """When a finding is present AND data.actions is provided, actions appear in verdict."""
    name_with_zwsp = "bad​tool"
    body = _post(
        {
            "name": name_with_zwsp,
            "description": "A poisoned tool.",
            "actions": [
                {"action_ref": "command:0", "kind": "command"},
                {"action_ref": "file:1", "kind": "file"},
            ],
        }
    )
    assert body["verdictHint"] == "deny"
    assert "actions" in body
    actions = body["actions"]
    assert len(actions) == 2
    assert actions[0]["actionRef"] == "command:0"
    assert actions[1]["actionRef"] == "file:1"
    # Each action should carry the dominant finding's risk score
    assert all(a["riskScore"] >= 70 for a in actions)


# ------------------------------------------------------------------
# JSON round-trip
# ------------------------------------------------------------------


def test_response_is_valid_json():
    body = _post({"name": "git", "description": "VCS."})
    json.dumps(body)
