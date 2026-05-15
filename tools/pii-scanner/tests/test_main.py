# Copyright 2026 OpenLatch, Inc.
# Licensed under the Apache License, Version 2.0 (see LICENSE).
"""Contract tests for the pii-scanner FastAPI app.

These cover the surfaces the supervisor relies on:
- /healthz returns 200
- /event returns a Verdict for clean input (allow)
- /event returns a Verdict for SSN input (deny, rule PII-SSN-01)
- /event with data.actions carries ActionScore list in response
- response JSON round-trips cleanly
"""

from __future__ import annotations

import json

from fastapi.testclient import TestClient
from pii_scanner import app

client = TestClient(app)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _event(extra: dict | None = None) -> dict:
    base = {
        "event_id": "evt_test",
        "event_type": "pre_tool_use",
        "agent": {"platform": "claude-code"},
    }
    if extra:
        base.update(extra)
    return base


def _post(extra: dict | None = None) -> dict:
    body = _event(extra)
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
# /event — clean input
# ---------------------------------------------------------------------------


def test_clean_input_allows():
    body = _post({"tool_call": {"name": "Bash", "input": {"command": "ls -la"}}})
    assert body["verdictHint"] == "allow"
    assert body["riskScore"] == 0


# ---------------------------------------------------------------------------
# /event — SSN triggers deny
# ---------------------------------------------------------------------------


def test_ssn_triggers_deny():
    body = _post(
        {
            "tool_call": {
                "name": "Write",
                "input": {"content": "SSN is 123-45-6789"},
            }
        }
    )
    assert body["verdictHint"] == "deny"
    assert body["ruleId"] == "PII-SSN-01"
    assert body["riskScore"] >= 80


# ---------------------------------------------------------------------------
# /event — data.actions produces ActionScore list
# ---------------------------------------------------------------------------


def test_actions_carry_action_scores():
    body = _post(
        {
            "tool_call": {
                "name": "Bash",
                "input": {"command": "echo 123-45-6789"},
            },
            "data": {"actions": [{"kind": "command", "action_ref": "command:0"}]},
        }
    )
    assert body["verdictHint"] == "deny"
    # Real top-level Verdict.actions array (camelCase on the wire)
    assert "actions" in body
    assert "enrichment" not in body
    assert len(body["actions"]) == 1
    act = body["actions"][0]
    assert act["actionRef"] == "command:0"
    assert act["threatCategory"] in ("pii_outbound", "pii_inbound")
    assert act["severity"] == "high"
    assert act["riskScore"] >= 80
    assert act["axes"]["exfil"] == 16
    assert act["axes"]["destructive"] == 0


# ---------------------------------------------------------------------------
# Response JSON round-trip
# ---------------------------------------------------------------------------


def test_response_is_valid_json():
    body = _post({"tool_call": {"name": "Bash", "input": {"x": "send to user@example.com"}}})
    json.dumps(body)  # must not raise
