# Copyright 2026 OpenLatch, Inc.
# Licensed under the Apache License, Version 2.0 (see LICENSE).
"""Smoke tests for the secrets-detector tool.

Covers the contract surface the supervisor relies on:
- /healthz returns 200
- /event returns a shaped verdict for allow and deny branches
- An AWS key in the payload triggers a deny with the correct rule_id
- actions list in event.data are echoed back as per-action scores
- Response serialises cleanly (camelCase wire format)
"""

from __future__ import annotations

import json

from fastapi.testclient import TestClient
from secrets_detector import app

client = TestClient(app)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_CLEAN_EVENT = {
    "event_id": "evt_clean",
    "event_type": "pre_tool_use",
    "agent": {"platform": "claude-code"},
    "tool_call": {"name": "Bash", "input": {"command": "ls -la"}},
}

_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # canonical test key format

_AWS_EVENT = {
    "event_id": "evt_aws",
    "event_type": "pre_tool_use",
    "agent": {"platform": "claude-code"},
    "tool_call": {"name": "Bash", "input": {"command": f"echo {_AWS_KEY}"}},
}

_AWS_EVENT_WITH_ACTIONS = {
    "event_id": "evt_aws_actions",
    "event_type": "pre_tool_use",
    "agent": {"platform": "claude-code"},
    "tool_call": {"name": "Bash", "input": {"command": f"echo {_AWS_KEY}"}},
    "data": {
        "actions": [
            {"kind": "command", "action_ref": "command:0"},
        ]
    },
}


def _post(body: dict) -> dict:
    response = client.post("/event", json=body)
    assert response.status_code == 200, response.text
    return response.json()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_healthz_returns_200():
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_clean_event_returns_allow():
    body = _post(_CLEAN_EVENT)
    assert body["verdictHint"] == "allow"
    assert body["riskScore"] == 0


def test_aws_key_returns_deny_with_correct_rule_id():
    body = _post(_AWS_EVENT)
    assert body["verdictHint"] == "deny"
    assert body["ruleId"] == "SECRET-AWS-AKIA-01"
    assert body["riskScore"] >= 90


def test_actions_echoed_when_data_has_actions_list():
    body = _post(_AWS_EVENT_WITH_ACTIONS)
    assert body["verdictHint"] == "deny"
    # The SDK surfaces per-action scores via the top-level `actions` array.
    actions = body.get("actions")
    assert (
        actions is not None and len(actions) >= 1
    ), f"expected top-level actions array in response: {body}"
    first = actions[0]
    assert first["actionRef"] == "command:0"
    assert first["riskScore"] >= 90
    assert first["severity"] == "critical"
    assert first["threatCategory"] == "credential_detection"
    assert first["axes"]["secret"] == 20


def test_response_is_valid_json():
    body = _post(_AWS_EVENT)
    # Round-trip serialisation — covers the SDK's Verdict camelCase wire shape
    json.dumps(body)


def test_response_camel_case_keys_present():
    body = _post(_AWS_EVENT)
    # Verify wire-format camelCase (not snake_case)
    assert "verdictHint" in body
    assert "riskScore" in body
    assert "ruleId" in body
