# Copyright 2026 OpenLatch, Inc.
# Licensed under the Apache License, Version 2.0 (see LICENSE).
"""Smoke tests for the shell-guard tool.

Covers the contract surface the supervisor relies on:
- /healthz returns 200
- /event returns a shaped verdict for safe and dangerous commands
- action scoring echoes action_ref + threat_category
- JSON round-trip on the verdict shape
"""

from __future__ import annotations

import json

from fastapi.testclient import TestClient
from shell_guard import app

client = TestClient(app)


def _post(command: str, data: dict | None = None) -> dict:
    body: dict = {
        "event_id": "evt_test",
        "event_type": "pre_tool_use",
        "agent": {"platform": "claude-code"},
        "tool_call": {"name": "Bash", "input": {"command": command}},
    }
    if data is not None:
        body["data"] = data
    response = client.post("/event", json=body)
    assert response.status_code == 200, response.text
    return response.json()


# ---------------------------------------------------------------------------
# Basic contract tests
# ---------------------------------------------------------------------------


def test_healthz_returns_200():
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_safe_command_returns_allow():
    body = _post("ls -la")
    assert body["verdictHint"] == "allow"
    assert body["riskScore"] == 0


def test_rm_rf_root_returns_deny():
    body = _post("rm -rf /")
    assert body["verdictHint"] == "deny"
    assert body["ruleId"] == "SHELL-RM-ROOT-01"
    assert body["riskScore"] >= 90


# ---------------------------------------------------------------------------
# Action scoring echo test
# ---------------------------------------------------------------------------


def test_data_actions_are_echoed():
    """Post a dangerous command with data.actions; verify ActionScore fields."""
    body = _post(
        "rm -rf /",
        data={"actions": [{"kind": "command", "action_ref": "command:0"}]},
    )
    assert body["verdictHint"] == "deny"
    assert "actions" in body
    assert len(body["actions"]) >= 1
    action = body["actions"][0]
    assert action["actionRef"] == "command:0"
    assert action["threatCategory"] == "shell_dangerous"
    assert action["riskScore"] >= 90


def test_data_actions_missing_does_not_crash():
    """When data has no actions list, actions field is absent."""
    body = _post("rm -rf /", data={"other": "stuff"})
    assert body["verdictHint"] == "deny"
    # actions should be absent when no actions list in data
    assert "actions" not in body or body.get("actions") is None


# ---------------------------------------------------------------------------
# JSON round-trip
# ---------------------------------------------------------------------------


def test_response_is_valid_json():
    body = _post("rm -rf /")
    json.dumps(body)


def test_allow_response_is_valid_json():
    body = _post("git status")
    json.dumps(body)
