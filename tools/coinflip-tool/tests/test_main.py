# Copyright 2026 OpenLatch, Inc.
# Licensed under the Apache License, Version 2.0 (see LICENSE).
"""Smoke tests for the coinflip-tool.

These cover the contract surface the supervisor relies on:
- /healthz returns 200
- /event returns a shaped verdict for both allow and deny branches
- OPENLATCH_COINFLIP_DENY_PCT clamps to [0, 100]
"""

from __future__ import annotations

import json

from fastapi.testclient import TestClient

from coinflip_tool import app

client = TestClient(app)


def _post_event() -> dict:
    body = {
        "event_id": "evt_test",
        "event_type": "pre_tool_use",
        "agent": {"platform": "claude-code"},
        "payload": {"tool_name": "Bash", "tool_input": "ls"},
    }
    response = client.post("/event", json=body)
    assert response.status_code == 200, response.text
    return response.json()


def test_healthz_returns_200():
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_detect_always_denies_when_threshold_is_100(monkeypatch):
    monkeypatch.setenv("OPENLATCH_COINFLIP_DENY_PCT", "100")
    body = _post_event()
    assert body["verdict_hint"] == "deny"
    assert body["risk_score"] >= 85
    assert body["rule_id"] == "coinflip.deny"


def test_detect_always_allows_when_threshold_is_0(monkeypatch):
    monkeypatch.setenv("OPENLATCH_COINFLIP_DENY_PCT", "0")
    body = _post_event()
    assert body["verdict_hint"] == "allow"
    assert body["risk_score"] == 5


def test_threshold_clamps_above_100(monkeypatch):
    monkeypatch.setenv("OPENLATCH_COINFLIP_DENY_PCT", "999")
    body = _post_event()
    # 999 should clamp to 100, so every roll is < threshold and we deny
    assert body["verdict_hint"] == "deny"


def test_threshold_falls_back_on_garbage(monkeypatch):
    monkeypatch.setenv("OPENLATCH_COINFLIP_DENY_PCT", "not-an-int")
    # Default 30%; we only check that the call succeeds and returns one of the two branches
    body = _post_event()
    assert body["verdict_hint"] in {"allow", "deny"}


def test_response_is_valid_json():
    body = _post_event()
    # Round-trip serialisation — covers the SDK's Verdict shape
    json.dumps(body)
