# Copyright 2026 OpenLatch, Inc.
# Licensed under the Apache License, Version 2.0 (see LICENSE).
"""Tool-integrity detection tool — FastAPI app + supervisor entry point.

Detects poisoned, typosquatted, and tampered tool/MCP definitions by running
stateless detectors over the tool name, description, schema, and (optionally)
a platform-supplied prior-config hash baseline.

HMAC verification is handled by ``openlatch-provider listen`` upstream, so the
SDK ``@tool`` decorator is mounted with no ``secret=`` argument.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

from fastapi import FastAPI
from openlatch_tool_sdk import (
    ActionAxes,
    ActionScore,
    CloudEvent,
    UserFacing,
    Verdict,
    score_to_severity,
    tool,
)

from tool_integrity.detect import Finding, run_detectors

app = FastAPI(title="tool-integrity")


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    """Liveness/readiness probe consumed by ``openlatch-provider listen``.

    The supervisor polls this endpoint to decide when the tool is up at
    startup and to detect crashes during steady-state. Returning 200 with
    any payload is enough.
    """
    return {"status": "ok"}


def _score_request_actions(event: CloudEvent, dominant: Finding | None) -> list[ActionScore] | None:
    """Build per-action scores from ``event.data["actions"]`` if present."""
    if not isinstance(event.data, dict):
        return None
    raw_actions = event.data.get("actions")
    if not raw_actions or not isinstance(raw_actions, list):
        return None
    if dominant is None:
        return None

    scores: list[ActionScore] = []
    for i, item in enumerate(raw_actions):
        if not isinstance(item, dict):
            continue
        action_ref = (
            item.get("action_ref") or item.get("actionRef") or f"{item.get('kind', 'action')}:{i}"
        )
        action_ref = str(action_ref)[:64]
        axes_dict = dominant.axes
        action_score = ActionScore(
            action_ref=action_ref,
            risk_score=dominant.risk_score,
            severity=score_to_severity(dominant.risk_score),
            threat_category=dominant.threat_category,
            axes=ActionAxes(
                destructive=int(axes_dict.get("destructive", 0)),
                exfil=int(axes_dict.get("exfil", 0)),
                secret=int(axes_dict.get("secret", 0)),
                privesc=int(axes_dict.get("privesc", 0)),
                reversibility=int(axes_dict.get("reversibility", 0)),
            ),
        )
        scores.append(action_score)
    return scores or None


@tool(app, path="/event")
async def detect(event: CloudEvent) -> Verdict:
    started = time.perf_counter()
    findings = run_detectors(event)

    if not findings:
        verdict = Verdict(
            verdict_hint="allow",
            risk_score=0,
            rule_id=None,
            rationale_summary="tool definition clean",
        )
        dominant: Finding | None = None
    else:
        # Pick the highest-risk finding as the dominant signal
        dominant = max(findings, key=lambda f: f.risk_score)
        severity = score_to_severity(dominant.risk_score)
        verdict_hint = "deny" if severity in ("high", "critical") else "allow"

        user_facing: UserFacing | None = None
        if dominant.user_facing:
            user_facing = UserFacing(
                headline=f"[{dominant.rule_id}] Suspicious tool definition detected",
                body=dominant.user_facing,
            )

        actions = _score_request_actions(event, dominant)

        verdict = Verdict(
            risk_score=dominant.risk_score,
            severity_hint=severity,
            verdict_hint=verdict_hint,
            rule_id=dominant.rule_id,
            rationale_summary=dominant.summary,
            user_facing=user_facing,
            actions=actions,
        )

    latency_ms = int((time.perf_counter() - started) * 1000)
    log: dict[str, Any] = {
        "event_id": event.event_id,
        "findings": len(findings),
        "verdict_hint": verdict.verdict_hint,
        "risk_score": verdict.risk_score,
        "rule_id": verdict.rule_id,
        "latency_ms": latency_ms,
    }
    print(json.dumps(log), flush=True)

    return verdict


def main() -> None:
    import asyncio
    import sys

    import uvicorn

    # Windows: switch off ProactorEventLoop. Its socket-cleanup path logs a
    # harmless ConnectionResetError traceback whenever the supervisor's
    # /healthz probe pool recycles a connection — purely cosmetic noise.
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    port = int(os.environ.get("OPENLATCH_TOOL_INTEGRITY_PORT", "8085"))
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")


if __name__ == "__main__":
    main()
