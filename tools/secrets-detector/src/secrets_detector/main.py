# Copyright 2026 OpenLatch, Inc.
# Licensed under the Apache License, Version 2.0 (see LICENSE).
"""Secrets-detector detection tool — credential detection via regex patterns.

Scans the text surface of every ``pre_tool_use`` event (tool call name,
input, and event data) for credential patterns: AWS access keys, GitHub
PATs, Anthropic API keys, Slack tokens, JWTs, Bearer tokens, and PEM
private keys. HMAC verification is handled upstream by
``openlatch-provider listen``; the SDK ``@tool`` decorator is mounted with
no ``secret=`` argument.
"""

from __future__ import annotations

import json
import os
import time

from fastapi import FastAPI
from openlatch_tool_sdk import (
    ActionAxes,
    ActionScore,
    CloudEvent,
    Verdict,
    score_to_severity,
    tool,
)

from secrets_detector.detect import Finding, run_detectors

app = FastAPI(title="secrets-detector")


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    """Liveness/readiness probe consumed by ``openlatch-provider listen``.

    The supervisor polls this endpoint to decide when the tool is up at
    startup and to detect crashes during steady-state. Returning 200 with
    any payload is enough.
    """
    return {"status": "ok"}


def _score_request_actions(event: CloudEvent, finding: Finding) -> list[ActionScore] | None:
    """Build per-action scores when the event data carries an actions list.

    Returns ``None`` when ``event.data`` is not a dict or has no non-empty
    ``actions`` list.
    """
    data = event.data
    if not isinstance(data, dict):
        return None
    raw_actions = data.get("actions")
    if not isinstance(raw_actions, list) or not raw_actions:
        return None

    sev = score_to_severity(finding.risk_score)
    scores: list[ActionScore] = []
    for i, item in enumerate(raw_actions):
        action_ref = (
            item.get("action_ref") or item.get("actionRef") or f"{item.get('kind', 'action')}:{i}"
        )
        # Truncate to the SDK limit of 64 chars
        action_ref = action_ref[:64]
        scores.append(
            ActionScore(
                action_ref=action_ref,
                risk_score=finding.risk_score,
                severity=sev,
                threat_category=finding.threat_category,
                axes=ActionAxes(**finding.axes),
            )
        )
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
            rationale_summary="no credentials detected",
        )
    else:
        dominant = max(findings, key=lambda f: f.risk_score)
        sev = score_to_severity(dominant.risk_score)
        verdict = Verdict(
            risk_score=dominant.risk_score,
            severity_hint=sev,
            verdict_hint="deny" if sev in ("high", "critical") else "allow",
            rule_id=dominant.rule_id,
            rationale_summary=dominant.summary,
            user_facing=dominant.user_facing,
            actions=_score_request_actions(event, dominant),
        )

    latency_ms = int((time.perf_counter() - started) * 1000)
    print(
        json.dumps(
            {
                "event_id": event.event_id,
                "rule_id": verdict.rule_id,
                "verdict_hint": verdict.verdict_hint,
                "risk_score": verdict.risk_score,
                "latency_ms": latency_ms,
            }
        ),
        flush=True,
    )

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

    port = int(os.environ.get("OPENLATCH_SECRETS_DETECTOR_PORT", "8082"))
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")


if __name__ == "__main__":
    main()
