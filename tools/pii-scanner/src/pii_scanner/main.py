# Copyright 2026 OpenLatch, Inc.
# Licensed under the Apache License, Version 2.0 (see LICENSE).
"""PII detection tool — detects email, SSN, credit card, phone, and IP addresses.

Consumes the vendored ``openlatch-tool-sdk`` package. HMAC verification is
handled by ``openlatch-provider listen`` upstream; the ``@tool`` decorator is
mounted with no ``secret=`` argument.
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
    Verdict,
    score_to_severity,
    tool,
)

from pii_scanner.detect import Finding, run_detectors

app = FastAPI(title="pii-scanner")


# ---------------------------------------------------------------------------
# Health probe
# ---------------------------------------------------------------------------


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    """Liveness/readiness probe consumed by ``openlatch-provider listen``.

    The supervisor polls this endpoint to decide when the tool is up at
    startup and to detect crashes during steady-state. Returning 200 with
    any payload is enough.
    """
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _score_request_actions(event: CloudEvent, dominant: Finding) -> list[ActionScore] | None:
    """Build per-action ``ActionScore`` list from ``event.data["actions"]``.

    Returns ``None`` when the event data does not carry an actions list so
    that the Verdict serialiser omits the field entirely (gap-tolerant).
    """
    data: Any = event.data
    if not (isinstance(data, dict) and isinstance(data.get("actions"), list)):
        return None

    scores: list[ActionScore] = []
    for idx, item in enumerate(data["actions"]):
        raw_ref = (
            item.get("action_ref") or item.get("actionRef") or f"{item.get('kind', 'action')}:{idx}"
        )
        action_ref = str(raw_ref)[:64]
        scores.append(
            ActionScore(
                action_ref=action_ref,
                risk_score=dominant.risk_score,
                severity=score_to_severity(dominant.risk_score),
                threat_category=dominant.threat_category,
                axes=ActionAxes(**dominant.axes),
            )
        )
    return scores or None


# ---------------------------------------------------------------------------
# Detection endpoint
# ---------------------------------------------------------------------------


@tool(app, path="/event")
async def detect(event: CloudEvent) -> Verdict:
    started = time.perf_counter()
    findings = run_detectors(event)

    if not findings:
        verdict = Verdict(
            verdict_hint="allow",
            risk_score=0,
            rule_id=None,
            rationale_summary="no PII detected",
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


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    import asyncio
    import sys

    import uvicorn

    # Windows: switch off ProactorEventLoop. Its socket-cleanup path logs a
    # harmless ConnectionResetError traceback whenever the supervisor's
    # /healthz probe pool recycles a connection — purely cosmetic noise.
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    port = int(os.environ.get("OPENLATCH_PII_SCANNER_PORT", "8081"))
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")


if __name__ == "__main__":
    main()
