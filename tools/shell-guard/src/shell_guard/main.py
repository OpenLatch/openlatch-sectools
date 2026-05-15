# Copyright 2026 OpenLatch, Inc.
# Licensed under the Apache License, Version 2.0 (see LICENSE).
"""Shell-guard detection tool — dangerous and exfiltration shell command detection.

A first-party consumer of the public ``openlatch-tool-sdk`` package. Detects
destructive shell commands (rm -rf /, fork bombs, disk wipes, setuid abuse)
and exfiltration patterns (curl|sh, reverse shells, data uploads) with 5-axis
risk scoring. HMAC verification is handled by ``openlatch-provider listen``
upstream, so the SDK ``@tool`` decorator is mounted with no ``secret=`` argument.
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

from shell_guard.detect import Finding, run_detectors

app = FastAPI(title="shell-guard")


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    """Liveness/readiness probe consumed by ``openlatch-provider listen``.

    The supervisor polls this endpoint to decide when the tool is up at
    startup and to detect crashes during steady-state. Returning 200 with
    any payload is enough.
    """
    return {"status": "ok"}


def _score_request_actions(event: CloudEvent, d: Finding) -> list[ActionScore] | None:
    """Build ActionScore entries from the event's data.actions list."""
    data = event.data if isinstance(event.data, dict) else {}
    items = data.get("actions") if isinstance(data.get("actions"), list) else []
    out: list[ActionScore] = []
    for i, a in enumerate(items):
        if not isinstance(a, dict):
            continue
        ref = a.get("action_ref") or a.get("actionRef") or f"{a.get('kind', 'action')}:{i}"
        out.append(
            ActionScore(
                action_ref=str(ref)[:64],
                risk_score=d.risk_score,
                severity=score_to_severity(d.risk_score),
                threat_category=d.threat_category,
                axes=ActionAxes(**{k: int(x) for k, x in d.axes.items()}),
            )
        )
    return out or None


@tool(app, path="/event")
async def detect(event: CloudEvent) -> Verdict:
    started = time.perf_counter()
    findings = run_detectors(event)

    if not findings:
        verdict = Verdict(
            verdict_hint="allow",
            risk_score=0,
            rule_id=None,
            rationale_summary="no dangerous shell pattern",
        )
    else:
        d = max(findings, key=lambda f: f.risk_score)
        sev = score_to_severity(d.risk_score)
        verdict = Verdict(
            risk_score=d.risk_score,
            severity_hint=sev,
            verdict_hint="deny" if sev in ("high", "critical") else "allow",
            rule_id=d.rule_id,
            rationale_summary=d.summary,
            user_facing=d.user_facing,
            actions=_score_request_actions(event, d),
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

    port = int(os.environ.get("OPENLATCH_SHELL_GUARD_PORT", "8083"))
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")


if __name__ == "__main__":
    main()
