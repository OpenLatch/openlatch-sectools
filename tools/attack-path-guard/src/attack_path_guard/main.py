# Copyright 2026 OpenLatch, Inc.
# Licensed under the Apache License, Version 2.0 (see LICENSE).
"""Attack-path-guard detection tool.

MCPhound-style attack-path analysis: builds a NetworkX reachability graph
from event.data's resource/permission topology and flags paths from untrusted
sources to sensitive sinks, including privilege-escalation edges.

Execution model: async (declared in openlatch-tool.yaml). HMAC verification
is handled by ``openlatch-provider listen`` upstream; this tool runs on
localhost and trusts the inbound request by the time it arrives.
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

from .detect import Finding, run_detectors

app = FastAPI(title="attack-path-guard")


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    """Liveness/readiness probe consumed by ``openlatch-provider listen``.

    The supervisor polls this endpoint to decide when the tool is up at
    startup and to detect crashes during steady-state. Returning 200 with
    any payload is enough.
    """
    return {"status": "ok"}


def _score_request_actions(event: CloudEvent, dominant: Finding) -> list[ActionScore] | None:
    """Map event.data["actions"] list into ActionScore objects.

    Each item in the list is expected to have at least ``action_ref`` and
    ``kind`` fields.  Missing or malformed entries are skipped.  Returns
    None if event.data has no "actions" key or the list is empty.
    """
    data = event.data
    if not isinstance(data, dict):
        return None
    raw_actions = data.get("actions")
    if not raw_actions or not isinstance(raw_actions, list):
        return None

    result: list[ActionScore] = []
    for i, item in enumerate(raw_actions):
        if not isinstance(item, dict):
            continue
        action_ref = str(
            item.get("action_ref") or item.get("actionRef") or f"{item.get('kind', 'action')}:{i}"
        )[:64]
        result.append(
            ActionScore(
                action_ref=action_ref,
                risk_score=dominant.risk_score,
                severity=score_to_severity(dominant.risk_score),
                threat_category=dominant.threat_category,
                axes=ActionAxes(
                    destructive=int(dominant.axes.get("destructive", 0)),
                    exfil=int(dominant.axes.get("exfil", 0)),
                    secret=int(dominant.axes.get("secret", 0)),
                    privesc=int(dominant.axes.get("privesc", 0)),
                    reversibility=int(dominant.axes.get("reversibility", 0)),
                ),
            )
        )

    return result if result else None


@tool(app, path="/event")
async def detect(event: CloudEvent) -> Verdict:
    started = time.perf_counter()

    findings = run_detectors(event.data)

    if not findings:
        verdict = Verdict(
            verdict_hint="allow",
            risk_score=0,
            rule_id=None,
            rationale_summary="no attack path",
        )
        dominant: Finding | None = None
    else:
        # Pick the highest-risk finding as the dominant one
        dominant = max(findings, key=lambda f: f.risk_score)
        severity = score_to_severity(dominant.risk_score)
        # Deny if high or critical
        verdict_hint = "deny" if severity in ("high", "critical") else "allow"
        actions = _score_request_actions(event, dominant)
        verdict = Verdict(
            verdict_hint=verdict_hint,
            risk_score=dominant.risk_score,
            severity_hint=severity,
            rule_id=dominant.rule_id,
            rationale_summary=dominant.rationale_summary,
            actions=actions,
        )

    latency_ms = int((time.perf_counter() - started) * 1000)
    log_record: dict[str, Any] = {
        "event_id": event.event_id,
        "verdict_hint": verdict.verdict_hint,
        "risk_score": verdict.risk_score,
        "rule_id": verdict.rule_id,
        "finding_count": len(findings),
        "latency_ms": latency_ms,
    }
    print(json.dumps(log_record), flush=True)

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

    port = int(os.environ.get("OPENLATCH_ATTACK_PATH_GUARD_PORT", "8086"))
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")


if __name__ == "__main__":
    main()
