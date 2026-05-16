# Copyright 2026 OpenLatch, Inc.
# Licensed under the Apache License, Version 2.0 (see LICENSE).
"""Config-guard detection tool — configuration-plane threat detection.

Detects poisoning, rug-pulls, prompt injection, RCE, and openlatch-hook
disabling across MCP server definitions, Skills, rules files, and hooks.

HMAC verification is handled by ``openlatch-provider listen`` upstream, so
the SDK ``@tool`` decorator is mounted with no ``secret=`` argument.
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

from config_guard.detect import Finding, run_detectors

app = FastAPI(title="config-guard")


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    """Liveness/readiness probe consumed by ``openlatch-provider listen``."""
    return {"status": "ok"}


def _score_request_actions(data: dict, dominant: Finding) -> list[ActionScore] | None:
    """Echo each ``data.actions`` item as an ``ActionScore`` carrying the
    dominant finding's risk, severity, category, and axes (D-05).

    Returns None when the request carries no actions list (gap-tolerant).
    """
    raw_actions = data.get("actions")
    if not isinstance(raw_actions, list) or not raw_actions:
        return None

    scored: list[ActionScore] = []
    for i, item in enumerate(raw_actions):
        if not isinstance(item, dict):
            continue
        action_ref = str(
            item.get("action_ref") or item.get("actionRef") or f"{item.get('kind', 'action')}:{i}"
        )[:64]
        scored.append(
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
    return scored if scored else None


def _finding_to_verdict(
    finding: Finding,
    actions: list[ActionScore] | None,
) -> Verdict:
    severity = score_to_severity(finding.risk_score)
    verdict_hint = "deny" if severity in ("high", "critical") else "allow"
    return Verdict(
        verdict_hint=verdict_hint,
        risk_score=finding.risk_score,
        severity_hint=severity,
        rule_id=finding.rule_id,
        rationale_summary=finding.summary,
        actions=actions,
    )


@tool(app, path="/event")
async def detect(event: CloudEvent) -> Verdict:
    started = time.perf_counter()
    data: dict = event.data if isinstance(event.data, dict) else {}

    findings: list[Finding] = run_detectors(event)

    if not findings:
        verdict = Verdict(
            verdict_hint="allow",
            risk_score=0,
            rule_id=None,
            rationale_summary="config artifact clean",
        )
    else:
        # Pick the finding with the highest risk score as the primary verdict
        top: Finding = max(findings, key=lambda f: f.risk_score)
        verdict = _finding_to_verdict(top, _score_request_actions(data, top))

    latency_ms = int((time.perf_counter() - started) * 1000)
    print(
        json.dumps(
            {
                "event_id": event.event_id,
                "kind": data.get("kind"),
                "findings": len(findings),
                "verdict_hint": verdict.verdict_hint,
                "risk_score": verdict.risk_score,
                "rule_id": verdict.rule_id,
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

    port = int(os.environ.get("OPENLATCH_CONFIG_GUARD_PORT", "8087"))
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")


if __name__ == "__main__":
    main()
