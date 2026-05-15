# Copyright 2026 OpenLatch, Inc.
# Licensed under the Apache License, Version 2.0 (see LICENSE).
"""Prompt-injection guard — FastAPI app and ``@tool`` handler.

HMAC verification is handled upstream by ``openlatch-provider listen``;
the ``@tool`` decorator is mounted without a ``secret=`` argument.
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

from prompt_injection_guard.detect import Finding, run_detectors

app = FastAPI(title="prompt-injection-guard")


# ---------------------------------------------------------------------------
# Liveness probe
# ---------------------------------------------------------------------------


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    """Liveness/readiness probe consumed by ``openlatch-provider listen``."""
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Action scoring helper
# ---------------------------------------------------------------------------


def _score_request_actions(event: CloudEvent, d: Finding) -> list[ActionScore] | None:
    """Convert platform-emitted ``data.actions`` entries into ``ActionScore`` objects.

    Returns ``None`` (excluded from verdict JSON) when no actions are present.
    """
    data = event.data if isinstance(event.data, dict) else {}
    items = data.get("actions") if isinstance(data.get("actions"), list) else []
    if not items:
        return None

    sev = score_to_severity(d.risk_score)
    scored: list[ActionScore] = []
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        action_ref = (
            item.get("action_ref") or item.get("actionRef") or f"{item.get('kind', 'action')}:{i}"
        )
        scored.append(
            ActionScore(
                action_ref=str(action_ref)[:64],
                risk_score=d.risk_score,
                severity=sev,
                threat_category=d.threat_category,
                axes=ActionAxes(**{k: int(v) for k, v in d.axes.items()}),
            )
        )
    return scored or None


# ---------------------------------------------------------------------------
# Detection handler
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
            rationale_summary="no injection detected",
        )
    else:
        d = max(findings, key=lambda f: f.risk_score)
        sev = score_to_severity(d.risk_score)
        # The structured channel for the decided threat_category is
        # ActionScore.threat_category inside Verdict.actions. But a request may
        # carry no actions[] block — to stay gap-tolerant (D-04) we ALSO
        # prefix rationale_summary with the rule + category so the decided
        # category is never lost when the structured channel is empty.
        rationale = f"[{d.rule_id} · {d.threat_category}] {d.summary}"
        verdict = Verdict(
            risk_score=d.risk_score,
            severity_hint=sev,
            verdict_hint="deny" if sev in ("high", "critical") else "allow",
            rule_id=d.rule_id,
            rationale_summary=rationale,
            user_facing=d.user_facing,
            actions=_score_request_actions(event, d),
        )

    latency_ms = int((time.perf_counter() - started) * 1000)
    print(
        json.dumps(
            {
                "event_id": event.event_id,
                "verdict_hint": verdict.verdict_hint,
                "risk_score": verdict.risk_score,
                "rule_id": verdict.rule_id,
                "latency_ms": latency_ms,
            }
        ),
        flush=True,
    )

    return verdict


# ---------------------------------------------------------------------------
# Entrypoint
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

    port = int(os.environ.get("OPENLATCH_PROMPT_INJECTION_GUARD_PORT", "8084"))
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")


if __name__ == "__main__":
    main()
