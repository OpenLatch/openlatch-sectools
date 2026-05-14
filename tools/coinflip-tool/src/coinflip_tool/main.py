# Copyright 2026 OpenLatch, Inc.
# Licensed under the Apache License, Version 2.0 (see LICENSE).
"""Coinflip detection tool — randomly returns allow/deny verdicts.

A faithful consumer of the public ``openlatch-tool-sdk`` package, used to
exercise the OpenLatch end-to-end pipeline (agent → openlatch-client →
openlatch-platform → openlatch-provider listen → THIS tool) without
writing real detection logic. HMAC verification is handled by
``openlatch-provider listen`` upstream, so the SDK ``@tool`` decorator is
mounted with no ``secret=`` argument.
"""

from __future__ import annotations

import json
import os
import random
import time

from fastapi import FastAPI
from openlatch_tool_sdk import CloudEvent, Evidence, UserFacing, Verdict, tool

app = FastAPI(title="coinflip-tool")


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    """Liveness/readiness probe consumed by ``openlatch-provider listen``.

    The supervisor polls this endpoint to decide when the tool is up at
    startup and to detect crashes during steady-state. Returning 200 with
    any payload is enough.
    """
    return {"status": "ok"}


def _deny_threshold() -> int:
    raw = os.environ.get("OPENLATCH_COINFLIP_DENY_PCT", "30")
    try:
        value = int(raw)
    except ValueError:
        value = 30
    return max(0, min(100, value))


@tool(app, path="/event")
async def detect(event: CloudEvent) -> Verdict:
    started = time.perf_counter()
    threshold = _deny_threshold()
    roll = random.randint(0, 99)

    if roll < threshold:
        verdict = Verdict(
            risk_score=min(100, 85 + (roll % 15)),
            severity_hint="high",
            verdict_hint="deny",
            rule_id="coinflip.deny",
            rationale_summary=(f"coinflip rolled {roll} below deny threshold {threshold}"),
            user_facing=UserFacing(
                headline="Coinflip detector denied this action",
                body=(
                    "The coinflip-tool is a synthetic detector that randomly "
                    "denies a configurable percentage of requests. Tune via "
                    "OPENLATCH_COINFLIP_DENY_PCT (0-100)."
                ),
                evidence=[
                    Evidence(label="roll", value_redacted=str(roll)),
                    Evidence(label="threshold", value_redacted=str(threshold)),
                ],
            ),
        )
    else:
        verdict = Verdict(
            verdict_hint="allow",
            risk_score=5,
            rationale_summary=f"coinflip rolled {roll} >= deny threshold {threshold}",
        )

    latency_ms = int((time.perf_counter() - started) * 1000)
    print(
        json.dumps(
            {
                "event_id": event.event_id,
                "roll": roll,
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

    port = int(os.environ.get("OPENLATCH_COINFLIP_PORT", "8081"))
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")


if __name__ == "__main__":
    main()
