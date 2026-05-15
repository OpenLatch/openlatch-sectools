"""FastAPI decorator that wires a Verdict-returning handler under one route.

Imported lazily by `__init__.py::tool()` so users without FastAPI installed
can still use the verify/sign primitives in `hmac_sw`.
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from typing import Any

from .hmac_sw import VerifyError, sign_response, verify
from .types import MAX_VERDICT_BYTES, CloudEvent, Verdict

# FastAPI is imported at module scope (rather than inside `tool()`) so that
# the `endpoint` function's annotations resolve via `typing.get_type_hints`.
# When `from __future__ import annotations` is active, FastAPI's signature
# introspection looks up forward-reference strings against the function's
# `__globals__` — function-local imports never make it there, and FastAPI
# would misclassify `request: Request` as a Pydantic body / query field.
try:
    from fastapi import HTTPException, Request, Response

    _FASTAPI_AVAILABLE = True
except ImportError:  # pragma: no cover — exercised only when fastapi extra missing
    _FASTAPI_AVAILABLE = False
    HTTPException = Request = Response = None  # type: ignore[assignment]

Handler = Callable[[CloudEvent], Awaitable[Verdict] | Verdict]


def tool(
    app: Any,
    *,
    path: str = "/event",
    secret: str | None = None,
    category: str | None = None,
) -> Callable[[Handler], Handler]:
    """Register `handler` at `path` on `app` (a FastAPI instance).

    When `secret` is set, inbound requests are HMAC-verified per Standard
    Webhooks v1 and outbound responses are signed with the same secret.
    Omit `secret` when running behind `openlatch-provider listen` (which
    handles HMAC verify for you).
    """
    if not _FASTAPI_AVAILABLE:
        raise ImportError(
            "openlatch-tool-sdk[fastapi] not installed; pip install 'openlatch-tool-sdk[fastapi]'"
        )

    def decorator(handler: Handler) -> Handler:
        @app.post(path)
        async def endpoint(request: Request) -> Response:
            started = time.perf_counter()
            raw = await request.body()

            if secret is not None:
                webhook_id = request.headers.get("webhook-id")
                ts_header = request.headers.get("webhook-timestamp")
                sig_header = request.headers.get("webhook-signature")
                if not (webhook_id and ts_header and sig_header):
                    raise HTTPException(
                        status_code=401,
                        detail={"code": "OL-4220", "message": "missing Standard Webhooks headers"},
                    )
                try:
                    verify(secret, webhook_id, int(ts_header), raw, sig_header)
                except VerifyError as e:
                    code = "OL-4226" if e.kind == "timestamp" else "OL-4220"
                    raise HTTPException(
                        status_code=401, detail={"code": code, "message": str(e)}
                    ) from e

            try:
                event = CloudEvent.model_validate_json(raw)
            except Exception as e:
                raise HTTPException(
                    status_code=400,
                    detail={"code": "OL-4221", "message": f"tool body invalid: {e}"},
                ) from e

            result = handler(event)
            if hasattr(result, "__await__"):
                result = await result  # type: ignore[assignment]
            verdict: Verdict = result  # type: ignore[assignment]

            if verdict.latency_ms is None:
                verdict.latency_ms = int((time.perf_counter() - started) * 1000)

            body = verdict.model_dump_json(by_alias=True, exclude_none=True).encode("utf-8")
            if len(body) > MAX_VERDICT_BYTES:
                raise HTTPException(
                    status_code=502,
                    detail={
                        "code": "OL-4223",
                        "message": f"verdict {len(body)} bytes > {MAX_VERDICT_BYTES} cap",
                    },
                )

            headers: dict[str, str] = {"content-type": "application/json"}
            if secret is not None:
                headers.update(sign_response(secret, body).as_dict())
            return Response(content=body, status_code=200, headers=headers)

        endpoint.__name__ = handler.__name__
        return handler

    _ = category  # reserved for telemetry plumbing in P3.T1
    return decorator
