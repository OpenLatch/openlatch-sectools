"""OpenLatch detection-tool SDK."""

from .hmac_sw import (
    MAX_TIMESTAMP_SKEW_SECS,
    SignedHeaders,
    VerifyError,
    compute_signature,
    decode_secret,
    sign_response,
    verify,
)
from .severity import score_to_severity
from .types import (
    MAX_VERDICT_BYTES,
    ActionAxes,
    ActionScore,
    CloudEvent,
    Evidence,
    PriorConfigState,
    SeverityHint,
    UserFacing,
    Verdict,
    VerdictHint,
)

__all__ = [
    # hmac
    "MAX_TIMESTAMP_SKEW_SECS",
    "SignedHeaders",
    "VerifyError",
    "compute_signature",
    "decode_secret",
    "sign_response",
    "verify",
    # types
    "MAX_VERDICT_BYTES",
    "ActionAxes",
    "ActionScore",
    "CloudEvent",
    "Evidence",
    "PriorConfigState",
    "SeverityHint",
    "UserFacing",
    "Verdict",
    "VerdictHint",
    # severity
    "score_to_severity",
]


def tool(*args, **kwargs):
    """Re-export the FastAPI decorator. Imported lazily so users without
    FastAPI installed can still use the verify/sign primitives."""
    from .fastapi_dec import tool as _tool

    return _tool(*args, **kwargs)
