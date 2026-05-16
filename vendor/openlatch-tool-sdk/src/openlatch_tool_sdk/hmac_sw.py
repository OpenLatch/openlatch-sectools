"""Standard Webhooks v1 HMAC verify + sign.

The wire-format invariants mirror runtime/webhook.rs in the Rust runtime:
the secret is `whsec_<base64>`, the signed payload is
`<id>.<timestamp>.<raw-body>`, the header is SPACE-delimited multi-entry
where each entry is `vN,<base64>`. Comparison is constant-time via
`hmac.compare_digest`.
"""

from __future__ import annotations

import base64
import hmac
import secrets
import time
from dataclasses import dataclass

MAX_TIMESTAMP_SKEW_SECS = 300


class VerifyError(Exception):
    """Raised when an inbound request fails Standard Webhooks v1 verify.

    `kind` ∈ ``"hmac"`` | ``"timestamp"`` | ``"malformed_header"`` — useful
    for shaping outbound `webhook_verify_failed` telemetry.
    """

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind


def decode_secret(secret: str) -> bytes:
    """Strip `whsec_` prefix and base64-decode. Raises VerifyError on malformed."""
    if not secret.startswith("whsec_"):
        raise VerifyError("hmac", "OL-4220: secret missing whsec_ prefix")
    try:
        return base64.b64decode(secret[len("whsec_") :])
    except Exception as e:
        raise VerifyError("hmac", f"OL-4220: secret base64 decode: {e}") from e


def compute_signature(key: bytes, webhook_id: str, webhook_timestamp: int, body: bytes) -> str:
    """Return the base64-encoded HMAC-SHA256 digest (the `v1,…` payload)."""
    payload = f"{webhook_id}.{webhook_timestamp}.".encode("utf-8") + body
    digest = hmac.new(key, payload, "sha256").digest()
    return base64.b64encode(digest).decode("ascii")


def verify(
    secret: str,
    webhook_id: str,
    webhook_timestamp: int,
    body: bytes,
    signature_header: str,
    *,
    now: float | None = None,
) -> None:
    """Verify a Standard Webhooks v1 inbound request. Raises VerifyError on failure."""
    now_secs = int(now if now is not None else time.time())
    skew = abs(now_secs - webhook_timestamp)
    if skew > MAX_TIMESTAMP_SKEW_SECS:
        raise VerifyError(
            "timestamp",
            f"OL-4226: timestamp skew {skew}s exceeds +/-{MAX_TIMESTAMP_SKEW_SECS}s",
        )

    if not signature_header or not signature_header.strip():
        raise VerifyError("malformed_header", "OL-4220: webhook-signature header empty")

    key = decode_secret(secret)
    expected = compute_signature(key, webhook_id, webhook_timestamp, body).encode("ascii")

    saw_v1 = False
    for entry in signature_header.split():
        sep = entry.find(",")
        if sep == -1:
            continue
        version, candidate = entry[:sep], entry[sep + 1 :]
        if version == "v1":
            saw_v1 = True
            candidate_bytes = candidate.encode("ascii")
            if len(candidate_bytes) == len(expected) and hmac.compare_digest(
                candidate_bytes, expected
            ):
                return
        # v1a (asymmetric) and future versions are silently skipped.

    if not saw_v1:
        raise VerifyError("malformed_header", "OL-4220: no v1 entry in signature header")
    raise VerifyError("hmac", "OL-4220: HMAC signature mismatch")


@dataclass
class SignedHeaders:
    webhook_id: str
    webhook_timestamp: int
    webhook_signature: str

    def as_dict(self) -> dict[str, str]:
        return {
            "webhook-id": self.webhook_id,
            "webhook-timestamp": str(self.webhook_timestamp),
            "webhook-signature": self.webhook_signature,
        }


def sign_response(secret: str, body: bytes) -> SignedHeaders:
    """Sign an outbound response body. Mints fresh `msg_<hex>` id + current ts."""
    key = decode_secret(secret)
    webhook_id = f"msg_{secrets.token_hex(16)}"
    webhook_timestamp = int(time.time())
    sig = compute_signature(key, webhook_id, webhook_timestamp, body)
    return SignedHeaders(
        webhook_id=webhook_id,
        webhook_timestamp=webhook_timestamp,
        webhook_signature=f"v1,{sig}",
    )
