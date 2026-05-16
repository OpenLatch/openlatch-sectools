# Copyright 2026 OpenLatch, Inc.
# Licensed under the Apache License, Version 2.0 (see LICENSE).
"""Pure detection logic for the tool-integrity tool.

All detectors are stateless (no I/O, no network). They operate on a tool/MCP
definition extracted from ``event.data`` and return a list of ``Finding``
objects. The caller (``main.py``) aggregates findings into a single ``Verdict``.

Supported detection rule_ids
-----------------------------
TOOL-POISON-UNICODE-01  — invisible / zero-width / control chars in name or description
TOOL-POISON-BIDI-01     — Unicode Bidi override / isolate chars (Trojan-Source)
TOOL-POISON-HOMOGLYPH-01 — mixed Cyrillic/Greek + Latin in tool name
TOOL-POISON-IMPERATIVE-01 — imperative injection keywords in description
TOOL-POISON-URLMISMATCH-01 — URL in description whose host mismatches declared url/homepage
TOOL-TYPOSQUAT-01       — name within edit-distance {1,2} of a known CLI tool
TOOL-HASH-DRIFT-01      — SHA-256 content hash differs from platform-supplied baseline
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import Levenshtein
from openlatch_tool_sdk import CloudEvent

# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    rule_id: str
    risk_score: int
    threat_category: str
    summary: str
    axes: dict[str, int] = field(
        default_factory=lambda: {
            "destructive": 0,
            "exfil": 8,
            "secret": 6,
            "privesc": 4,
            "reversibility": 0,
        }
    )
    user_facing: str | None = None


# ---------------------------------------------------------------------------
# Shared axes baselines
# ---------------------------------------------------------------------------

_POISON_AXES: dict[str, int] = {
    "destructive": 0,
    "exfil": 10,
    "secret": 8,
    "privesc": 6,
    "reversibility": 0,
}

_TYPOSQUAT_AXES: dict[str, int] = {
    "destructive": 0,
    "exfil": 8,
    "secret": 6,
    "privesc": 4,
    "reversibility": 0,
}

_HASH_AXES: dict[str, int] = {
    "destructive": 0,
    "exfil": 10,
    "secret": 8,
    "privesc": 6,
    "reversibility": 0,
}

# ---------------------------------------------------------------------------
# Known CLI / tool registry for typosquatting checks
# ---------------------------------------------------------------------------

_KNOWN_TOOLS: frozenset[str] = frozenset(
    {
        "git",
        "npm",
        "pip",
        "curl",
        "wget",
        "aws",
        "gcloud",
        "kubectl",
        "docker",
        "ssh",
        "bash",
        "python",
        "node",
        "terraform",
        "ansible",
        "jq",
        "make",
    }
)

# ---------------------------------------------------------------------------
# Character-set detectors
# ---------------------------------------------------------------------------

# Zero-width / invisible / soft-hyphen / tag block chars
_INVISIBLE_CODEPOINTS: frozenset[int] = frozenset(
    [
        0x200B,  # ZERO WIDTH SPACE
        0x200C,  # ZERO WIDTH NON-JOINER
        0x200D,  # ZERO WIDTH JOINER
        0x200E,  # LEFT-TO-RIGHT MARK
        0x200F,  # RIGHT-TO-LEFT MARK
        0x2060,  # WORD JOINER
        0xFEFF,  # ZERO WIDTH NO-BREAK SPACE / BOM
        0x00AD,  # SOFT HYPHEN
    ]
)
# Also include the entire Unicode Tags block U+E0000–U+E007F
_TAG_BLOCK_START = 0xE0000
_TAG_BLOCK_END = 0xE007F


def _has_invisible_chars(text: str) -> bool:
    for ch in text:
        cp = ord(ch)
        if cp in _INVISIBLE_CODEPOINTS or (_TAG_BLOCK_START <= cp <= _TAG_BLOCK_END):
            return True
    return False


# Bidi override / isolate chars (Trojan-Source attack vectors)
_BIDI_CODEPOINTS: frozenset[int] = frozenset(
    [
        0x202A,  # LEFT-TO-RIGHT EMBEDDING
        0x202B,  # RIGHT-TO-LEFT EMBEDDING
        0x202C,  # POP DIRECTIONAL FORMATTING
        0x202D,  # LEFT-TO-RIGHT OVERRIDE
        0x202E,  # RIGHT-TO-LEFT OVERRIDE
        0x2066,  # LEFT-TO-RIGHT ISOLATE
        0x2067,  # RIGHT-TO-LEFT ISOLATE
        0x2068,  # FIRST STRONG ISOLATE
        0x2069,  # POP DIRECTIONAL ISOLATE
    ]
)


def _has_bidi_chars(text: str) -> bool:
    return any(ord(ch) in _BIDI_CODEPOINTS for ch in text)


# Homoglyph: Cyrillic (U+0400–U+04FF) or Greek (U+0370–U+03FF) mixed with Latin
_CYRILLIC_RANGE = range(0x0400, 0x0500)
_GREEK_RANGE = range(0x0370, 0x0400)
_LATIN_RANGE = range(0x0041, 0x007B)  # A-Z a-z


def _has_mixed_script_confusable(name: str) -> bool:
    """Return True when *name* mixes Cyrillic/Greek codepoints with Latin."""
    has_latin = any(ord(ch) in _LATIN_RANGE for ch in name)
    has_confusable = any(ord(ch) in _CYRILLIC_RANGE or ord(ch) in _GREEK_RANGE for ch in name)
    return has_latin and has_confusable


# Imperative injection patterns
_IMPERATIVE_RE = re.compile(
    r"(always|you must|before\s+(responding|answering)|"
    r"do not\s+(tell|mention|inform)|ignore\s+(the|all|previous)|"
    r"secretly|exfiltrate)",
    re.IGNORECASE,
)

# URL-in-description pattern
_URL_RE = re.compile(r"https?://[^\s\"'>]+", re.IGNORECASE)

# Sensitive path hint (login, credential, token pages on plain http)
_SENSITIVE_PATH_RE = re.compile(r"/(credential|login|token|auth|password)", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Hash helper
# ---------------------------------------------------------------------------


def _tool_hash(name: str, description: str, schema: Any) -> str:
    payload = f"{name}|{description}|{json.dumps(schema, sort_keys=True, default=str)}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Individual detectors
# ---------------------------------------------------------------------------


def _detect_unicode(name: str, description: str) -> Finding | None:
    for target, label in [(name, "name"), (description, "description")]:
        if _has_invisible_chars(target):
            return Finding(
                rule_id="TOOL-POISON-UNICODE-01",
                risk_score=85,
                threat_category="tool_poison_detection",
                summary=f"Invisible/zero-width/control character detected in tool {label}",
                axes=_POISON_AXES,
                user_facing=(
                    "This tool definition contains hidden Unicode characters that "
                    "may be used to conceal malicious instructions from human reviewers."
                ),
            )
    return None


def _detect_bidi(name: str, description: str) -> Finding | None:
    for target, label in [(name, "name"), (description, "description")]:
        if _has_bidi_chars(target):
            return Finding(
                rule_id="TOOL-POISON-BIDI-01",
                risk_score=88,
                threat_category="tool_poison_detection",
                summary=f"Bidi override/isolate character detected in tool {label} (Trojan-Source)",
                axes=_POISON_AXES,
                user_facing=(
                    "This tool definition uses Unicode bidirectional control characters. "
                    "These are used in Trojan-Source attacks to make malicious content "
                    "appear innocent to human reviewers."
                ),
            )
    return None


def _detect_homoglyph(name: str) -> Finding | None:
    if _has_mixed_script_confusable(name):
        return Finding(
            rule_id="TOOL-POISON-HOMOGLYPH-01",
            risk_score=80,
            threat_category="tool_poison_detection",
            summary="Mixed-script confusable (Cyrillic/Greek + Latin) detected in tool name",
            axes=_POISON_AXES,
            user_facing=(
                "The tool name contains characters from multiple Unicode scripts "
                "(e.g. Cyrillic or Greek mixed with Latin). This is a common homoglyph "
                "attack to impersonate legitimate tool names."
            ),
        )
    return None


def _detect_imperative(description: str) -> Finding | None:
    m = _IMPERATIVE_RE.search(description)
    if m:
        return Finding(
            rule_id="TOOL-POISON-IMPERATIVE-01",
            risk_score=82,
            threat_category="tool_poison_detection",
            summary=f"Imperative injection keyword '{m.group(0)}' found in tool description",
            axes=_POISON_AXES,
            user_facing=(
                "The tool description contains language that attempts to override "
                "agent instructions (prompt injection). Review the tool definition carefully."
            ),
        )
    return None


def _detect_url_mismatch(description: str, declared_url: str | None) -> Finding | None:
    urls_in_desc = _URL_RE.findall(description)
    if not urls_in_desc:
        return None

    declared_host: str | None = None
    if declared_url:
        try:
            declared_host = urlparse(declared_url).hostname
        except Exception:
            declared_host = None

    for url in urls_in_desc:
        try:
            parsed = urlparse(url)
        except Exception:
            continue
        desc_host = parsed.hostname or ""

        # Plain http URL pointing to a credential/login/token path
        if parsed.scheme == "http" and _SENSITIVE_PATH_RE.search(parsed.path):
            return Finding(
                rule_id="TOOL-POISON-URLMISMATCH-01",
                risk_score=75,
                threat_category="tool_poison_detection",
                summary=(
                    f"Insecure HTTP URL to sensitive path '{parsed.path}' in tool description"
                ),
                axes=_POISON_AXES,
                user_facing=(
                    "The tool description contains an insecure HTTP link to a "
                    "credential or login endpoint, which may be used for credential harvesting."
                ),
            )

        # Host mismatch vs declared url/homepage
        if declared_host and desc_host and desc_host != declared_host:
            return Finding(
                rule_id="TOOL-POISON-URLMISMATCH-01",
                risk_score=75,
                threat_category="tool_poison_detection",
                summary=(
                    f"URL in description ({desc_host!r}) does not match "
                    f"declared homepage host ({declared_host!r})"
                ),
                axes=_POISON_AXES,
                user_facing=(
                    "The tool description references a URL whose domain does not match "
                    "the tool's declared homepage. This may indicate a phishing or "
                    "supply-chain substitution attack."
                ),
            )
    return None


def _detect_typosquat(name: str) -> Finding | None:
    candidate = name.lower()
    # If the name exactly matches a known tool, it is not a typosquat
    if candidate in _KNOWN_TOOLS:
        return None
    for known in _KNOWN_TOOLS:
        dist = Levenshtein.distance(candidate, known)
        if dist in (1, 2):
            return Finding(
                rule_id="TOOL-TYPOSQUAT-01",
                risk_score=70,
                threat_category="tool_typosquatting",
                summary=(
                    f"Tool name {name!r} is within edit-distance {dist} of known tool {known!r}"
                ),
                axes=_TYPOSQUAT_AXES,
                user_facing=(
                    f"The tool name is very similar to the well-known tool '{known}'. "
                    "This may be a typosquatting attempt designed to impersonate a "
                    "trusted tool and execute malicious code."
                ),
            )
    return None


def _detect_hash_drift(
    event: CloudEvent, name: str, description: str, schema: Any
) -> Finding | None:
    """Return a finding if the tool's content hash differs from the platform baseline.

    Stateless-tolerant: if ``prior_config_state`` is absent or has no
    ``prior_artifact_payload``, no finding is emitted.
    """
    pcs = event.prior_config_state
    if pcs is None:
        return None
    payload = pcs.prior_artifact_payload
    if not payload:
        return None

    # Accept either a precomputed {"tool_hash": "..."} OR recompute from
    # the artifact's own name/description/schema keys.
    if "tool_hash" in payload:
        baseline_hash = payload["tool_hash"]
    else:
        baseline_name = payload.get("name", "")
        baseline_desc = payload.get("description", "")
        baseline_schema = payload.get("schema", payload.get("input_schema", {}))
        baseline_hash = _tool_hash(baseline_name, baseline_desc, baseline_schema)

    current_hash = _tool_hash(name, description, schema)

    if current_hash != baseline_hash:
        return Finding(
            rule_id="TOOL-HASH-DRIFT-01",
            risk_score=78,
            threat_category="tool_hash_verification",
            summary=(
                f"Tool definition hash has changed: "
                f"baseline={baseline_hash[:16]}… current={current_hash[:16]}…"
            ),
            axes=_HASH_AXES,
            user_facing=(
                "The tool's content hash no longer matches the platform-approved baseline. "
                "The tool definition may have been tampered with since it was last reviewed."
            ),
        )
    return None


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def run_detectors(event: CloudEvent) -> list[Finding]:
    """Run all detectors against the tool definition in *event.data*.

    Returns a (possibly empty) list of ``Finding`` objects.
    """
    data: dict[str, Any] = event.data if isinstance(event.data, dict) else {}

    name: str = data.get("name", "") or ""
    description: str = data.get("description", "") or ""
    schema: Any = data.get("schema", data.get("input_schema", {}))
    declared_url: str | None = data.get("url") or data.get("homepage")

    findings: list[Finding] = []

    for detector in (
        lambda: _detect_unicode(name, description),
        lambda: _detect_bidi(name, description),
        lambda: _detect_homoglyph(name),
        lambda: _detect_imperative(description),
        lambda: _detect_url_mismatch(description, declared_url),
        lambda: _detect_typosquat(name),
        lambda: _detect_hash_drift(event, name, description, schema),
    ):
        result = detector()
        if result is not None:
            findings.append(result)

    return findings
