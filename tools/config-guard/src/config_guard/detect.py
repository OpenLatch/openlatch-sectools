# Copyright 2026 OpenLatch, Inc.
# Licensed under the Apache License, Version 2.0 (see LICENSE).
"""Pure detection logic for config-guard.

All functions are side-effect-free (no network, no I/O).  The public
surface is ``run_detectors(event)`` which returns a (possibly empty) list
of Finding objects.

Risk scores here are provisional; the authoritative rule-id table lives in
the openlatch-platform repo.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from openlatch_tool_sdk import CloudEvent, PriorConfigState

# ---------------------------------------------------------------------------
# Low-level character-class helpers
# ---------------------------------------------------------------------------

# Invisible / zero-width characters
_INVISIBLE_CHARS = frozenset(
    [
        "​",  # ZERO WIDTH SPACE
        "‌",  # ZERO WIDTH NON-JOINER
        "‍",  # ZERO WIDTH JOINER
        "‎",  # LEFT-TO-RIGHT MARK
        "‏",  # RIGHT-TO-LEFT MARK
        "⁠",  # WORD JOINER
        "﻿",  # ZERO WIDTH NO-BREAK SPACE (BOM)
        "­",  # SOFT HYPHEN
    ]
)

# TAG characters U+E0000–U+E007F
_TAG_RANGE = (0xE0000, 0xE007F)


def _has_invisible(s: str) -> bool:
    """Return True if *s* contains zero-width/control or TAG codepoints."""
    for ch in s:
        if ch in _INVISIBLE_CHARS:
            return True
        cp = ord(ch)
        if _TAG_RANGE[0] <= cp <= _TAG_RANGE[1]:
            return True
    return False


# BiDi override characters
_BIDI_CHARS = frozenset(
    [
        "‪",  # LEFT-TO-RIGHT EMBEDDING
        "‫",  # RIGHT-TO-LEFT EMBEDDING
        "‬",  # POP DIRECTIONAL FORMATTING
        "‭",  # LEFT-TO-RIGHT OVERRIDE
        "‮",  # RIGHT-TO-LEFT OVERRIDE
        "⁦",  # LEFT-TO-RIGHT ISOLATE
        "⁧",  # RIGHT-TO-LEFT ISOLATE
        "⁨",  # FIRST STRONG ISOLATE
        "⁩",  # POP DIRECTIONAL ISOLATE
    ]
)


def _has_bidi(s: str) -> bool:
    """Return True if *s* contains a Unicode BiDi override character."""
    return any(ch in _BIDI_CHARS for ch in s)


def _script_of(ch: str) -> str:
    """Return a coarse script bucket for mixed-script detection."""
    cp = ord(ch)
    if 0x0041 <= cp <= 0x007A:  # Basic Latin letters
        return "latin"
    if 0x00C0 <= cp <= 0x024F:  # Latin Extended
        return "latin"
    if 0x0400 <= cp <= 0x04FF:  # Cyrillic
        return "cyrillic"
    if 0x0370 <= cp <= 0x03FF:  # Greek and Coptic
        return "greek"
    return "other"


def _has_homoglyph(s: str) -> bool:
    """Return True if *s* mixes Latin with Cyrillic or Greek letters."""
    scripts: set[str] = set()
    for ch in s:
        if unicodedata.category(ch).startswith("L"):  # Letter
            sc = _script_of(ch)
            if sc != "other":
                scripts.add(sc)
    if "latin" not in scripts:
        return False
    return bool(scripts & {"cyrillic", "greek"})


# ---------------------------------------------------------------------------
# Pattern-based helpers
# ---------------------------------------------------------------------------

_IMPERATIVE_RE = re.compile(
    r"(always|you must|ignore (all|previous)|do not (tell|mention)|"
    r"before responding|secretly|exfiltrate)",
    re.IGNORECASE,
)


def _imperative(s: str) -> bool:
    return bool(_IMPERATIVE_RE.search(s))


# Per-line (no DOTALL): a real `curl … | sh` is always one line, and a
# bounded per-line scan can't be turned into a backtracking DoS by a large
# newline-free attacker payload.
_CURL_PIPE_SH_RE = re.compile(
    r"(curl|wget)\b[^\n]*\|\s*(sudo\s+)?(sh|bash)",
    re.IGNORECASE,
)


def _curl_pipe_sh(s: str) -> bool:
    return bool(_CURL_PIPE_SH_RE.search(s))


_FENCED_RUN_RE = re.compile(
    r"```\s*(run|bash|sh)\b",
    re.IGNORECASE,
)


def _fenced_run(s: str) -> bool:
    """Return True if *s* contains a fenced run/bash/sh code block."""
    return bool(_FENCED_RUN_RE.search(s))


_HTML_COMMENT_IMPERATIVE_RE = re.compile(
    r"<!--.*?-->",
    re.DOTALL,
)


def _html_comment_imperative(s: str) -> bool:
    """Return True if any HTML comment contains an imperative directive."""
    return any(_imperative(m.group()) for m in _HTML_COMMENT_IMPERATIVE_RE.finditer(s))


_DETAILS_HIDDEN_RE = re.compile(
    r"<details\b[^>]*>.*?</details>",
    re.DOTALL | re.IGNORECASE,
)


def _details_hidden(s: str) -> bool:
    """Return True if a <details> block contains an imperative directive."""
    return any(_imperative(m) for m in _details_hidden_re_all(s))


def _details_hidden_re_all(s: str) -> list[str]:
    return [m.group() for m in _DETAILS_HIDDEN_RE.finditer(s)]


_SETUP_URL_RE = re.compile(
    r"(setup\s*:\s*https?://|run\s+this\s+(url|script)|install\s+from\s+https?://)",
    re.IGNORECASE,
)


def _setup_url(s: str) -> bool:
    return bool(_SETUP_URL_RE.search(s))


# Shell metacharacters that indicate RCE risk in hook commands
_SHELL_META_RE = re.compile(r"[;&|`$(){}<>]|&&|\|\|")


def _shell_meta(s: str) -> bool:
    return bool(_SHELL_META_RE.search(s))


# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    rule_id: str
    risk_score: int
    threat_category: str = "configuration_threat"
    summary: str = ""
    axes: dict[str, int] = field(
        default_factory=lambda: {
            "destructive": 4,
            "exfil": 8,
            "secret": 6,
            "privesc": 8,
            "reversibility": 4,
        }
    )
    user_facing: str | None = None


# ---------------------------------------------------------------------------
# Per-family detectors
# ---------------------------------------------------------------------------

# ── Helpers ────────────────────────────────────────────────────────────────


def _artifact_hash(d: dict[str, Any]) -> str:
    """Stable hash of the fields we compare for rug-pull detection."""
    raw = "|".join(
        [
            str(d.get("name", "")),
            str(d.get("description", "")),
            str(d.get("command", "")),
        ]
    )
    return hashlib.sha256(raw.encode()).hexdigest()


def _extract_host(url: str) -> str | None:
    try:
        return urlparse(url).hostname
    except Exception:
        return None


_URL_RE = re.compile(r"https?://[^\s\"'>]+", re.IGNORECASE)


def _extract_urls_from_text(text: str) -> list[str]:
    return _URL_RE.findall(text)


# ── MCP detectors ──────────────────────────────────────────────────────────


def _detect_mcp(data: dict[str, Any], prior: PriorConfigState | None) -> list[Finding]:
    findings: list[Finding] = []
    name = str(data.get("name", ""))
    description = str(data.get("description", ""))
    url = str(data.get("url", data.get("homepage", "")))

    # MCP-POISON-UNICODE-01
    if _has_invisible(name) or _has_invisible(description):
        findings.append(
            Finding(
                rule_id="MCP-POISON-UNICODE-01",
                risk_score=85,
                summary="Invisible or zero-width Unicode characters detected in MCP name/description",
                axes={
                    "destructive": 4,
                    "exfil": 10,
                    "secret": 6,
                    "privesc": 10,
                    "reversibility": 4,
                },
            )
        )

    # MCP-POISON-BIDI-01
    if _has_bidi(name) or _has_bidi(description):
        findings.append(
            Finding(
                rule_id="MCP-POISON-BIDI-01",
                risk_score=88,
                summary="BiDi override characters detected in MCP name/description",
                axes={
                    "destructive": 4,
                    "exfil": 12,
                    "secret": 6,
                    "privesc": 12,
                    "reversibility": 4,
                },
            )
        )

    # MCP-POISON-HOMOGLYPH-01
    if _has_homoglyph(name):
        findings.append(
            Finding(
                rule_id="MCP-POISON-HOMOGLYPH-01",
                risk_score=80,
                summary="Mixed-script confusable (homoglyph) characters detected in MCP name",
                axes={"destructive": 4, "exfil": 8, "secret": 6, "privesc": 10, "reversibility": 4},
            )
        )

    # MCP-POISON-IMPERATIVE-01
    if _imperative(description):
        findings.append(
            Finding(
                rule_id="MCP-POISON-IMPERATIVE-01",
                risk_score=82,
                summary="Imperative injection directive detected in MCP description",
                axes={
                    "destructive": 4,
                    "exfil": 10,
                    "secret": 8,
                    "privesc": 10,
                    "reversibility": 4,
                },
            )
        )

    # MCP-POISON-URLMISMATCH-01
    declared_host = _extract_host(url) if url else None
    if declared_host:
        desc_urls = _extract_urls_from_text(description)
        for du in desc_urls:
            desc_host = _extract_host(du)
            if desc_host and desc_host != declared_host:
                findings.append(
                    Finding(
                        rule_id="MCP-POISON-URLMISMATCH-01",
                        risk_score=75,
                        summary=(
                            f"URL host in description ({desc_host!r}) does not match "
                            f"declared url host ({declared_host!r})"
                        ),
                        axes={
                            "destructive": 4,
                            "exfil": 10,
                            "secret": 6,
                            "privesc": 8,
                            "reversibility": 4,
                        },
                    )
                )
                break  # one finding per artifact is enough

    # MCP-RUGPULL-01 (stateful)
    if prior is not None and prior.prior_artifact_payload is not None:
        prev = prior.prior_artifact_payload
        prev_hash = _artifact_hash(prev)
        curr_hash = _artifact_hash(data)
        if prev_hash != curr_hash:
            findings.append(
                Finding(
                    rule_id="MCP-RUGPULL-01",
                    risk_score=88,
                    summary="MCP server definition changed since last observation (rug-pull candidate)",
                    axes={
                        "destructive": 8,
                        "exfil": 10,
                        "secret": 8,
                        "privesc": 14,
                        "reversibility": 8,
                    },
                )
            )

    return findings


# ── Skill detectors ─────────────────────────────────────────────────────────

_SKILL_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{0,63}$")


def _detect_skill(data: dict[str, Any], prior: PriorConfigState | None) -> list[Finding]:
    findings: list[Finding] = []
    name = str(data.get("name", ""))
    description = str(data.get("description", ""))
    body = str(data.get("body", data.get("content", "")))

    # SKILL-NAME-01
    if not _SKILL_NAME_RE.match(name):
        findings.append(
            Finding(
                rule_id="SKILL-NAME-01",
                risk_score=60,
                summary=f"Skill name {name!r} does not match required pattern [a-z0-9][a-z0-9-]{{0,63}}",
                axes={"destructive": 2, "exfil": 4, "secret": 4, "privesc": 6, "reversibility": 2},
            )
        )

    # SKILL-NAME-HOMOGLYPH-01
    if _has_homoglyph(name) or _has_bidi(name) or _has_invisible(name):
        findings.append(
            Finding(
                rule_id="SKILL-NAME-HOMOGLYPH-01",
                risk_score=80,
                summary="Homoglyph, BiDi, or invisible characters detected in skill name",
                axes={"destructive": 4, "exfil": 8, "secret": 6, "privesc": 10, "reversibility": 4},
            )
        )

    # SKILL-DESC-LEN-01
    if len(description) > 1024:
        findings.append(
            Finding(
                rule_id="SKILL-DESC-LEN-01",
                risk_score=55,
                summary=f"Skill description length {len(description)} exceeds 1024-character limit",
                axes={"destructive": 2, "exfil": 6, "secret": 4, "privesc": 4, "reversibility": 2},
            )
        )

    # SKILL-INJECT-UNICODE-01
    if (
        _has_invisible(description)
        or _has_invisible(body)
        or _has_bidi(description)
        or _has_bidi(body)
    ):
        findings.append(
            Finding(
                rule_id="SKILL-INJECT-UNICODE-01",
                risk_score=82,
                summary="Invisible or BiDi Unicode characters detected in skill description/body",
                axes={
                    "destructive": 4,
                    "exfil": 10,
                    "secret": 6,
                    "privesc": 10,
                    "reversibility": 4,
                },
            )
        )

    # SKILL-INJECT-DETAILS-01
    if _details_hidden(body) or _details_hidden(description):
        findings.append(
            Finding(
                rule_id="SKILL-INJECT-DETAILS-01",
                risk_score=78,
                summary="<details>-hidden imperative instructions detected in skill body",
                axes={"destructive": 4, "exfil": 8, "secret": 6, "privesc": 10, "reversibility": 4},
            )
        )

    # SKILL-INJECT-COMMENT-01
    if _html_comment_imperative(body) or _html_comment_imperative(description):
        findings.append(
            Finding(
                rule_id="SKILL-INJECT-COMMENT-01",
                risk_score=76,
                summary="HTML/Markdown comment hiding imperative directives detected in skill",
                axes={"destructive": 4, "exfil": 8, "secret": 6, "privesc": 8, "reversibility": 4},
            )
        )

    # SKILL-INJECT-FENCED-RUN-01
    if _fenced_run(body):
        findings.append(
            Finding(
                rule_id="SKILL-INJECT-FENCED-RUN-01",
                risk_score=80,
                summary="Fenced run/bash/sh code block detected in skill body",
                axes={"destructive": 6, "exfil": 8, "secret": 6, "privesc": 10, "reversibility": 6},
            )
        )

    # SKILL-INJECT-CURL-01
    if _curl_pipe_sh(body) or _curl_pipe_sh(description):
        findings.append(
            Finding(
                rule_id="SKILL-INJECT-CURL-01",
                risk_score=85,
                summary="curl|wget piped to shell detected in skill body",
                axes={
                    "destructive": 8,
                    "exfil": 14,
                    "secret": 8,
                    "privesc": 12,
                    "reversibility": 6,
                },
            )
        )

    # SKILL-COLLISION-01 (stateful)
    if prior is not None and name in prior.sibling_skill_names:
        findings.append(
            Finding(
                rule_id="SKILL-COLLISION-01",
                risk_score=75,
                summary=f"Skill name {name!r} collides with an existing sibling skill",
                axes={"destructive": 4, "exfil": 6, "secret": 6, "privesc": 10, "reversibility": 4},
            )
        )

    return findings


# ── Rules file detectors ────────────────────────────────────────────────────


def _detect_rules(data: dict[str, Any], prior: PriorConfigState | None) -> list[Finding]:  # noqa: ARG001
    findings: list[Finding] = []
    content = str(data.get("content", data.get("body", "")))

    # RULES-INJECT-UNICODE-01
    if _has_invisible(content) or _has_bidi(content):
        findings.append(
            Finding(
                rule_id="RULES-INJECT-UNICODE-01",
                risk_score=82,
                summary="Invisible or BiDi Unicode characters detected in rules file content",
                axes={
                    "destructive": 4,
                    "exfil": 10,
                    "secret": 6,
                    "privesc": 10,
                    "reversibility": 4,
                },
            )
        )

    # RULES-INJECT-COMMENT-01
    if _html_comment_imperative(content):
        findings.append(
            Finding(
                rule_id="RULES-INJECT-COMMENT-01",
                risk_score=76,
                summary="HTML/Markdown comment hiding imperative directives in rules file",
                axes={"destructive": 4, "exfil": 8, "secret": 6, "privesc": 8, "reversibility": 4},
            )
        )

    # RULES-INJECT-DETAILS-01
    if _details_hidden(content):
        findings.append(
            Finding(
                rule_id="RULES-INJECT-DETAILS-01",
                risk_score=78,
                summary="<details>-hidden imperative instructions detected in rules file",
                axes={"destructive": 4, "exfil": 8, "secret": 6, "privesc": 10, "reversibility": 4},
            )
        )

    # RULES-INJECT-FENCED-RUN-01
    if _fenced_run(content):
        findings.append(
            Finding(
                rule_id="RULES-INJECT-FENCED-RUN-01",
                risk_score=80,
                summary="Fenced run/bash/sh code block detected in rules file",
                axes={"destructive": 6, "exfil": 8, "secret": 6, "privesc": 10, "reversibility": 6},
            )
        )

    # RULES-INJECT-CURL-01
    if _curl_pipe_sh(content):
        findings.append(
            Finding(
                rule_id="RULES-INJECT-CURL-01",
                risk_score=85,
                summary="curl|wget piped to shell detected in rules file content",
                axes={
                    "destructive": 8,
                    "exfil": 14,
                    "secret": 8,
                    "privesc": 12,
                    "reversibility": 6,
                },
            )
        )

    # RULES-INJECT-SETUP-URL-01
    if _setup_url(content):
        findings.append(
            Finding(
                rule_id="RULES-INJECT-SETUP-URL-01",
                risk_score=72,
                summary="Setup/install URL directive detected in rules file content",
                axes={"destructive": 6, "exfil": 8, "secret": 6, "privesc": 8, "reversibility": 4},
            )
        )

    return findings


# ── Hooks detectors ─────────────────────────────────────────────────────────

_OPENLATCH_HOOK_KEY_RE = re.compile(r"openlatch", re.IGNORECASE)


def _is_openlatch_hook_key(key: str) -> bool:
    return bool(_OPENLATCH_HOOK_KEY_RE.search(key))


def _hook_command_str(hook_val: Any) -> str:
    """Extract a flattened command string from a hook value (str, list, or dict)."""
    if isinstance(hook_val, str):
        return hook_val
    if isinstance(hook_val, list):
        return " ".join(str(v) for v in hook_val)
    if isinstance(hook_val, dict):
        # Common shape: {"command": "...", ...}
        cmd = hook_val.get("command", "")
        if isinstance(cmd, list):
            return " ".join(str(v) for v in cmd)
        return str(cmd)
    return str(hook_val)


def _detect_hooks(data: dict[str, Any], prior: PriorConfigState | None) -> list[Finding]:
    findings: list[Finding] = []
    hooks: dict[str, Any] = data.get("hooks", {}) or {}

    # HOOKS-RCE-01
    for hook_key, hook_val in hooks.items():
        cmd_str = _hook_command_str(hook_val)
        if _shell_meta(cmd_str) or _curl_pipe_sh(cmd_str):
            findings.append(
                Finding(
                    rule_id="HOOKS-RCE-01",
                    risk_score=92,
                    summary=(
                        f"Hook {hook_key!r} command contains shell metacharacters "
                        f"or curl-pipe-shell pattern (potential RCE)"
                    ),
                    axes={
                        "destructive": 16,
                        "exfil": 14,
                        "secret": 10,
                        "privesc": 18,
                        "reversibility": 14,
                    },
                )
            )
            break  # one finding per artifact

    # HOOKS-DISABLE-OPENLATCH-01 (stateful)
    if prior is not None and prior.prior_hooks_block is not None:
        prev_hooks: dict[str, Any] = prior.prior_hooks_block or {}
        for prev_key in prev_hooks:
            if not _is_openlatch_hook_key(prev_key):
                continue
            # Fired if the key is absent OR its value is empty/falsy
            current_val = hooks.get(prev_key)
            if current_val is None or current_val == "" or current_val == [] or current_val == {}:
                findings.append(
                    Finding(
                        rule_id="HOOKS-DISABLE-OPENLATCH-01",
                        risk_score=90,
                        summary=(
                            f"OpenLatch hook {prev_key!r} was present in prior config "
                            f"but is now missing or disabled"
                        ),
                        axes={
                            "destructive": 12,
                            "exfil": 12,
                            "secret": 10,
                            "privesc": 16,
                            "reversibility": 10,
                        },
                    )
                )
                break  # one finding per artifact

    return findings


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


# Cap any single attacker-controlled string field before the regex
# detectors touch it. Real config artifacts are far smaller; clipping keeps
# every scan linear and bounded regardless of payload size.
_MAX_SCAN = 64 * 1024


def _clip_strings(data: dict[str, Any]) -> dict[str, Any]:
    return {k: (v[:_MAX_SCAN] if isinstance(v, str) else v) for k, v in data.items()}


def run_detectors(event: CloudEvent) -> list[Finding]:
    """Dispatch to the appropriate family of detectors based on ``data.kind``.

    Returns an empty list for a clean artifact.
    """
    raw: dict[str, Any] = event.data if isinstance(event.data, dict) else {}
    data = _clip_strings(raw)
    prior: PriorConfigState | None = event.prior_config_state
    kind = str(data.get("kind", "")).lower()

    if kind == "mcp":
        return _detect_mcp(data, prior)
    if kind == "skill":
        return _detect_skill(data, prior)
    if kind == "rules":
        return _detect_rules(data, prior)
    if kind == "hooks":
        return _detect_hooks(data, prior)

    # Unknown kind — allow (no opinion)
    return []
