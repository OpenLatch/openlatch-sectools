# Copyright 2026 OpenLatch, Inc.
# Licensed under the Apache License, Version 2.0 (see LICENSE).
"""Pure-Python detection logic for shell-guard.

No network I/O. All detectors operate on a single text representation of the
command extracted from the inbound CloudEvent.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from openlatch_tool_sdk import CloudEvent, UserFacing


@dataclass
class Finding:
    """A single match from a detector rule."""

    rule_id: str
    risk_score: int
    threat_category: str
    summary: str
    axes: dict[str, int]
    user_facing: UserFacing | None = field(default=None)


# ---------------------------------------------------------------------------
# Command text extraction
# ---------------------------------------------------------------------------


def _extract_command_text(event: CloudEvent) -> str:
    """Build a single flat string that all detectors operate on.

    Priority order for the tool-call input:
    1. ``command`` / ``cmd`` / ``script`` keys from a dict input
    2. JSON-dumped dict when no preferred key exists
    Plus the tool name and str(data) appended for context.
    """
    parts: list[str] = []

    tool_call = event.tool_call
    if tool_call is not None:
        if tool_call.name:
            parts.append(tool_call.name)
        inp = tool_call.input
        if isinstance(inp, dict):
            for key in ("command", "cmd", "script"):
                if key in inp:
                    parts.append(str(inp[key]))
                    break
            else:
                parts.append(json.dumps(inp))
        elif inp is not None:
            parts.append(str(inp))

    if event.data is not None:
        parts.append(str(event.data))

    return " ".join(parts)


# ---------------------------------------------------------------------------
# Individual detectors
# ---------------------------------------------------------------------------


def _detect_rm_root(text: str) -> Finding | None:
    """SHELL-RM-ROOT-01 — recursive force-delete targeting root or home."""
    # Must have rm with both recursive and force flags
    if not re.search(r"\brm\b", text):
        return None
    # Check for combined flags like -rf, -fr, -Rf, --recursive + --force
    has_recursive = bool(re.search(r"\s-[a-zA-Z]*[rR][a-zA-Z]*\b|--recursive\b", text))
    has_force = bool(re.search(r"\s-[a-zA-Z]*f[a-zA-Z]*\b|--force\b", text))
    has_no_preserve = bool(re.search(r"--no-preserve-root", text))

    # Combined short flags: -rf, -fr, -Rf, -rRf, etc.
    has_combined = bool(re.search(r"-[a-zA-Z]*[rR][a-zA-Z]*f|--[a-zA-Z]*f[a-zA-Z]*[rR]", text))

    if not (has_recursive or has_combined) and not has_no_preserve:
        return None
    if not (has_force or has_combined) and not has_no_preserve:
        return None

    # Target must be a dangerous path
    dangerous_target = bool(
        re.search(
            r"(?:^|\s|[&|;`])\s*rm\b[^&|;\n]*(?:"
            r"\s/(?:\s|$|[&|;#])"  # bare / followed by whitespace/end/separator
            r"|\s/\*"  # /*
            r"|\s~(?:/|$|\s)"  # ~ or ~/...
            r"|\s\$HOME(?:/|$|\s)"  # $HOME
            r")",
            text,
        )
    )

    if not dangerous_target and not has_no_preserve:
        return None

    return Finding(
        rule_id="SHELL-RM-ROOT-01",
        risk_score=95,
        threat_category="shell_dangerous",
        summary="rm with recursive+force flags targeting root/home filesystem",
        axes={"destructive": 20, "exfil": 0, "secret": 0, "privesc": 0, "reversibility": 20},
    )


def _detect_forkbomb(text: str) -> Finding | None:
    """SHELL-FORKBOMB-01 — classic fork bomb pattern."""
    # Tolerant regex: variable name, spacing variations
    # Pattern: <name>(){ <name>|<name>& };<name>  (with variations)
    if re.search(
        r"""[:\w]+\s*\(\s*\)\s*\{\s*[:\w]+\s*\|\s*[:\w]+\s*&\s*\}\s*;\s*[:\w]+""",
        text,
    ):
        return Finding(
            rule_id="SHELL-FORKBOMB-01",
            risk_score=90,
            threat_category="shell_dangerous",
            summary="classic shell fork bomb detected",
            axes={"destructive": 18, "exfil": 0, "secret": 0, "privesc": 0, "reversibility": 18},
        )
    return None


def _detect_disk_destroy(text: str) -> Finding | None:
    """SHELL-DISK-DESTROY-01 — dd to raw device, mkfs, wipefs, redirect to /dev/sd*."""
    # dd of=/dev/sd*, /dev/nvme*, /dev/hd*
    if re.search(r"\bdd\b[^&|;\n]*\bof=/dev/(?:sd[a-z]|nvme\d|hd[a-z])", text):
        return Finding(
            rule_id="SHELL-DISK-DESTROY-01",
            risk_score=95,
            threat_category="shell_dangerous",
            summary="dd writing directly to a raw block device",
            axes={"destructive": 20, "exfil": 0, "secret": 0, "privesc": 0, "reversibility": 20},
        )
    # mkfs targeting a block device
    if re.search(r"\bmkfs(?:\.\w+)?\b[^&|;\n]*/dev/(?:sd[a-z]|nvme\d|hd[a-z])", text):
        return Finding(
            rule_id="SHELL-DISK-DESTROY-01",
            risk_score=95,
            threat_category="shell_dangerous",
            summary="mkfs formatting a raw block device",
            axes={"destructive": 20, "exfil": 0, "secret": 0, "privesc": 0, "reversibility": 20},
        )
    # wipefs
    if re.search(r"\bwipefs\b[^&|;\n]*/dev/(?:sd[a-z]|nvme\d|hd[a-z])", text):
        return Finding(
            rule_id="SHELL-DISK-DESTROY-01",
            risk_score=95,
            threat_category="shell_dangerous",
            summary="wipefs erasing a raw block device",
            axes={"destructive": 20, "exfil": 0, "secret": 0, "privesc": 0, "reversibility": 20},
        )
    # redirect to raw block device: > /dev/sda
    if re.search(r">\s*/dev/(?:sd[a-z]|nvme\d|hd[a-z])\b", text):
        return Finding(
            rule_id="SHELL-DISK-DESTROY-01",
            risk_score=95,
            threat_category="shell_dangerous",
            summary="output redirected to a raw block device",
            axes={"destructive": 20, "exfil": 0, "secret": 0, "privesc": 0, "reversibility": 20},
        )
    return None


def _detect_chmod_world(text: str) -> Finding | None:
    """SHELL-CHMOD-WORLD-01 — chmod 777 or a+rwx on root/system paths."""
    if not re.search(r"\bchmod\b", text):
        return None
    # Check for world-writable mode
    has_world_mode = bool(re.search(r"\b(?:777|a\+rwx)\b", text))
    if not has_world_mode:
        return None
    # Check for system path targets
    system_path = bool(
        re.search(
            r"(?:^|[\s,])(?:/\s*$|/etc\b|/usr\b|/bin\b|/sbin\b|/lib\b|/root\b|/boot\b)",
            text,
        )
    )
    if not system_path:
        return None
    return Finding(
        rule_id="SHELL-CHMOD-WORLD-01",
        risk_score=70,
        threat_category="shell_dangerous",
        summary="chmod world-writable permissions on system path",
        axes={"destructive": 0, "exfil": 0, "secret": 0, "privesc": 12, "reversibility": 0},
    )


def _detect_suid(text: str) -> Finding | None:
    """SHELL-SUID-01 — chmod setuid on a binary."""
    if not re.search(r"\bchmod\b", text):
        return None
    # setuid modes: u+s, +s, 4755, 4777, 4700
    # Note: +s starts with non-word char so we can't use \b before it;
    # match it as (?<!\w) to ensure it's not mid-word.
    if re.search(r"(?:u\+s|(?<!\w)\+s|4[0-7]{3})\b", text):
        return Finding(
            rule_id="SHELL-SUID-01",
            risk_score=80,
            threat_category="shell_dangerous",
            summary="chmod setuid bit on a binary — potential privilege escalation vector",
            axes={"destructive": 0, "exfil": 0, "secret": 0, "privesc": 18, "reversibility": 0},
        )
    return None


def _detect_curl_pipe_sh(text: str) -> Finding | None:
    """SHELL-CURL-PIPE-SH-01 — curl/wget output piped to a shell."""
    # curl or wget piped to sh/bash/sudo bash/zsh
    if re.search(
        r"(?:curl|wget)\b[^|&;\n]*\|[^|&;\n]*(?:sudo\s+)?(?:bash|zsh|sh)\b",
        text,
    ):
        return Finding(
            rule_id="SHELL-CURL-PIPE-SH-01",
            risk_score=85,
            threat_category="shell_exfiltration",
            summary="remote script fetched and piped directly to a shell interpreter",
            axes={"destructive": 0, "exfil": 10, "secret": 0, "privesc": 10, "reversibility": 14},
        )
    return None


def _detect_reverse_shell(text: str) -> Finding | None:
    """SHELL-REVERSE-SHELL-01 — reverse shell one-liners."""
    patterns = [
        # bash /dev/tcp
        r"bash\s+-i\s+[>&]+\s*/dev/tcp/",
        # nc -e /bin/sh or /bin/bash
        r"\bnc\b[^&|;\n]*-e\s+/bin/(?:sh|bash)\b",
        r"\bnc\b[^&|;\n]*-c\s+['\"]?/bin/(?:sh|bash)\b",
        # mkfifo | nc
        r"\bmkfifo\b[^&|;\n]*\|[^&|;\n]*\bnc\b",
        # python/perl reverse shell
        r"(?:python\d?|perl)\s+-[ce]\s+['\"].*socket.*connect",
        r"(?:python\d?|perl)\s+-[ce]\s+['\"].*(?:SOCK_STREAM|AF_INET).*connect",
        # socat reverse shell
        r"\bsocat\b[^&|;\n]*(?:TCP|EXEC).*(?:EXEC|TCP).*(?:/bin/(?:sh|bash)|pty)",
    ]
    for pat in patterns:
        if re.search(pat, text, re.IGNORECASE):
            return Finding(
                rule_id="SHELL-REVERSE-SHELL-01",
                risk_score=90,
                threat_category="shell_exfiltration",
                summary="reverse shell command detected — inbound connection from attacker",
                axes={"destructive": 0, "exfil": 18, "secret": 0, "privesc": 0, "reversibility": 0},
            )
    return None


def _detect_exfil_curl(text: str) -> Finding | None:
    """SHELL-EXFIL-CURL-01 — uploading files/data out via curl, nc, or tar|curl."""
    _finding = Finding(
        rule_id="SHELL-EXFIL-CURL-01",
        risk_score=80,
        threat_category="shell_exfiltration",
        summary="data or files being uploaded to a remote host",
        axes={"destructive": 0, "exfil": 18, "secret": 8, "privesc": 0, "reversibility": 0},
    )
    # curl uploading a file: -d @file, --data-binary @file, -T file http
    if re.search(
        r"\bcurl\b[^&|;\n]*(?:-d\s+@|-T\s+\S+\s+http|--data-binary\s+@|--data\s+@)",
        text,
        re.IGNORECASE,
    ):
        return _finding
    # tar piped to curl (exfil archive)
    if re.search(r"\btar\b[^|;\n]*\|[^|;\n]*\bcurl\b", text, re.IGNORECASE):
        return _finding
    # piping output to nc with a host and port — but not a reverse shell (mkfifo|nc pattern)
    if re.search(r"\|[^|;\n]*\bnc\b\s+\S+\s+\d+", text, re.IGNORECASE) and not re.search(
        r"\bmkfifo\b", text, re.IGNORECASE
    ):
        return _finding
    return None


# ---------------------------------------------------------------------------
# Ordered detector list (checked in sequence; all matches collected)
# ---------------------------------------------------------------------------

_DETECTORS = [
    _detect_rm_root,
    _detect_forkbomb,
    _detect_disk_destroy,
    _detect_chmod_world,
    _detect_suid,
    _detect_curl_pipe_sh,
    _detect_reverse_shell,
    _detect_exfil_curl,
]


def run_detectors(event: CloudEvent) -> list[Finding]:
    """Run all detectors against the event and return every finding."""
    text = _extract_command_text(event)
    findings: list[Finding] = []
    for detector in _DETECTORS:
        result = detector(text)
        if result is not None:
            findings.append(result)
    return findings
