# Copyright 2026 OpenLatch, Inc.
# Licensed under the Apache License, Version 2.0 (see LICENSE).
"""Attack-path detection logic — pure graph analysis, no network I/O.

Builds a NetworkX DiGraph from the event's resource/permission topology
and runs two detectors:

  ATTACK-PATH-REACHABLE-01  — any path from an untrusted node to a sensitive node
  ATTACK-PATH-PRIVESC-01    — a source→sink path traversing a privilege-escalation edge
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import networkx as nx

# --- trust-label normalisation --------------------------------------------------

_UNTRUSTED_LABELS: frozenset[str] = frozenset({"untrusted", "source", "external"})
_SENSITIVE_LABELS: frozenset[str] = frozenset({"sensitive", "secret", "crown_jewel"})

# Edge `via` values that indicate privilege escalation
_PRIVESC_VIAS: frozenset[str] = frozenset(
    {"sudo", "assume-role", "setuid", "privilege-escalation", "admin"}
)

# Bound graph construction so an attacker-supplied topology can't turn the
# async budget into a DoS. Real config graphs are tiny; these caps are generous.
_MAX_NODES = 2000
_MAX_EDGES = 8000


def _normalise_trust(raw: str) -> str:
    """Map synonyms onto the canonical three-way trust value."""
    lower = raw.lower().strip()
    if lower in _UNTRUSTED_LABELS:
        return "untrusted"
    if lower in _SENSITIVE_LABELS:
        return "sensitive"
    return "internal"


# --- Finding -------------------------------------------------------------------


@dataclass
class Finding:
    rule_id: str
    risk_score: int
    rationale_summary: str
    threat_category: str
    axes: dict[str, int]


# --- Graph builder -------------------------------------------------------------


def _build_graph(data: dict[str, Any]) -> tuple[nx.DiGraph, list[str], list[str]]:
    """Parse nodes/edges from *data* into a DiGraph.

    Returns (graph, untrusted_node_ids, sensitive_node_ids). Malformed
    individual entries (not a dict, missing id/endpoints) are skipped — this
    is attacker-controlled input, so a bad entry is expected, not exceptional.
    """
    graph: nx.DiGraph = nx.DiGraph()
    untrusted: list[str] = []
    sensitive: list[str] = []

    raw_nodes = data.get("nodes")
    raw_nodes = raw_nodes[:_MAX_NODES] if isinstance(raw_nodes, list) else []
    for node in raw_nodes:
        if not isinstance(node, dict) or "id" not in node:
            continue
        node_id = str(node["id"])
        trust = _normalise_trust(str(node.get("trust", "internal")))
        graph.add_node(node_id, trust=trust)
        if trust == "untrusted":
            untrusted.append(node_id)
        elif trust == "sensitive":
            sensitive.append(node_id)

    raw_edges = data.get("edges")
    raw_edges = raw_edges[:_MAX_EDGES] if isinstance(raw_edges, list) else []
    for edge in raw_edges:
        if not isinstance(edge, dict) or "from" not in edge or "to" not in edge:
            continue
        src = str(edge["from"])
        dst = str(edge["to"])
        # Only add edges whose endpoints exist in the graph
        if src in graph and dst in graph:
            graph.add_edge(src, dst, via=str(edge.get("via") or ""))

    return graph, untrusted, sensitive


# --- Detectors ----------------------------------------------------------------


def _detect_reachable(
    graph: nx.DiGraph,
    untrusted: list[str],
    sensitive: list[str],
) -> Finding | None:
    """ATTACK-PATH-REACHABLE-01 — any path from an untrusted node to a sensitive node."""
    best_path: list[str] | None = None
    best_len = float("inf")

    for src in untrusted:
        for sink in sensitive:
            try:
                path = nx.shortest_path(graph, src, sink)
            except nx.NetworkXNoPath:
                continue
            if len(path) < best_len:
                best_len = len(path)
                best_path = path

    if best_path is None:
        return None

    # Escalate risk when the shortest path is very short (≤ 2 hops = direct)
    risk_score = 90 if best_len <= 2 else 80

    path_str = " → ".join(best_path)
    return Finding(
        rule_id="ATTACK-PATH-REACHABLE-01",
        risk_score=risk_score,
        rationale_summary=(f"Untrusted node can reach sensitive node via path: {path_str}"),
        threat_category="attack_path_analysis",
        axes={"destructive": 0, "exfil": 14, "secret": 12, "privesc": 8, "reversibility": 0},
    )


def _detect_privesc(
    graph: nx.DiGraph,
    untrusted: list[str],
    sensitive: list[str],
) -> Finding | None:
    """ATTACK-PATH-PRIVESC-01 — source→sink path traversing a privesc edge."""
    for src in untrusted:
        for sink in sensitive:
            # all_simple_paths yields nothing when the sink is unreachable,
            # so no separate has_path guard is needed. cutoff bounds compute.
            for path in nx.all_simple_paths(graph, src, sink, cutoff=10):
                for u, v in zip(path, path[1:]):
                    via = graph[u][v].get("via", "")
                    if via.lower() in _PRIVESC_VIAS:
                        path_str = " → ".join(path)
                        return Finding(
                            rule_id="ATTACK-PATH-PRIVESC-01",
                            risk_score=85,
                            rationale_summary=(
                                f"Privilege escalation edge '{via}' on path: {path_str}"
                            ),
                            threat_category="attack_path_analysis",
                            axes={
                                "destructive": 0,
                                "exfil": 10,
                                "secret": 10,
                                "privesc": 18,
                                "reversibility": 0,
                            },
                        )
    return None


# --- Public entrypoint --------------------------------------------------------


def run_detectors(data: Any) -> list[Finding]:
    """Run all detectors against *data* and return a (possibly empty) list.

    Returns an empty list for malformed/empty input; genuine internal errors
    propagate (the provider maps a 5xx to OL-4225 — never swallow them).
    """
    if not isinstance(data, dict):
        return []

    graph, untrusted, sensitive = _build_graph(data)
    if not untrusted or not sensitive or graph.number_of_nodes() == 0:
        return []

    findings: list[Finding] = []
    reachable = _detect_reachable(graph, untrusted, sensitive)
    if reachable is not None:
        findings.append(reachable)
    privesc = _detect_privesc(graph, untrusted, sensitive)
    if privesc is not None:
        findings.append(privesc)
    return findings
