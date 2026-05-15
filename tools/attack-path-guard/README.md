# attack-path-guard

MCPhound-style attack-path analysis for OpenLatch. Builds a NetworkX reachability
graph from the event's resource/permission topology and flags paths from untrusted
sources to sensitive sinks, including privilege-escalation edges.

## Detection summary

The tool receives a graph description in `event.data` and runs two detectors
in sequence. The highest-risk finding wins.

## Rule table

| rule_id | Trigger | Base risk | Escalated risk |
| ------- | ------- | --------- | -------------- |
| `ATTACK-PATH-REACHABLE-01` | Any path exists from an untrusted node to a sensitive node | 80 | 90 (if shortest path length ≤ 2) |
| `ATTACK-PATH-PRIVESC-01` | A source→sink path traverses an edge whose `via` field is in the privilege-escalation set (`sudo`, `assume-role`, `setuid`, `privilege-escalation`, `admin`) | 85 | — |

Verdicts of `high` or `critical` severity (risk ≥ 70) emit `verdict_hint: deny`.
All others emit `verdict_hint: approve`. No findings emit `verdict_hint: allow`.

## Expected `data` schema

```json
{
  "nodes": [
    { "id": "internet",     "trust": "untrusted"  },
    { "id": "app-server",   "trust": "internal"   },
    { "id": "secrets-store","trust": "sensitive"  }
  ],
  "edges": [
    { "from": "internet",   "to": "app-server"  },
    { "from": "app-server", "to": "secrets-store", "via": "sudo" }
  ],
  "actions": [
    { "action_ref": "path:0" }
  ]
}
```

### `nodes[].trust` synonyms

| Canonical | Accepted synonyms |
| --------- | ----------------- |
| `untrusted` | `source`, `external` |
| `sensitive` | `secret`, `crown_jewel` |
| `internal` | (any other value) |

### `edges[].via` (optional)

Free-form string. Set to one of `sudo`, `assume-role`, `setuid`,
`privilege-escalation`, or `admin` to trigger `ATTACK-PATH-PRIVESC-01`.

### `actions` (optional)

List of agent actions to echo back as `ActionScore` objects. Each item must
contain `action_ref` (or `kind` as a fallback). Scores and axes are derived
from the dominant finding.

## Async execution

This tool declares `execution_mode: async` in `openlatch-tool.yaml` with a
`declared_latency_p95_ms` of 5000 ms. For large graphs with many paths,
NetworkX path enumeration is bounded to `cutoff=10` hops to keep latency
predictable. For production workloads with graphs of > 1000 nodes, consider
pre-computing reachability offline.

## Tuning

| Environment variable | Default | Effect |
| -------------------- | ------- | ------ |
| `OPENLATCH_ATTACK_PATH_GUARD_PORT` | `8086` | Listening port for the tool subprocess |

## Running tests

```bash
cd tools/attack-path-guard
uv sync --extra dev
uv run pytest -q
```

Coverage threshold: 70 % project / 75 % patch (enforced by Codecov).
