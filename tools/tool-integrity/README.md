# tool-integrity

Detects poisoned, typosquatted, and tampered tool/MCP definitions before an agent
binds them. Part of the OpenLatch built-in security tools (`openlatch-sectools`).

## What it detects

The tool receives a tool/MCP definition in `event.data` (keys: `name`, `description`,
`schema`/`input_schema`, `url`/`homepage`) and runs seven stateless detectors:

| rule_id | Risk | Threat category | What triggers it |
| ------- | ---- | --------------- | ---------------- |
| `TOOL-POISON-UNICODE-01` | 85 | `tool_poison_detection` | Invisible / zero-width / control characters (U+200B–200F, U+2060, U+FEFF, U+00AD, Unicode tag block U+E0000–E007F) in `name` or `description` |
| `TOOL-POISON-BIDI-01` | 88 | `tool_poison_detection` | Bidi override / isolate characters (U+202A–202E, U+2066–2069) — Trojan-Source attack vectors |
| `TOOL-POISON-HOMOGLYPH-01` | 80 | `tool_poison_detection` | Mixed-script confusables: Cyrillic or Greek codepoints intermixed with Latin in `name` |
| `TOOL-POISON-IMPERATIVE-01` | 82 | `tool_poison_detection` | Imperative injection keywords in `description`: `always`, `you must`, `before responding/answering`, `do not tell/mention/inform`, `ignore the/all/previous`, `secretly`, `exfiltrate` |
| `TOOL-POISON-URLMISMATCH-01` | 75 | `tool_poison_detection` | A URL in `description` whose host differs from the declared `url`/`homepage`, or any `http://` link to a credential/login/token path |
| `TOOL-TYPOSQUAT-01` | 70 | `tool_typosquatting` | `name` is within Levenshtein edit-distance {1, 2} of a known CLI tool (`git`, `npm`, `pip`, `curl`, `wget`, `aws`, `gcloud`, `kubectl`, `docker`, `ssh`, `bash`, `python`, `node`, `terraform`, `ansible`, `jq`, `make`) and is not an exact match |
| `TOOL-HASH-DRIFT-01` | 78 | `tool_hash_verification` | SHA-256 content hash of `name\|description\|schema` differs from the platform-supplied baseline in `prior_config_state.prior_artifact_payload` |

## `tool_hash_verification` and `prior_config_state`

`TOOL-HASH-DRIFT-01` is **stateless-tolerant**: if the platform does not supply a
`prior_config_state` (or `prior_artifact_payload` is absent), the detector emits no
finding. When a baseline is present, it accepts either:

- A pre-computed `{"tool_hash": "<sha256hex>"}` in `prior_artifact_payload`, or
- The raw `name`/`description`/`schema` keys of the prior artifact, from which the
  hash is recomputed on the fly.

The platform feeds this state only when the tool's capability declares
`needs_prior_config_state: true` (see `openlatch-tool.yaml`).

## Verdict logic

- No findings → `verdict_hint: allow`, `risk_score: 0`.
- Findings present → dominant = highest risk score; `verdict_hint: deny` when
  `risk_score >= 70`, `approve` otherwise; `severity_hint` derived via
  `score_to_severity`.

## Tuning

| Env var | Default | Purpose |
| ------- | ------- | ------- |
| `OPENLATCH_TOOL_INTEGRITY_PORT` | `8085` | Override the listen port |

## Running locally

```bash
# From tools/tool-integrity/
uv sync --extra dev

# Run all tests
uv run pytest -q

# Start the server (locally, no TLS)
uv run uvicorn tool_integrity:app --port 8085 --host 127.0.0.1
```

## Running via the full provider

From the repo root:

```bash
npx openlatch-provider listen \
  --provider openlatch-provider.yaml \
  --no-tls --port 8443
```

The supervisor spawns this tool automatically and polls `/healthz` before
accepting traffic.
