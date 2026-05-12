# Error Handling

`openlatch-sectools` does not own the OpenLatch error-code registry. The bundled `@openlatch/provider` already speaks `OL-42xx` codes for transport, manifest, and runtime errors. Tools in this repo defer to those codes whenever possible.

## What this repo defers to

| Layer | Owns its error codes? | Where defined |
| ----- | --------------------- | ------------- |
| HMAC verify / replay-cache / proxy / manifest validation | `@openlatch/provider` | `openlatch-provider/.claude/rules/error-handling.md` (`OL-42xx`) |
| Supervisor lifecycle (spawn / probe / restart / reap) | `@openlatch/provider` | same (`OL-43xx`) |
| Tool detection logic | The tool itself, returned as a `Verdict` | `openlatch-tool-sdk` |

## What a tool may emit

Inside `detect()`, do not raise unstructured exceptions when you can return a `Verdict` instead. The SDK's `Verdict` carries enough shape to express:

- **`verdict_hint`** (`allow` / `flag` / `block`) — the only thing the agent actually consumes.
- **`risk_score`** (0–100) — used by the routing engine for aggregation.
- **`rationale_summary`** — short text for logs / audit.
- **`user_facing`** — optional, only when the user should see the message.
- **`rule_id`** — your tool's stable identifier for this finding.

If the tool *itself* malfunctions (dependency missing, cache unreachable, model didn't load), let the exception propagate. FastAPI returns 500, the provider returns 502 to the platform with `OL-4225` (localhost tool 5xx), and the platform's routing engine applies the penalty. Don't swallow tool-internal failures into a `verdict_hint: allow`.

## Forbidden patterns

| Forbidden | Use instead |
| --------- | ----------- |
| `raise Exception("…")` inside `@tool` | Return a `Verdict` with `verdict_hint="flag"` if the input is suspicious, or let a real internal error 500 out |
| Inventing new `OL-XXXX` codes inside a tool | The CI/runtime owns the registry; if you need a new code, file an issue against `openlatch-provider` |
| Catching every exception and logging silently | Audit logs are the contract surface — let failures propagate to the provider so they appear in the JSONL audit log |
| Emitting `verdict_hint: allow` on internal error | That hides outages from the routing engine |

## Workflow-level errors

Workflows (`pr-checks.yml`, `deploy.yml`) fail loud:

- Any non-zero exit code from a step fails the workflow.
- `set -euo pipefail` is the default for every multi-line shell block.
- `flyctl deploy` failures **MUST** abort the deploy job; we never push to production on a half-failed staging deploy.

## Telemetry & errors

The bundled provider emits the existing `OL-42xx` telemetry events (`error_emitted`, `webhook_verify_failed`, `proxy_call_failed`, `tool_process_crashed`, etc.). This repo doesn't emit its own telemetry — see `.claude/rules/telemetry.md`.
