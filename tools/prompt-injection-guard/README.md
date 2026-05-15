# prompt-injection-guard

Detects prompt-injection attacks targeting AI agents. Ships in the OpenLatch
sectools provider and fires on `pre_tool_use` events for both user-input
injections and tool-response poisoning.

## What it detects

| Rule ID | Risk | Description |
| ------- | ---- | ----------- |
| `INJECT-IGNORE-INSTRUCTIONS-01` | 80 | Attempts to make the agent ignore/disregard its system instructions or prior context |
| `INJECT-SYSTEM-PROMPT-LEAK-01` | 75 | Requests to reveal, repeat, or leak the agent's system prompt or developer message |
| `INJECT-ROLE-OVERRIDE-01` | 78 | Role-jailbreak patterns (DAN, "you are now", "enable developer mode", etc.) |
| `INJECT-TOOL-RESPONSE-POISON-01` | 82 | Malicious instructions embedded in tool output (XML/bracket tags, `AI: you must …`) |
| `INJECT-DEBERTA-01` | ≥70 | Optional ML scan via llm-guard DeBERTa — see below |

The highest-risk finding wins. Any finding with severity `high` (70–89) or
`critical` (≥90) produces `verdictHint: "deny"`. Lower findings produce
`verdictHint: "allow"` (flagged but not blocked).

### Direction

Events with `event_type` containing `"response"` or `"post_tool"`, or with
`data.direction == "tool_response"`, are tagged `injection_tool_response`.
All other events are tagged `injection_user_input`. The `INJECT-TOOL-RESPONSE-POISON-01`
rule always overrides direction to `injection_tool_response` regardless of event type.

## Optional DeBERTa ML scan

The DeBERTa-backed scan is **off by default** (no model download at startup).
Enable it with:

```bash
pip install ".[ml]"
OPENLATCH_PROMPT_INJECTION_GUARD_MODEL=1 uvicorn prompt_injection_guard:app --port 8084
```

The `llm-guard` package and its model weights are fetched lazily on the first
request. Any import or runtime error is silently swallowed — the regex
prefilter result is always returned regardless.

## Tuning

| Variable | Default | Effect |
| -------- | ------- | ------ |
| `OPENLATCH_PROMPT_INJECTION_GUARD_PORT` | `8084` | Listening port (local) |
| `OPENLATCH_PROMPT_INJECTION_GUARD_MODEL` | `""` | Set to `1` to enable DeBERTa scan |

## Running tests

```bash
cd tools/prompt-injection-guard
uv sync --frozen --extra dev
uv run ruff check .
uv run pytest -q
```

Coverage gate: 70% project / 75% patch (enforced by Codecov per-flag threshold).
