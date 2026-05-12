# Logging

`openlatch-sectools` runs on Fly. Logging follows Fly's contract: **stdout/stderr only**, structured, no log files.

## What goes where

| Surface | Contract | Consumer |
| ------- | -------- | -------- |
| Tool stdout/stderr | Free-form by the tool, but should be structured JSON one-line-per-event | Fly logs (`flyctl logs`) |
| Provider tracing | `@openlatch/provider` emits structured `tracing` events; JSON when non-TTY (true in production) | Fly logs |
| Provider audit JSONL | One record per processed event at `~/.openlatch/provider/logs/runtime-YYYY-MM-DD.jsonl` | Mounted on a Fly volume (`sectools_audit`) — the only persistent surface |

The provider's audit JSONL is what we use to debug "what verdict did this event get". `flyctl logs` is what we use to debug "did the process even start".

## Tool logging guidance

A Python tool should print one JSON object per event:

```python
print(json.dumps({
    "event_id": event.event_id,
    "rule_id": "coinflip.deny",
    "verdict_hint": verdict.verdict_hint,
    "risk_score": verdict.risk_score,
    "latency_ms": latency_ms,
}), flush=True)
```

`flush=True` matters — without it, Python buffers until the tool exits.

## Forbidden

| Forbidden | Why |
| --------- | --- |
| Writing log files inside the container | Container is ephemeral; logs would die with the machine |
| Calling out to a logging SaaS from a tool | All observability flows through Fly logs / audit JSONL |
| `logging.basicConfig(level=DEBUG)` in a tool | Default `INFO` is the convention; debug only on `--verbose` runs locally |
| Logging binding secrets or `Authorization` headers | Never — even in `--debug`, the provider redacts them and we should too |
| Logging the raw event payload | PII risk; log the event's metadata (id, hook, agent) only |

## No Prometheus / metrics

We deliberately do not run a metrics agent or expose a `/metrics` endpoint. Reasons:

1. The platform-side aggregator already has every verdict — there's no metric we'd compute here that isn't already computable there.
2. A `/metrics` endpoint is one more thing to authenticate.
3. Cardinality control is hard; per-binding labels would blow up Prometheus.

If a tool genuinely needs internal metrics, emit them as structured stdout lines and parse them out of Fly logs.

## Audit JSONL fields (provider-owned)

Documented here for reference only — `@openlatch/provider` owns the schema (see `openlatch-provider/.claude/rules/logging.md`):

| Field | Type | Notes |
| ----- | ---- | ----- |
| `timestamp` | RFC 3339 UTC | When processed |
| `event_id` | string | From inbound webhook |
| `binding_id` | string | Which binding routed it |
| `verdict_hint` | string | `allow` / `flag` / `block` |
| `risk_score` | int 0-100 | From verdict |
| `processing_ms` | int | Provider in-pipeline time (excluding tool) |
| `tool_ms` | int | Tool's localhost call duration |
| `outcome` | string | `delivered` / `tool_unreachable` / `tool_5xx` / `oversize` / `timeout` |
