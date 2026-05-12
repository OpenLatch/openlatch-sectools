# Telemetry

`openlatch-sectools` does not emit its own telemetry. It inherits whatever the bundled `@openlatch/provider` is configured to do, with a few caveats below.

## Defaults

| Surface | Default in this repo |
| ------- | -------------------- |
| `@openlatch/provider` PostHog events | **Off in CI**, opt-in in deployed environments via `OPENLATCH_PROVIDER_POSTHOG_KEY` Fly secret |
| `@openlatch/provider` Sentry crash reports | **On in deployed environments** via `OPENLATCH_PROVIDER_SENTRY_DSN` Fly secret; off in CI |
| Tool-level telemetry | **Off**. Tools must not call third-party telemetry SaaS at runtime |

The provider's 6-level consent precedence still applies (`DO_NOT_TRACK` > `OPENLATCH_TELEMETRY_DISABLED` > CI > consent file > built-in). In Fly we control consent via the secret being set or empty.

## Why opt-in defaults

- Production telemetry on a public security provider is a data-handling decision. Until we have a public privacy notice naming `sectools.openlatch.ai` specifically, we keep PostHog off by leaving the key unset in production secrets.
- Crash reports (Sentry) are higher signal and lower PII risk — they default on once a DSN is set.

## What a tool may emit

- **stdout/stderr** structured JSON lines (see `.claude/rules/logging.md`). These end up in Fly logs.
- **Verdict fields** (`rule_id`, `rationale_summary`, `risk_score`) — consumed by the platform aggregator. This is the canonical "telemetry" path for tool findings.

## What a tool must NOT do

| Forbidden | Why |
| --------- | --- |
| Initialise PostHog / Sentry / Datadog / etc. inside a tool | Provider already owns the telemetry surface; double-emit = double cost + double privacy footprint |
| Read `OPENLATCH_PROVIDER_*` env vars in a tool | The supervisor strips them before spawning the child; even if you could read them, you shouldn't |
| Phone home at startup | Tools are stateless workers; any phone-home introduces a startup dependency the supervisor's `/healthz` probe doesn't see |

## SDK helpers (deferred)

`openlatch-tool-sdk` and `@openlatch/tool-sdk` MAY add SDK-level telemetry helpers later that route through the provider's existing PostHog batch. When that lands, the contract is: tools opt-in by calling an SDK function, and the SDK forwards to the provider's already-configured PostHog client (no separate key). Until then, no tool-level telemetry exists.
