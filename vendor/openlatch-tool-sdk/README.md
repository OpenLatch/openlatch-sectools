# openlatch-tool-sdk

Standard Webhooks v1 verify/sign + FastAPI decorator for OpenLatch
detection tools (Python). Pairs with `openlatch-provider listen` (HMAC
verification happens there) or stands on its own when the tool server is
exposed publicly.

## Install

```bash
pip install 'openlatch-tool-sdk[fastapi]'
```

## FastAPI

```python
from openlatch_tool_sdk import CloudEvent, Verdict, tool
from fastapi import FastAPI

app = FastAPI()

@tool(app, path="/event", secret=None)  # secret=os.environ["OPENLATCH_WHSEC"] for standalone
async def detect(event: CloudEvent) -> Verdict:
    text = str((event.tool_call.input if event.tool_call else None) or {})
    if "AKIA" in text:
        return Verdict(
            risk_score=99,
            severity_hint="critical",
            verdict_hint="deny",
            rule_id="aws.access_key",
            rationale_summary="AWS access key detected",
        )
    return Verdict(risk_score=5, severity_hint="low", verdict_hint="allow")
```

## Direct API

```python
from openlatch_tool_sdk import compute_signature, sign_response, verify
```

## Verdict shape

Pydantic models are configured with `alias_generator=to_camel`, so wire
JSON uses camelCase (`riskScore`, `severityHint`, …) per
`provider-call.schema.json`, while Python code uses snake_case naturally.

## Per-action scoring + config state

Optional v2 contract additions (camelCase on the wire, snake_case in Python):

```python
from openlatch_tool_sdk import (
    ActionScore, CloudEvent, Verdict, score_to_severity,
)

async def detect(event: CloudEvent) -> Verdict:
    # Stateful config/integrity detectors: prior artifact state arrives as
    # the CloudEvents `priorconfigstate` extension when the capability
    # declares `needs_prior_config_state: true` in the manifest.
    prior = event.prior_config_state
    risk = 87
    return Verdict(
        risk_score=risk,
        severity_hint=score_to_severity(risk),
        verdict_hint="deny",
        actions=[
            ActionScore(
                action_ref="cmd:0",                  # "{kind}:{index}" join key
                risk_score=risk,
                severity=score_to_severity(risk),
                threat_category="shell_dangerous",   # routing 12-category
                axes={"destructive": 18, "exfil": 0, "secret": 0,
                      "privesc": 0, "reversibility": 20},
            )
        ],
    )
```

- **`Verdict.actions`** — optional `list[ActionScore]` (≤256). Absent ⇒ the
  platform records per-action risk as null (gap-tolerant). Each
  `action_ref` is the platform-emitted `"{kind}:{index}"` join key.
- **`CloudEvent.prior_config_state`** — typed view of the `priorconfigstate`
  CloudEvents extension; populated only for capabilities declaring
  `needs_prior_config_state: true`.
- **`score_to_severity(risk_score)`** — canonical `<40 / 40-69 / 70-89 /
  90+` buckets. **First-party tools MUST derive `severity` from this** so
  the bucket invariant holds by construction (the platform trusts the
  provider-reported severity verbatim).

## Cross-impl HMAC parity

Test fixtures and signed outputs are byte-identical between this SDK,
`@openlatch/tool-sdk` (npm), and `runtime/webhook.rs` in the
`openlatch-provider` Rust binary. The same `whsec_<base64>` secret +
`<id>.<timestamp>.<raw-body>` payload + base64(HMAC-SHA256) framing is
used by all three.

## Releases

`openlatch-tool-sdk` is released in lock-step with `openlatch-provider`
via release-please. Land conventional-commit PRs against `main`;
release-please opens a Release PR bumping all three packages
(`openlatch-provider` on crates.io + npm, `openlatch-tool-sdk` on PyPI,
`@openlatch/tool-sdk` on npm). Merging the Release PR creates a `v*`
tag and the unified `publish.yml` workflow publishes everything via
OIDC trusted publishing.
