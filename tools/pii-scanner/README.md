# pii-scanner

Detects **personally identifiable information** (PII) in outbound agent actions and inbound tool responses. Powered by regex recognizers and an optional [Microsoft Presidio](https://microsoft.github.io/presidio/) enrichment pass.

This is a real security tool — not a synthetic demo. It inspects every `pre_tool_use` hook payload for email addresses, US Social Security Numbers, credit card numbers (Luhn-validated), North-American phone numbers, and public IPv4 addresses.

```text
Agent (pre_tool_use hook)
   └─► openlatch-client (localhost:7443)
         └─► openlatch-platform (cloud)
               └─► openlatch-provider listen (the built-in provider that bundles this repo's tools)
                     └─► pii-scanner (THIS — supervised on localhost:8081)
```

## What it detects

| Rule ID | PII Type | Risk Score | Verdict | Notes |
| ------- | -------- | ---------- | ------- | ----- |
| `PII-SSN-01` | US Social Security Number | 80 | **deny** | Regex `\b\d{3}-\d{2}-\d{4}\b`; excludes invalid area codes (000, 666, 9xx) |
| `PII-CC-01` | Credit card number | 80 | **deny** | 13–19 digit sequence passing the Luhn check (spaces/dashes stripped) |
| `PII-EMAIL-01` | Email address | 50 | allow | RFC-ish regex; flagged in audit log |
| `PII-PHONE-01` | North-American phone | 50 | allow | `(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}` |
| `PII-IP-01` | Public IPv4 address | 40 | allow | Excludes RFC1918, loopback, 0.0.0.0 |

`score_to_severity` thresholds: `<40` → low, `40–69` → medium, `70–89` → high, `≥90` → critical.
`verdict_hint: deny` is issued for `high` or `critical` severity (risk score ≥ 70).

## Configuration

| Env var | Default | Effect |
| ------- | ------- | ------ |
| `OPENLATCH_PII_SCANNER_PORT` | `8081` | Port the tool binds on `127.0.0.1`. Must match `local_endpoint` in the root `openlatch-provider.yaml`. |
| `OPENLATCH_PII_SCANNER_PRESIDIO` | `0` | Set to `1` to enable Microsoft Presidio enrichment (requires `pip install presidio-analyzer` + spaCy model). |

The supervisor strips every `OPENLATCH_*` env var before spawning the child to avoid leaking provider credentials, so set tool-private config via `bindings[].process_override.env` in the root `openlatch-provider.yaml`.

## Optional: Presidio enrichment

Install the `ml` extra and a spaCy language model, then set the env var:

```bash
uv sync --extra ml
python -m spacy download en_core_web_lg
OPENLATCH_PII_SCANNER_PRESIDIO=1 uv run uvicorn pii_scanner:app --port 8081
```

Presidio findings are merged with the regex findings (deduplicated by rule_id). The regex path alone covers the most common PII patterns without any extra dependencies.

## Running just this tool

```bash
cd tools/pii-scanner
uv sync
uv run uvicorn pii_scanner:app --port 8081
```

Then in another terminal:

```bash
curl -s http://127.0.0.1:8081/healthz
# {"status":"ok"}

curl -s -X POST http://127.0.0.1:8081/event \
  -H 'content-type: application/json' \
  -d '{"event_id":"evt_test","event_type":"pre_tool_use","agent":{"platform":"claude-code"},"tool_call":{"name":"Bash","input":{"command":"echo my SSN is 123-45-6789"}}}'
```

## Tests

```bash
uv sync --extra dev
uv run pytest
```

Coverage is uploaded to Codecov under the `pii-scanner` flag.
