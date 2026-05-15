# secrets-detector

Detects credentials and secrets in agent tool calls using pure in-process regex pattern matching — no network calls at request time.

Every `pre_tool_use` event is scanned across three text surfaces: the tool's name, its input, and the event's `data` field. If a credential pattern matches, the tool returns a `deny` verdict for high/critical risk findings or an `allow` with an elevated risk score for medium risk findings.

## What it detects

| Rule ID | Pattern target | Risk score | Verdict |
|---|---|---|---|
| `SECRET-PEM-01` | PEM private key headers (`RSA`, `EC`, `OPENSSH`, `DSA`) | 95 | deny |
| `SECRET-AWS-AKIA-01` | AWS access key IDs (`AKIA…`, `ASIA…`) | 90 | deny |
| `SECRET-GITHUB-PAT-01` | GitHub PATs (`ghu_`, `gho_`, `ghp_`, `ghs_`, `ghr_`) | 85 | deny |
| `SECRET-ANTHROPIC-01` | Anthropic API keys (`sk-ant-…`) | 85 | deny |
| `SECRET-SLACK-01` | Slack tokens (`xoxb-`, `xoxa-`, `xoxp-`, `xoxr-`, `xoxs-`) | 80 | deny |
| `SECRET-JWT-01` | JSON Web Tokens (two `eyJ…` segments) | 75 | deny |
| `SECRET-BEARER-01` | `Bearer <token>` with ≥16-char token | 70 | deny |

All findings map to `threat_category: credential_detection`. The verdict is `deny` when `score_to_severity` returns `high` (70–89) or `critical` (≥90).

When multiple patterns fire in the same event, the highest-risk finding drives the verdict. All findings are captured and could be surfaced via enrichment in a future version.

## Tuning

| Environment variable | Default | Effect |
|---|---|---|
| `OPENLATCH_SECRETS_DETECTOR_PORT` | `8082` | Listening port (local dev / supervisor override) |

There are no false-positive suppression knobs in v0.1.0. If a rule fires on a known-safe pattern in your environment, open an issue against `openlatch-sectools`.

## Running tests

```bash
cd tools/secrets-detector
uv sync --extra dev
uv run pytest -q
```

Coverage gate: 70% project / 75% patch (enforced by Codecov in CI).

## Local development

```bash
# From repo root:
npx openlatch-provider listen \
  --provider openlatch-provider.yaml \
  --no-tls --port 8443

# Fire a synthetic event with a test key:
npx openlatch-provider trigger pre_tool_use \
  --binding <bnd_id_from_listen_logs> \
  --tool Bash \
  --input 'AKIAIOSFODNN7EXAMPLE' \
  --no-tls
```

The supervisor will spawn `secrets-detector` on port 8082, poll `/healthz`, then start accepting webhooks. Ctrl+C reaps the child cleanly.
