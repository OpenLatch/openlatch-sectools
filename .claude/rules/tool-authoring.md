# Tool Authoring

How to add a new security tool to `openlatch-sectools`.

## Anatomy of a tool

```
tools/<slug>/
├── openlatch-tool.yaml          # kind: Tool (v2)
├── pyproject.toml               # OR package.json for Node tools
├── uv.lock                      # OR pnpm-lock.yaml
├── README.md                    # one-pager — what it detects, how to tune
├── src/<slug_underscored>/
│   ├── __init__.py              # exports `app` (FastAPI)
│   └── main.py                  # @tool(app, path="/event") detection function
└── tests/
    └── test_detect.py           # pytest-style, but the orchestrator is the runner
```

## The tool contract

Every tool MUST:

1. **Speak the OpenLatch SDK protocol**: receive a `CloudEvent`, return a `Verdict` (≤250 KB). Use `openlatch-tool-sdk` (vendored at `vendor/openlatch-tool-sdk/`; reference it via `[tool.uv.sources] openlatch-tool-sdk = { path = "../../vendor/openlatch-tool-sdk" }` in each tool's `pyproject.toml`).
2. **Expose `/healthz`** that returns 200 with any payload. The supervisor polls this at startup and during steady-state.
3. **Listen on `127.0.0.1:<port>`** — never bind a public interface. The Fly machine is the only network boundary.
4. **Print structured logs to stdout/stderr**. No log files. Fly drains stdout.
5. **Be deterministic by default.** Tools should produce the same verdict for the same input. If a tool has any intentional non-determinism (sampling, probabilistic filtering), document it explicitly in the tool's README.

## Latency budget

| Stage | Budget (p95) |
| ----- | ------------ |
| Provider in-pipeline (HMAC verify + replay-cache + sign) | ≤ 5 ms |
| Tool itself (localhost call) | ≤ 200 ms for synchronous tools |
| Provider response (sign + send) | ≤ 5 ms |

Tools above the synchronous budget MUST declare `execution_mode: async` in their capability. The platform's routing engine penalises bindings that miss the latency target.

## Manifest shape (v2)

`openlatch-tool.yaml` lives next to the tool's source. One file = one editor + one or more tools.

```yaml
schema_version: 2
kind: Tool
editor:
  slug: openlatch
  display_name: OpenLatch
  description: Built-in security tools that ship with the OpenLatch platform. Open-sourced, written against the public openlatch-tool-sdk — the same SDK any community author uses.
  homepage_url: https://openlatch.ai
  docs_url: https://docs.openlatch.ai
tools:
  - slug: shell-guard          # replace with your tool's kebab-slug
    version: 0.1.0
    license: apache-2.0
    description: One sentence.
    hooks_supported: [pre_tool_use]
    agents_supported: [claude-code]
    capabilities:
      - threat_category: shell_dangerous
        execution_mode: sync
        declared_latency_p95_ms: 30
        needs_raw_payload: false
        # needs_prior_config_state: true  # set for stateful detectors (tool-integrity, config-guard)
    process:
      command: ["uv", "run", "uvicorn", "shell_guard:app", "--port", "8083"]
      cwd: "."
      env: {}
      health_check:
        http: { port: 8083, path: /healthz }
      restart:
        max_restarts: 5
        window_seconds: 60
```

**Stateful detectors**: `tool-integrity` (`tool_hash_verification`) and `config-guard` declare `needs_prior_config_state: true`; `config-guard` also declares `needs_raw_payload: true`. These tools read `event.prior_config_state` (the platform feeds prior config-artifact state at call time; the tool itself stays stateless — no database).

**ML/model extras**: any optional model dependency (e.g. the deberta/llm-guard model in `prompt-injection-guard`) MUST be a lazy, optional extra (`[project.optional-dependencies] ml = [...]`). Never bake model weights into the container image; load them on first use, guarded by an env flag.

Add a matching binding to the root `openlatch-provider.yaml`:

```yaml
bindings:
  - tool: openlatch/<slug>@0.1.0
    provider: openlatch-sectools
    local_endpoint: http://127.0.0.1:<port>/event
    declared_latency_p95_ms: 30
    capacity_qps: 50
    priority: 100
    pricing: { tier: free }
    process_override:
      env: {}
```

## Local development loop

```bash
# 1. Sync the tool's deps (shell-guard is the canonical copy-me template)
cd tools/shell-guard
uv sync

# 2. Run the full provider + supervisor locally
cd ../..
npx openlatch-provider listen \
  --provider openlatch-provider.yaml \
  --no-tls --port 8443

# 3. Fire a synthetic event (input 'rm -rf /' → block SHELL-RM-ROOT-01; 'ls' → allow)
npx openlatch-provider trigger pre_tool_use \
  --binding <bnd_id_from_listen_logs> \
  --tool Bash \
  --input 'rm -rf /' \
  --no-tls
```

The supervisor will spawn your tool, wait for `/healthz`, then start accepting webhooks. Crashes restart with exponential backoff; `Ctrl+C` reaps the child.

## Forbidden in a tool

| Forbidden | Why |
| --------- | --- |
| Binding to a public interface (`0.0.0.0`) | Network boundary is the Fly machine, not the tool |
| Persistent state on disk | Tools are stateless; restart at any time |
| Reading `OPENLATCH_*` env vars (other than your own `OPENLATCH_<SLUG>_*`) | The supervisor strips these to avoid leaking provider credentials to tools |
| `print()` for verdict context | Use the SDK's structured `Evidence` / `rationale_summary` fields |
| Network egress to third parties at request time | Pre-cache at startup; the latency budget assumes localhost work only |
| Reading the raw event payload when `needs_raw_payload: false` | The SDK redacts payloads when this flag is false |

## Retiring a tool

1. Delete `tools/<slug>/`.
2. Remove the binding from `openlatch-provider.yaml`.
3. Update the per-tool flag in `codecov.yml` and the per-tool entry in `release-please-config.json`.
4. Run `openlatch-provider bindings delete <bnd_id>` against the platform to unhook the production binding.
