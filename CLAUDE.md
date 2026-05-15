# CLAUDE.md

Project orientation for Claude Code and other agents working in `openlatch-sectools`. Read this first; then drill into `.claude/rules/<topic>.md` for the specific concern you're touching.

## What this repo is

`openlatch-sectools` is the open-source home of the **built-in security tools** that ship with the OpenLatch platform. Every customer gets them out of the box. The tools are written against the `openlatch-tool-sdk` (vendored at `vendor/openlatch-tool-sdk/` — see below) and bundled by the pinned [`@openlatch/provider`](https://www.npmjs.com/package/@openlatch/provider) runtime into a single container image deployed on Fly.io as `sectools.openlatch.ai` (prod) and `sectools-staging.openlatch.ai` (staging).

We open-sourced them so security researchers can study real detection logic, and so anyone authoring a tool has a clone-and-modify starting point. **Any `tools/<slug>/` directory is a self-contained, lift-and-shift OpenLatch tool** — the SDK is the contract.

> **Vendored SDK**: `openlatch-tool-sdk` is vendored at `vendor/openlatch-tool-sdk/` because the PyPI release predates the post-PR1 contract (`Verdict.actions[]`, `prior_config_state`, `score_to_severity`). Each tool's `pyproject.toml` references it via `[tool.uv.sources] openlatch-tool-sdk = { path = "../../vendor/openlatch-tool-sdk" }`. A de-vendor follow-up is tracked in `vendor/README.md`.

### Where this repo sits in the OpenLatch system

```
Agent hook → openlatch-client → openlatch-platform → openlatch-provider listen → tool
   (localhost)      (cloud)                            (THIS REPO @ sectools.openlatch.ai)   (localhost:<port>)
```

This repo operates the **provider stage**: one Fly app per environment, one process per machine (`openlatch-provider listen`), one supervised subprocess per tool binding. See `.claude/rules/openlatch-architecture.md` for the four-repo split and what each repo owns.

## Hard dependency: v2 manifest split

This repo only works against `@openlatch/provider` that supports the v2 manifest split (`kind: Tool` per tool + `kind: Provider` at the root + `tool_paths:` globbing). Until that ships, `pr-checks.yml`'s `manifest-validate` step will fail. See `.claude/rules/openlatch-architecture.md`.

## Repository layout

```
openlatch-sectools/
├── openlatch-provider.yaml      # kind: Provider (v2) — operator manifest, lists bindings
├── package.json                 # pins @openlatch/provider (npm, NOT pnpm — see tech-stack.md)
├── pnpm-workspace.yaml          # for future Node tools under tools/*
├── pyproject.toml               # workspace-level ruff/pytest config
├── Dockerfile                   # multi-stage: base → deps → runtime
├── fly/fly.{staging,production}.toml
├── tools/
│   ├── pii-scanner/             # pii_outbound, pii_inbound — port 8081
│   ├── secrets-detector/        # credential_detection — port 8082
│   ├── shell-guard/             # shell_dangerous, shell_exfiltration — port 8083
│   │   ├── openlatch-tool.yaml  # kind: Tool (v2)
│   │   ├── pyproject.toml       # uv-managed (SDK via vendor path source)
│   │   ├── src/shell_guard/     # FastAPI app, @tool decorator
│   │   └── tests/
│   ├── prompt-injection-guard/  # injection_user_input, injection_tool_response — port 8084
│   ├── tool-integrity/          # tool_poison_detection, tool_typosquatting, tool_hash_verification — port 8085
│   ├── attack-path-guard/       # attack_path_analysis — port 8086 (async, 5000 ms)
│   └── config-guard/            # configuration_threat — port 8087
├── vendor/
│   └── openlatch-tool-sdk/      # vendored SDK (de-vendor tracked in vendor/README.md)
├── scripts/
│   ├── register-and-sync-secrets.sh   # CI: register provider + push binding secrets to Fly
│   ├── verify-no-stale-machines.sh    # CI: post-deploy cleanup
│   └── render-staging-manifest.py     # CI: derive staging manifest from prod
├── .github/workflows/
│   ├── pr-checks.yml            # lint, test, manifest-validate, docker-build, coverage
│   ├── deploy.yml               # build → push → register → deploy staging → smoke → prod
│   ├── release-please.yml       # per-tool Release PRs (monorepo)
│   ├── cleanup-ghcr.yml         # weekly image cleanup
│   └── cleanup-fly-machines.yml # weekly Fly machine cleanup
└── .claude/rules/               # ← topic-specific guardrails; read these
```

## .claude/rules/ index

| File | When to read it |
| ---- | --------------- |
| `openlatch-architecture.md` | First read — situates this repo in the OpenLatch system |
| `tool-authoring.md` | Adding, modifying, or retiring a tool under `tools/<slug>/` |
| `tech-stack.md` | Adding a dependency, changing a runtime, choosing a package manager |
| `naming-conventions.md` | Naming a tool, binding, env var, branch, image tag |
| `security-constraints.md` | Anything touching secrets, signing, HMAC, supply chain |
| `testing.md` | Coverage gates, smoke tests, what NOT to mock |
| `logging.md` | Anything that emits to stdout/stderr or writes audit JSONL |
| `error-handling.md` | Verdict shape, error propagation, `OL-42xx` registry deferral |
| `telemetry.md` | PostHog / Sentry / metrics — defaults and forbiddens |
| `ci-release.md` | Workflows, branch protection, release-please, cleanup jobs |
| `documentation-sync.md` | Any change that adds/renames/retires a tool or schema |

When a rule and CLAUDE.md disagree, the rule wins (rules are higher-resolution).

## Common commands

```bash
# Install pinned runtime + shell-guard deps (use any tool slug you're working on)
npm ci --omit=dev
cd tools/shell-guard && uv sync && cd ../..

# Run the full provider + supervisor locally (no TLS, port 8443)
npx openlatch-provider listen --provider openlatch-provider.yaml --no-tls --port 8443

# Fire a synthetic event (grab bnd_… from listen logs)
npx openlatch-provider trigger pre_tool_use --binding bnd_REPLACE_ME --tool Bash --input 'rm -rf /' --no-tls

# Validate without deploying
npx openlatch-provider register --provider openlatch-provider.yaml --dry-run --skip-preflight
docker build -t openlatch-sectools:local .

# Per-tool tests (run from tool dir)
cd tools/<slug>
uv sync --frozen --extra dev
uv run ruff check .
uv run pytest -q

# Pre-commit hygiene
pre-commit install
pre-commit run --all-files
```

## Non-negotiables (the ones worth surfacing here)

1. **Don't add unstructured exceptions inside a `@tool` function.** Return a `Verdict` (`verdict_hint: "flag"` for suspicious input) or let a genuine internal error 500 out — the provider maps that to `OL-4225`. Never swallow into `verdict_hint: "allow"`. (`error-handling.md`)
2. **Tools bind `127.0.0.1` only.** The Fly machine is the network boundary; tools don't listen publicly. (`tool-authoring.md`)
3. **No log files.** Stdout/stderr only, structured JSON one line per event, `flush=True`. (`logging.md`)
4. **No HMAC re-verification in a tool.** The bundled provider already verified the inbound signature; by the time the tool sees the request, it's trusted. (`security-constraints.md`)
5. **No `OPENLATCH_*` reads inside a tool** other than your own `OPENLATCH_<SLUG>_*` vars. The supervisor strips provider credentials before spawning the child. (`tool-authoring.md`)
6. **No metrics endpoint, no third-party telemetry from a tool.** Verdict fields are the telemetry surface. (`telemetry.md`)
7. **No secrets in committed files.** Binding secrets go through `flyctl secrets set` only. `OPENLATCH_TOKEN` is a GH Environment secret. (`security-constraints.md`)
8. **`@openlatch/provider` is pinned and Dependabot-bumped.** Don't hand-edit `package.json` to upgrade it. (`tech-stack.md`)
9. **Docs ship in the same PR as code.** Stale docs are worse than no docs. (`documentation-sync.md`)
10. **Coverage gate: 70 % project / 75 % patch, per-tool flag.** Failing one tool's flag fails its PR check without dragging the rest of the repo. (`testing.md`)

## Branching, commits, releases

- Branches: `feat/<short-name>`, `fix/<short-name>`, `docs/<short-name>`, `chore/<short-name>`.
- Commits: **Conventional Commits** enforced by `commit-msg` hook. Tool-scoped commits use the tool slug as scope (`feat(shell-guard): …`).
- PRs squash-merge into `main`; `main` deploys via `deploy.yml` (staging → smoke → production).
- Releases: `release-please` opens **one Release PR per tool** (component-prefixed tags like `shell-guard-v0.1.0`). Pre-1.0 — minor bumps allowed for breaking changes inside a tool.

## Tech stack (must-know)

- Python 3.12 + `uv` (NOT pip / poetry / pipenv) for tools.
- Node 22 LTS + `pnpm` for Node tools; root uses `npm` for the single `@openlatch/provider` pin.
- Ruff for Python lint+format. No flake8/black/isort.
- Docker 25+, `flyctl` for ops.
- License allowlist (CI gate): Apache-2.0, MIT, BSD-*, ISC, MPL-2.0. **No GPL/AGPL** in shipped tools.

## When you (the agent) get confused

- **About the architecture?** `.claude/rules/openlatch-architecture.md`.
- **About what to put in a tool?** `.claude/rules/tool-authoring.md` + copy `tools/shell-guard/` as a template (pure-Python, deterministic, no extras).
- **About the CI pipeline?** `.claude/rules/ci-release.md` + the workflow files themselves.
- **About what NOT to do?** Each rule has a "Forbidden" table — search for it.

## What you (the agent) should NOT do

- Don't author `OL-XXXX` error codes here — they live in `openlatch-provider`. File an issue against that repo instead.
- Don't write or edit `@openlatch/provider` source — it lives in a separate repo.
- Don't mock the provider runtime in tests — always run the real bundled binary (`pr-checks.yml` does this).
- Don't add a metrics endpoint or pull in PostHog/Sentry inside a tool.
- Don't bind `0.0.0.0`.
- Don't write log files inside the container.
- Don't store anything in a Fly volume other than the audit JSONL directory.
