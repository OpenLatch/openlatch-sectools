# Tech Stack Guardrails

Non-negotiable language and tooling constraints for `openlatch-sectools`.

## Language Requirements

| Layer | Required | Location |
| ----- | -------- | -------- |
| Detection tool (Python) | Python 3.12+ with type hints | `tools/<slug>/` |
| Detection tool (Node/TS) | Node.js 26 + TypeScript 5+ | `tools/<slug>/` |
| Provider runtime | `@openlatch/provider` (pinned in `package.json`) | root |
| Container image | Multi-stage Dockerfile | `Dockerfile` |
| Fly config | TOML | `fly/fly.*.toml` |
| CI / deploy | YAML (GitHub Actions) | `.github/workflows/` |
| Manifests | YAML | `openlatch-provider.yaml` + per-tool `openlatch-tool.yaml` |

## Package Managers

| Ecosystem | Manager | Lock File | Committed |
| --------- | ------- | --------- | --------- |
| Python | `uv` | `tools/<slug>/uv.lock` | Yes |
| Node | `pnpm` (workspace) | `pnpm-lock.yaml` | Yes |
| Root runtime | `npm` (single dep: `@openlatch/provider`) | `package-lock.json` | Yes |

The root `package.json` deliberately uses `npm` (not `pnpm`) because the Dockerfile installs `@openlatch/provider` with `npm ci --omit=dev` — `npm` ships with Node 26 and avoids needing `pnpm install --frozen-lockfile` in the deps layer.

> **Corepack note**: Node 25+ no longer bundles Corepack, so the runtime image does **not** enable it (pnpm is unused in the image — the only Node dependency is installed via `npm ci`). CI installs pnpm explicitly via `pnpm/action-setup`. If a Node tool is ever added to the image, the Dockerfile must install pnpm explicitly (e.g. `npm ci` of a pinned `pnpm`), never `npm install -g`.

## Runtime Versions

- Python 3.12+ (`requires-python = ">=3.11"` in tool `pyproject.toml` to ease lifting; container ships 3.12)
- Node.js 26 (Docker base `node:26-bookworm-slim` + workflows; Dependabot-bumped major)
- Docker 25+
- `flyctl` latest

## Forbidden

| Forbidden | Use Instead | Why |
| --------- | ----------- | --- |
| `pip` / `poetry` / `pipenv` | `uv` | Consistent with `openlatch-platform` and `openlatch-provider` |
| `yarn` for Node tools | `pnpm` (workspace) | Workspace ergonomics, lockfile parity |
| `flake8` / `black` / `isort` | `ruff` | Single tool for lint + format |
| `requests` in Python tools | `httpx` (only if the SDK doesn't already abstract it) | Async support |
| Custom logging libraries | stdout/stderr + Fly log drain | Operational simplicity |
| Hand-rolled HMAC verification in a tool | The bundled `openlatch-provider` already verifies | Don't double-verify |
| `npm install -g` anywhere in the Dockerfile | `npm ci --omit=dev` from the committed `package-lock.json` | Reproducibility |
| Storing tool state in a Fly volume that isn't `/root/.openlatch/provider/logs/` | Make tools stateless | One volume, one purpose |

## Dependency Policy

- `@openlatch/provider` is **pinned by minor version** in `package.json`; Dependabot bumps it weekly. A Dependabot PR is the only path to a runtime upgrade.
- Tool dependencies are pinned in `uv.lock` / `pnpm-lock.yaml` (committed) and bumped by Dependabot per-tool.
- New direct dependencies require justification — prefer stdlib / SDK helpers.
- GitHub Action versions are pinned by SHA (or major-version tag as a fallback) in workflows.
- License allowlist (CI gate): Apache-2.0, MIT, BSD-*, ISC, MPL-2.0. No GPL/AGPL in shipped tools.
