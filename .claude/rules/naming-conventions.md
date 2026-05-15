# Naming Conventions

## Slugs

| Entity | Convention | Example |
| ------ | ---------- | ------- |
| Tool slug (filesystem + manifest) | kebab-case, ≤ 30 chars, lowercase ASCII + `-` | `shell-guard`, `prompt-injection-guard` |
| Tool Python package | underscored slug | `shell_guard` |
| Provider slug | kebab-case, environment-suffixed | `openlatch-sectools`, `openlatch-sectools-staging` |
| Binding slug (used in env var name) | UPPER_SNAKE_CASE of the binding's logical name | `SHELL_GUARD` |
| Editor slug | kebab-case, no suffix | `openlatch` |

## Files & Directories

| Type | Convention |
| ---- | ---------- |
| Python source | snake_case `*.py` |
| TS/JS source | kebab-case files, PascalCase for class-only files |
| Manifests | `openlatch-tool.yaml` (per-tool) / `openlatch-provider.yaml` (root) |
| Fly configs | `fly/fly.<env>.toml` |
| Workflows | `.github/workflows/<verb>.yml` |
| Scripts | `scripts/<verb>-<noun>.{sh,py}` |
| Per-tool README | `tools/<slug>/README.md` |

## Environment Variables

| Pattern | Used for |
| ------- | -------- |
| `OPENLATCH_TOKEN` | Service editor API key (CI only) |
| `OPENLATCH_API_URL` | Platform REST base (defaults to `https://api.openlatch.ai`) |
| `OPENLATCH_BINDING_SECRET_<SLUG_UPPER>` | Per-binding webhook secret (set via `flyctl secrets set`) |
| `OPENLATCH_SECTOOLS_*` | Anything specific to this repo (none in v0; reserved) |
| `OPENLATCH_<TOOL_SLUG_UPPER>_*` | Tool-private config (passed via `process_override.env`) |
| `FLY_API_TOKEN` | Fly deploy auth (CI Environment secret) |
| `CODECOV_TOKEN` | Coverage upload (repo secret) |

## Container tags

| Pattern | Used for |
| ------- | -------- |
| `main-<sha>` | Immutable per-commit tag — required for forensics |
| `latest` | Mutable, always points at the most recent successful build |
| `staging-<sha>` | Staging-only artefacts (rare — only when staging diverges) |

## Branches

| Pattern | Used for |
| ------- | -------- |
| `main` | Protected, deploys |
| `feat/<short-name>` | New tools or capabilities |
| `fix/<short-name>` | Bug fixes |
| `docs/<short-name>` | Docs |
| `chore/<short-name>` | Maintenance, dep bumps (Dependabot uses its own pattern) |
