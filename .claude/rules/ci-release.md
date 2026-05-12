# CI & Release

## Branch protection

- `main` is protected: require PR, require status checks, no force-push, squash-merge only.
- Required status check: `all-checks` (the aggregator job in `pr-checks.yml`).

## Workflows

| Workflow | Trigger | Purpose |
| -------- | ------- | ------- |
| `pr-checks.yml` | PR + push to main | Lint, test, manifest-validate, docker-build, coverage |
| `deploy.yml` | push to main (path-filtered) + `workflow_dispatch` | Build → push (ghcr + fly) → register → secrets → deploy staging → smoke → deploy prod |
| `release-please.yml` | push to main | Open/refresh a per-tool Release PR using conventional commits |
| `cleanup-ghcr.yml` | weekly + `workflow_dispatch` | Delete old image versions in GHCR |
| `cleanup-fly-machines.yml` | weekly + `workflow_dispatch` | Destroy Fly machines older than 14 days that aren't on the current image |

## Deploy pipeline (`deploy.yml`)

```text
push to main
    │
    ▼
build-and-push  ──►  push to ghcr.io (signed + SBOM) AND registry.fly.io
    │
    ▼
register-staging  ──►  openlatch-provider register --provider <staging>.yaml
                       captures new binding secrets
    │
    ▼
deploy-staging  ──►  flyctl deploy --config fly/fly.staging.toml
                     --image registry.fly.io/openlatch-sectools:main-<sha>
    │
    ▼
smoke-staging  ──►  curl https://sectools-staging.openlatch.ai/healthz
                    trigger pre_tool_use; verify verdict
    │
    ▼
register-production  ──►  same as staging, against the prod manifest
    │
    ▼
deploy-production  ──►  flyctl deploy --config fly/fly.production.toml
    │
    ▼
post-deploy-cleanup  ──►  destroy stale Fly machines (different image digest)
```

Each environment job uses a GitHub Environment (`staging`, `production`) so secrets are scoped and approvals can be required on `production`.

## Required secrets

| Scope | Secret | Used by |
| ----- | ------ | ------- |
| Repo | `CODECOV_TOKEN` | coverage uploads in `pr-checks.yml` |
| `staging` environment | `FLY_API_TOKEN`, `OPENLATCH_TOKEN` | `register-staging`, `deploy-staging` |
| `production` environment | `FLY_API_TOKEN`, `OPENLATCH_TOKEN` | `register-production`, `deploy-production` |

`OPENLATCH_TOKEN` is the service editor account (`bot+sectools@openlatch.ai`).

## Image registries

Dual-push by design:

| Registry | Purpose | Auth |
| -------- | ------- | ---- |
| `ghcr.io/openlatch/openlatch-sectools` | Archive, signed with Cosign keyless, SBOM attached | GH OIDC |
| `registry.fly.io/openlatch-sectools` | What Fly pulls at deploy time | `FLY_API_TOKEN` |

Tags pushed: `latest` + `main-<short-sha>` + `staging-<sha>` for staging-only artefacts.

## release-please

Monorepo config (`release-please-config.json`) with one component per tool:

- Bumps each tool's version on conventional commits scoped to its path.
- Opens **one Release PR per tool** (`separate-pull-requests: true`).
- Tags `coinflip-tool-v0.2.0`, etc. (component-prefixed).
- Pre-1.0 — minor bumps are allowed for breaking changes within a tool.

The root repo itself is also `release-type: simple` so the monorepo can cut its own version when ops changes ship without touching tools.

## Cleanup

- **GHCR**: weekly job keeps the last 20 `main-<sha>` versions; untagged versions deleted.
- **Fly machines**: weekly job lists machines per app; destroys machines older than 14 days not on the active image digest. Same script runs as the final `post-deploy-cleanup` step after every production deploy.
