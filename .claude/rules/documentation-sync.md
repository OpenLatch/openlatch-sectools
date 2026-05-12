# Documentation Sync

**Documentation that contradicts the code is worse than no documentation.** Updates ship in the same PR as the code change.

## When to Update

| Change Type | Files to Check |
| ----------- | -------------- |
| New tool (`tools/<new>/`) | `README.md` (layout diagram + tutorial mention if needed), `tools/<new>/README.md`, `release-please-config.json`, `codecov.yml`, `.github/CODEOWNERS`, `.github/dependabot.yml` |
| Tool retirement | `README.md`, `openlatch-provider.yaml`, `release-please-config.json`, `codecov.yml`, `.github/CODEOWNERS`, `.github/dependabot.yml` |
| Manifest schema bump | `openlatch-provider.yaml`, every `tools/*/openlatch-tool.yaml`, this rule file |
| Pinned `@openlatch/provider` bump | `package.json`, `package-lock.json`, `Dockerfile` if version-specific flags changed |
| New environment variable | `.claude/rules/naming-conventions.md` (env-var prefix table), `README.md` (Configuration section) |
| New workflow | `.claude/rules/ci-release.md` (Workflows table) |
| Deploy infra change (Fly config, Dockerfile, scripts) | `.claude/rules/ci-release.md`, `Dockerfile` comments where non-obvious |
| New CI gate / threshold | `.claude/rules/testing.md` (Coverage Requirements), `codecov.yml` |
| Webhook secret env var convention change | `.claude/rules/security-constraints.md`, `scripts/register-and-sync-secrets.sh` |
| New tool authoring helper / template | `.claude/rules/tool-authoring.md` |
| New SDK release with breaking changes | `.claude/rules/tool-authoring.md`, every affected `tools/*/pyproject.toml` |

## Hard Rules

1. **Same-PR requirement** — docs ship with code, not as follow-up.
2. **No orphaned references** — grep `.md` files when renaming, moving, or deleting a tool.
3. **No speculative docs** — only document what exists now (the v2 manifest dependency is the one explicit exception, documented as such).
4. **Update, don't duplicate** — integrate into existing structure (`README.md`, `.claude/rules/`).
5. **Remove stale content** — contradictory guidance is a violation.
6. **README stays a tutorial** — architecture + local dev. Deploy lives in `.claude/rules/ci-release.md` + workflow file comments, not the README.
