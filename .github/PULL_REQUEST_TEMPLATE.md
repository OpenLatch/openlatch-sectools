### Description

<!-- What does this PR change?
 Example: Adds a new `prompt-injection-tool` under tools/, wires its binding into
 openlatch-provider.yaml, and bumps the production resource budget.
-->

### Related Issue

<!-- Link the issue this PR resolves with a GitHub keyword (Closes #123). -->

### Type of change

- [ ] New security tool (`tools/<new>/`)
- [ ] Existing tool change (detection logic, manifest, dependencies)
- [ ] Provider / deploy infra (Dockerfile, fly.toml, workflows, scripts)
- [ ] Documentation
- [ ] Other

### Checklist

- [ ] `pre-commit run --all-files` passes locally
- [ ] If a Python tool changed: `uv run ruff check` + `uv run pytest --cov` pass under `tools/<name>/`
- [ ] If a Node tool changed: `pnpm lint` + `pnpm test --coverage` pass under `tools/<name>/`
- [ ] Manifest(s) validate: `openlatch-provider register --provider openlatch-provider.yaml --dry-run`
- [ ] `docker build .` succeeds
- [ ] Coverage thresholds met (project 70% / patch 75%)
- [ ] Docs updated where the change is user-visible (per `.claude/rules/documentation-sync.md`)

### Additional Notes

<!-- Extra context, screenshots of `openlatch-provider trigger` output, etc. -->
