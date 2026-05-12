# Contributing to openlatch-sectools

Thanks for your interest in contributing! `openlatch-sectools` is the monorepo where OpenLatch Security Researchers author tools that get auto-deployed to `sectools.openlatch.ai`. Whether you're adding a new tool, fixing a bug, sharpening the deploy pipeline, or improving docs — every contribution matters.

Please read our [Code of Conduct](CODE_OF_CONDUCT.md) before participating.

---

## Getting Started

### Prerequisites

| Tool | Version | Purpose |
| ---- | ------- | ------- |
| Node.js | 22 LTS | Runs the bundled `@openlatch/provider` CLI |
| Python | 3.12+ | Tool authoring (Python tools use `uv`) |
| `uv` | latest | Python dependency management |
| `pnpm` | 9+ | Node tool dependency management |
| Docker | 25+ | Building the runtime image locally |
| `flyctl` | latest | Operating the deployed apps (maintainers only) |
| `pre-commit` | latest | Hygiene hooks (recommended) |

### Setup

```bash
# Fork on GitHub, then:
git clone https://github.com/YOUR_USERNAME/openlatch-sectools.git
cd openlatch-sectools
pre-commit install
npm install                        # installs the pinned @openlatch/provider
cd tools/coinflip-tool && uv sync  # or any other tool you're touching
```

---

## Development Workflow

### Branch strategy

- **`main`** — protected; CI must pass; merges deploy to staging then production
- **`feat/<short-name>`** — new tools or capabilities
- **`fix/<short-name>`** — bug fixes
- **`docs/<short-name>`** — documentation only

### Authoring a new tool

1. Pick a slug (kebab-case, e.g. `prompt-injection-tool`).
2. Scaffold under `tools/<slug>/`:

   ```bash
   openlatch-provider new tool --template python --name <slug>
   ```

3. Write your detection logic. Keep `/healthz` returning 200; the runtime supervisor relies on it.
4. Author an `openlatch-tool.yaml` (`kind: Tool`, `schema_version: 2`) — see `tools/coinflip-tool/openlatch-tool.yaml` for the canonical example.
5. Add a binding for your tool to the root `openlatch-provider.yaml` (`kind: Provider`).
6. Run locally:

   ```bash
   npx openlatch-provider listen \
     --provider openlatch-provider.yaml \
     --no-tls --port 8443
   ```

7. Trigger a synthetic event:

   ```bash
   npx openlatch-provider trigger pre_tool_use \
     --binding <bnd_id> --no-tls
   ```

8. Open a PR — see `.github/PULL_REQUEST_TEMPLATE.md`.

### Coverage

| Scope | Minimum | Enforced by |
| ----- | ------- | ----------- |
| Project | 70 % | Codecov project gate |
| Patch (new code) | 75 % | Codecov patch gate |

Per-tool flags isolate coverage so one untested tool doesn't drag the whole repo.

---

## Commit Conventions

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```text
feat(coinflip-tool): expose deny-pct override via env
fix(deploy): wait for /healthz before declaring staging green
docs(readme): add Mermaid diagram for round-trip
chore(deps): bump @openlatch/provider to 0.2.0
```

A `commit-msg` pre-commit hook enforces the format.

---

## Pull Request Process

1. **Fill out the PR template** (auto-populated).
2. **Ensure CI passes**: lint, tests, manifest-validate, docker-build, coverage gates.
3. **Request review** and address feedback.
4. **Squash-merge** when approved + CI green.

---

## License

By contributing, you agree that your contributions will be licensed under the **Apache License 2.0**.

---

## Getting Help

- **GitHub Discussions**: [github.com/OpenLatch/openlatch-sectools/discussions](https://github.com/OpenLatch/openlatch-sectools/discussions)
- **GitHub Issues**: [github.com/OpenLatch/openlatch-sectools/issues](https://github.com/OpenLatch/openlatch-sectools/issues)
- **Slack**: [openlatch.slack.com](https://openlatch.slack.com)
