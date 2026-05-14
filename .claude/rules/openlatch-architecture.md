# OpenLatch System Architecture

Security infrastructure for AI agents. A platform that plugs into agents via native lifecycle hooks to enforce security checks, routes events to the right security tool via a marketplace, and provides free platform primitives (alerting, dashboards, reporting, audit trail, policy engine, compliance, billing, SSO).

## Four Repositories

| Repo | Stack | Role | Deploy |
| ---- | ----- | ---- | ------ |
| **openlatch-client** | Rust (axum+tokio+clap) | Thin forwarder on the agent host: capture hook events, wrap, filter, forward, return verdict | npm / crates.io / Homebrew / curl |
| **openlatch-platform** | Python (FastAPI) + React 19 SPA | Cloud control plane: ingest, normalize, route, marketplace catalog, policy engine, platform primitives | Fly.io |
| **openlatch-provider** | Rust (axum+tokio+clap) | Two-mode binary: management CLI for Editor/Provider self-onboarding + runtime daemon for HMAC-signed inbound webhooks proxied to localhost-hosted detection tools | npm / crates.io / curl |
| **openlatch-sectools** (this repo) | Python (uv) + Node (pnpm) + Docker + `@openlatch/provider` | Source of the built-in security tools shipped with the OpenLatch platform; written against the public SDK; bundled by `@openlatch/provider` into one Fly app per environment | Fly.io (`sectools.openlatch.ai`) |

## End-to-end pipeline

```
Agent hook → openlatch-client → openlatch-platform → openlatch-provider listen → tool
   (localhost)      (cloud)                              (sectools.openlatch.ai)        (localhost:<tool-port>)
```

`openlatch-sectools` operates the "provider" stage. It bakes a pinned `@openlatch/provider` into a container, mounts every tool's `openlatch-tool.yaml` (v2), and runs one `openlatch-provider listen --provider openlatch-provider.yaml` process that supervises every tool subprocess.

## This Repo's Role

### What this repo owns

- The **deployed provider** at `sectools.openlatch.ai` (one Fly app per environment).
- The **operator manifest** (`openlatch-provider.yaml`, `kind: Provider`) that lists bindings, the public `endpoint_url`, and `tool_paths:` globs.
- Every **first-party tool** authored by OpenLatch Security Researchers under `tools/<slug>/`, each with its own `openlatch-tool.yaml` (`kind: Tool`).
- The **runtime image** (multi-stage Dockerfile) bundling Node + Python + uv + the pinned `@openlatch/provider` + every tool's deps.
- The **deploy pipeline** (`pr-checks.yml`, `deploy.yml`, `release-please.yml`, cleanup workflows).

### What this repo does NOT own

| Forbidden in this repo | Belongs in |
| ---------------------- | ---------- |
| `@openlatch/provider` source code | `openlatch-provider` |
| Manifest schema definitions (`manifest-tool-v2.schema.json`, `manifest-provider-v2.schema.json`) | `openlatch-client/schemas/` |
| Tool SDK (`openlatch-tool-sdk`, `@openlatch/tool-sdk`) source | `openlatch-provider` |
| Routing decisions, marketplace UI, billing | `openlatch-platform` |
| Detection logic for third-party tools | The third-party tool's own repo |

## Hard dependency: v2 manifest split

This repo only works when `openlatch-provider` supports `kind: Tool` + `kind: Provider` + `tool_paths:` (the v2 split). See `D:\GITOSIS\openlatch-provider\.local\handoff-multi-tool-manifest.md` for the design. Until v2 ships, the deployed sectools provider cannot consume multiple per-tool manifests from one entrypoint and the workflow `manifest-validate` step will fail.

## Topology

- **One Fly app per environment** — `openlatch-sectools-staging` + `openlatch-sectools` (production).
- **Region**: `iad` (single region; latency budget §Performance).
- **Networking**: Fly edge TLS → provider listening on plaintext internal port `8443`. Shared IPv4.
- **Domains**: `sectools.openlatch.ai` (prod), `sectools-staging.openlatch.ai` (staging).
- **Container registry**: dual — `ghcr.io/openlatch/openlatch-sectools` (archive, signed, SBOM) + `registry.fly.io/openlatch-sectools` (Fly pull).

## Operational invariants

1. **One Fly machine, many tool subprocesses.** The provider's supervisor (`src/runtime/supervisor/`) spawns each binding's `process:` and reaps them on shutdown. No per-tool Fly app.
2. **HMAC-only inbound auth.** Webhooks from `openlatch-platform` are verified via Standard Webhooks v1 HMAC-SHA256 with replay-cache. No mTLS in v0.
3. **Audit JSONL on volume.** `~/.openlatch/provider/logs/` is mounted on a Fly volume so audit records survive restart.
4. **stdout/stderr → Fly logs.** No other logging sink in production (no Prometheus, no metrics agent — see `.claude/rules/logging.md`).
5. **No PR previews.** Branches build but don't deploy. Production is reached only via merge-to-main → staging → smoke → promote.
