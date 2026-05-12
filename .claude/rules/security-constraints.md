# Security Constraints

`openlatch-sectools` ships security tools. Its supply-chain and operational posture must be at least as careful as the platform it plugs into.

## Secrets

### Binding secrets (`whsec_live_*`)

- Issued by the platform when a binding is first registered.
- Stored in **Fly app secrets** (`flyctl secrets set`) per environment.
- Convention: one env var per binding, `OPENLATCH_BINDING_SECRET_<BINDING_SLUG_UPPER>=whsec_live_…`.
- Captured from `openlatch-provider register --output json` in the deploy workflow and synced to Fly immediately.
- **Never logged**, even at debug. The bundled `@openlatch/provider` redacts them in tracing output by design.
- Rotation: not automated in v0. Manual rotation via `openlatch-provider bindings rotate-secret <id>` + `flyctl secrets set`.

### Editor API key (`olk_edt_live_*`)

- Stored as the `OPENLATCH_TOKEN` GitHub Environment secret for the service editor account (`bot+sectools@openlatch.ai`).
- **Never** stored in the repo, in any `.yaml`, or in any container image.
- Workflows pass it as an env var to a single step at a time.

### Fly API token

- Stored as `FLY_API_TOKEN` per environment.
- Scoped to the apps it deploys to.

## HMAC inbound posture

The bundled `@openlatch/provider` owns inbound auth:

- Standard Webhooks v1 HMAC-SHA256 over raw body bytes.
- ±5 min timestamp skew.
- LRU replay-cache (size 1000, TTL 5 min) on `webhook-id`.

Tools never see unverified payloads — by the time a tool receives a request on its localhost port, the provider has already verified the signature. **Tools MUST NOT re-implement HMAC verification.**

## What never enters this repo

- Plaintext secrets, in any form, ever.
- Customer event payloads. Tools see CloudEvents at runtime; we never check fixtures of real events into git.
- Private keys for code signing — handled by Sigstore keyless via GH OIDC.

## Image signing & SBOM

- Every push to GHCR is **signed with Cosign keyless** (OIDC via `actions/attest-build-provenance`).
- Every push has a Syft SBOM attached.
- Fly pulls from `registry.fly.io` (not GHCR) because Fly doesn't enforce Cosign at pull-time today; the GHCR copy is the auditable artefact.

## Forbidden patterns

| Forbidden | Why |
| --------- | --- |
| `print()`-ing a binding secret in a workflow log | Even with masking, it leaks if the masking pattern is malformed |
| Storing secrets in `fly.toml`'s `[env]` block | `[env]` is committed; only `flyctl secrets set` values are encrypted |
| Putting `OPENLATCH_TOKEN` in `Dockerfile` `ARG`/`ENV` | Bakes into image history |
| `npm install` without `--ignore-scripts` for untrusted deps | We trust `@openlatch/provider`; for any future dep, evaluate before opting in |
| Reading the inbound `Authorization` / `webhook-signature` headers in a tool | Provider strips them before proxying |
| `latest` tag as the **only** tag pushed | Forensics need an immutable `main-<sha>` tag |

## Dependency policy

- `@openlatch/provider` pinned by minor version in `package.json`; bumped by Dependabot only.
- All Python deps in `uv.lock` (committed, reproducible).
- All Node deps in `pnpm-lock.yaml` / `package-lock.json` (committed).
- All GitHub Actions pinned by SHA or major-version tag.
- License allowlist (CI gate): Apache-2.0, MIT, BSD-*, ISC, MPL-2.0. GPL/AGPL forbidden in shipped tools.

## Reporting vulnerabilities

See [`SECURITY.md`](../../SECURITY.md). Use GitHub Private Reporting or `security@openlatch.ai`.
