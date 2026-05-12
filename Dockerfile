# syntax=docker/dockerfile:1.7
#
# openlatch-sectools — runtime image
#
# Multi-stage build:
#   1. `base`     — Node 22 + Python 3.12 + uv + corepack (for pnpm), shared
#                   between deps and runtime so layer caches play nice.
#   2. `deps`     — installs the pinned `@openlatch/provider` from npm and
#                   every tool's locked dependencies. This is the layer
#                   Dependabot exercises and we want to cache aggressively.
#   3. `runtime`  — lean image that ships the tools + manifests + the
#                   already-built node_modules and per-tool virtualenvs.
#
# A push to `main` builds this image, signs it with Cosign keyless via
# OIDC, attaches a Syft SBOM, and dual-pushes to ghcr.io (archive) and
# registry.fly.io (Fly pull-target). See .github/workflows/deploy.yml.

FROM node:22-bookworm-slim AS base
ARG GIT_SHA=dev-local
ENV GIT_SHA=${GIT_SHA} \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    NODE_ENV=production \
    UV_LINK_MODE=copy \
    UV_NO_PROGRESS=1
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3.12 python3.12-venv ca-certificates curl tini \
    && rm -rf /var/lib/apt/lists/* \
    && curl -LsSf https://astral.sh/uv/install.sh | sh \
    && mv /root/.local/bin/uv /usr/local/bin/uv \
    && ln -sf /usr/bin/python3.12 /usr/local/bin/python \
    && corepack enable
WORKDIR /app

# ── deps ──────────────────────────────────────────────────────────────
FROM base AS deps

# Root npm dep — pinned `@openlatch/provider`.
COPY package.json package-lock.json* ./
RUN --mount=type=cache,id=npm-cache,target=/root/.npm \
    npm ci --omit=dev

# Per-tool Python deps. Each tool block is independent so cache misses
# don't cascade. Add a new block when a new Python tool lands.
COPY tools/coinflip-tool/pyproject.toml tools/coinflip-tool/uv.lock tools/coinflip-tool/
RUN --mount=type=cache,id=uv-cache,target=/root/.cache/uv \
    cd tools/coinflip-tool && uv sync --frozen --no-dev --no-install-project

# ── runtime ───────────────────────────────────────────────────────────
FROM base AS runtime

# Carry the populated `node_modules/` and per-tool `.venv/` from deps.
COPY --from=deps /app /app

# Tool source + manifests
COPY tools/ /app/tools/
COPY openlatch-provider.yaml /app/openlatch-provider.yaml

# Second-pass `uv sync` per tool to install the local project itself
# (its src/<slug>/ package needs to be importable at runtime). The deps
# layer above did `--no-install-project` to keep the cache layer slim.
RUN cd /app/tools/coinflip-tool && uv sync --frozen --no-dev

# Audit log + PID file directory — mounted onto a Fly volume so we keep
# the audit JSONL across machine restarts. See fly/fly.*.toml [mounts].
RUN mkdir -p /root/.openlatch/provider/logs /root/.openlatch/provider/runtime

# Put @openlatch/provider's binary on PATH.
ENV PATH="/app/node_modules/.bin:${PATH}"

EXPOSE 8443

# Tini reaps zombies — important because the provider's supervisor
# spawns one child per binding. Without tini, exited children stay as
# zombies until the provider notices.
ENTRYPOINT ["/usr/bin/tini", "--"]

CMD ["openlatch-provider", "listen", \
     "--no-tls", \
     "--port", "8443", \
     "--provider", "/app/openlatch-provider.yaml"]
