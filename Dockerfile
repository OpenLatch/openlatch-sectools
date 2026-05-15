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

# Vendored SDK (the post-PR1 `openlatch-tool-sdk` contract — the PyPI
# release predates it). Every tool's uv.lock pins
# `source = { directory = "../../vendor/openlatch-tool-sdk" }`, so the
# vendor tree must be present before any per-tool `uv sync`.
COPY vendor/ /app/vendor/

# Per-tool Python deps. Each tool block is independent so cache misses
# don't cascade. Add a new block when a new Python tool lands.
COPY tools/pii-scanner/pyproject.toml tools/pii-scanner/uv.lock tools/pii-scanner/
RUN --mount=type=cache,id=uv-cache,target=/root/.cache/uv \
    cd tools/pii-scanner && uv sync --frozen --no-dev --no-install-project

COPY tools/secrets-detector/pyproject.toml tools/secrets-detector/uv.lock tools/secrets-detector/
RUN --mount=type=cache,id=uv-cache,target=/root/.cache/uv \
    cd tools/secrets-detector && uv sync --frozen --no-dev --no-install-project

COPY tools/shell-guard/pyproject.toml tools/shell-guard/uv.lock tools/shell-guard/
RUN --mount=type=cache,id=uv-cache,target=/root/.cache/uv \
    cd tools/shell-guard && uv sync --frozen --no-dev --no-install-project

COPY tools/prompt-injection-guard/pyproject.toml tools/prompt-injection-guard/uv.lock tools/prompt-injection-guard/
RUN --mount=type=cache,id=uv-cache,target=/root/.cache/uv \
    cd tools/prompt-injection-guard && uv sync --frozen --no-dev --no-install-project

COPY tools/tool-integrity/pyproject.toml tools/tool-integrity/uv.lock tools/tool-integrity/
RUN --mount=type=cache,id=uv-cache,target=/root/.cache/uv \
    cd tools/tool-integrity && uv sync --frozen --no-dev --no-install-project

COPY tools/attack-path-guard/pyproject.toml tools/attack-path-guard/uv.lock tools/attack-path-guard/
RUN --mount=type=cache,id=uv-cache,target=/root/.cache/uv \
    cd tools/attack-path-guard && uv sync --frozen --no-dev --no-install-project

COPY tools/config-guard/pyproject.toml tools/config-guard/uv.lock tools/config-guard/
RUN --mount=type=cache,id=uv-cache,target=/root/.cache/uv \
    cd tools/config-guard && uv sync --frozen --no-dev --no-install-project

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
# `/app/vendor/openlatch-tool-sdk` arrived with the `COPY --from=deps`.
RUN cd /app/tools/pii-scanner            && uv sync --frozen --no-dev \
 && cd /app/tools/secrets-detector       && uv sync --frozen --no-dev \
 && cd /app/tools/shell-guard            && uv sync --frozen --no-dev \
 && cd /app/tools/prompt-injection-guard && uv sync --frozen --no-dev \
 && cd /app/tools/tool-integrity         && uv sync --frozen --no-dev \
 && cd /app/tools/attack-path-guard      && uv sync --frozen --no-dev \
 && cd /app/tools/config-guard           && uv sync --frozen --no-dev

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
