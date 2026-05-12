#!/usr/bin/env bash
# Copyright 2026 OpenLatch, Inc.
# Licensed under the Apache License, Version 2.0 (see LICENSE).
#
# Idempotently register the provider manifest against api.openlatch.ai
# and sync every newly-issued binding secret to the matching Fly app.
#
# Usage:
#   scripts/register-and-sync-secrets.sh \
#     --provider openlatch-provider.yaml \
#     --fly-app  openlatch-sectools
#
# Requires:
#   OPENLATCH_TOKEN   (env)   service editor API key
#   FLY_API_TOKEN     (env)   Fly token (the calling environment already has it
#                             because flyctl actions exported it)
#   npx, jq, flyctl on PATH

set -euo pipefail

PROVIDER=""
FLY_APP=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --provider)
            PROVIDER="$2"; shift 2 ;;
        --fly-app)
            FLY_APP="$2"; shift 2 ;;
        *)
            echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

if [[ -z "$PROVIDER" || -z "$FLY_APP" ]]; then
    echo "usage: $0 --provider <yaml> --fly-app <fly-app-name>" >&2
    exit 2
fi

if [[ -z "${OPENLATCH_TOKEN:-}" ]]; then
    echo "OPENLATCH_TOKEN is required" >&2
    exit 2
fi

echo "==> Registering against api.openlatch.ai (provider=$PROVIDER)"
register_output=$(mktemp)
trap 'rm -f "$register_output"' EXIT

# The provider's `register` command should emit JSON when --output json is
# passed; we want both the human report (for the workflow log) and the
# structured one (for parsing). Run with --output json and capture both.
npx -y openlatch-provider register \
    --provider "$PROVIDER" \
    --output json \
    > "$register_output"

cat "$register_output"

# Open question (plan §Open implementation questions Q2): the exact JSON
# shape `register --output json` emits for newly-issued secrets is not
# finalised in openlatch-provider v0.1. The contract we expect is one of:
#   { "bindings": [ { "slug": "...", "id": "...", "secret": "whsec_live_..." } ] }
# We accept either `slug` or `binding_slug`. Secrets only appear on first
# issuance; on re-run the field is missing or null. That's intentional —
# we never see a secret twice.
echo "==> Syncing binding secrets to Fly app $FLY_APP"
secret_count=$(jq -r '[.bindings[]? | select(.secret != null and .secret != "")] | length' "$register_output")
echo "Newly issued binding secrets: $secret_count"

if [[ "$secret_count" -eq 0 ]]; then
    echo "Nothing to sync."
    exit 0
fi

# Stage each secret and apply them together for one rolling restart.
mapfile -t pairs < <(
    jq -r '
        .bindings[]?
        | select(.secret != null and .secret != "")
        | "OPENLATCH_BINDING_SECRET_" + ((.slug // .binding_slug) | ascii_upcase | gsub("-"; "_"))
            + "=" + .secret
    ' "$register_output"
)

if [[ ${#pairs[@]} -eq 0 ]]; then
    echo "No parseable secrets found in register output."
    exit 0
fi

# Mask each secret value in the workflow log before doing anything else
for pair in "${pairs[@]}"; do
    value="${pair#*=}"
    echo "::add-mask::$value"
done

echo "Setting ${#pairs[@]} binding secret(s) on $FLY_APP"
flyctl secrets set --app "$FLY_APP" --stage "${pairs[@]}"
echo "==> Done."
