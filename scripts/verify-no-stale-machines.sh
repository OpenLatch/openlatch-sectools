#!/usr/bin/env bash
# Copyright 2026 OpenLatch, Inc.
# Licensed under the Apache License, Version 2.0 (see LICENSE).
#
# Destroy Fly machines that:
#   (a) belong to the given app, AND
#   (b) are NOT on the currently-released image digest, AND
#   (c) are older than 14 days OR in state `stopped`/`destroyed`.
#
# Usage:
#   scripts/verify-no-stale-machines.sh <fly-app-name>
#
# Requires:
#   FLY_API_TOKEN  (env)
#   flyctl, jq on PATH

set -euo pipefail

APP="${1:-}"
if [[ -z "$APP" ]]; then
    echo "usage: $0 <fly-app-name>" >&2
    exit 2
fi

if [[ -z "${FLY_API_TOKEN:-}" ]]; then
    echo "FLY_API_TOKEN is required" >&2
    exit 2
fi

echo "==> Listing machines for $APP"
machines_json=$(flyctl machine list --app "$APP" --json)

# Active release's image digest. `flyctl releases` returns most-recent first.
latest_image=$(flyctl releases --app "$APP" --json | jq -r '.[0].ImageRef.Digest // ""')
echo "Latest release image digest: ${latest_image:-<none>}"

# Cutoff = now - 14 days
cutoff=$(date -u -d "14 days ago" +%s 2>/dev/null || date -u -v-14d +%s)

destroy_count=0
while IFS= read -r m; do
    id=$(echo "$m" | jq -r '.id')
    state=$(echo "$m" | jq -r '.state')
    digest=$(echo "$m" | jq -r '.image_ref.digest // ""')
    created=$(echo "$m" | jq -r '.created_at')
    created_epoch=$(date -u -d "$created" +%s 2>/dev/null || date -u -j -f "%Y-%m-%dT%H:%M:%SZ" "$created" +%s)

    on_latest="no"
    [[ -n "$latest_image" && "$digest" == "$latest_image" ]] && on_latest="yes"

    age_old="no"
    [[ "$created_epoch" -lt "$cutoff" ]] && age_old="yes"

    case "$state" in
        destroyed) continue ;;
    esac

    if [[ "$on_latest" == "no" && ( "$age_old" == "yes" || "$state" == "stopped" ) ]]; then
        echo "Destroying stale machine $id (state=$state digest=${digest:0:12} created=$created)"
        flyctl machine destroy "$id" --app "$APP" --force || true
        destroy_count=$((destroy_count + 1))
    else
        echo "Keeping machine $id (state=$state on_latest=$on_latest age_old=$age_old)"
    fi
done < <(echo "$machines_json" | jq -c '.[]')

echo "==> Destroyed $destroy_count stale machine(s) on $APP"
