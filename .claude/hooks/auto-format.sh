#!/usr/bin/env bash
# PostToolUse hook: Auto-format edited Python files with ruff
# Errors are reported to stderr so Claude Code can surface them.

file_path=$(node -e "try{console.log(JSON.parse(process.env.TOOL_USE_INPUT).file_path||'')}catch{}" 2>/dev/null)

if [ -z "$file_path" ]; then
  exit 0
fi

# Normalize path separators for Windows
normalized=$(echo "$file_path" | tr '\\' '/')

# Only format Python files
if ! echo "$normalized" | grep -qE '\.py$'; then
  exit 0
fi

root=$(git rev-parse --show-toplevel 2>/dev/null) || exit 0
cd "$root" 2>/dev/null || exit 0

# Resolve a single ruff binary. The workspace pyproject.toml at the repo
# root supplies the ruff config; we just need any ruff that reads it.
# Per-tool venvs are deliberately avoided so PostToolUse stays fast.
if command -v ruff >/dev/null 2>&1; then
  ruff_cmd=(ruff)
elif command -v uvx >/dev/null 2>&1; then
  ruff_cmd=(uvx ruff)
else
  # No ruff available — silent no-op, matching the provider hook's posture.
  exit 0
fi

if ! "${ruff_cmd[@]}" format "$normalized" 2>&1; then
  echo "AUTO-FORMAT FAILED: ruff format failed for $normalized" >&2
fi

# --fix applies safe autofixes (import sorting, simplifications, etc.) so the
# Stop hook doesn't flag what we could've fixed here.
if ! "${ruff_cmd[@]}" check --fix "$normalized" 2>&1; then
  echo "AUTO-FORMAT FAILED: ruff check --fix failed for $normalized" >&2
fi

exit 0
