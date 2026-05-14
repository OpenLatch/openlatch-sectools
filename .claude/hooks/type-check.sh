#!/usr/bin/env bash
# Stop hook: Run ruff check on changed Python files when Claude finishes a turn
# Catches lint and correctness errors before Claude reports "done"
# (Python has no clippy; ruff covers pyflakes, pycodestyle, bugbear,
# simplify, isort, and pyupgrade — see workspace pyproject.toml.)

root=$(git rev-parse --show-toplevel 2>/dev/null) || exit 0
# Ensure we're in the repo root — hooks may fire from deleted worktree dirs
cd "$root" 2>/dev/null || exit 0

# All uncommitted Python changes: modified + staged + untracked
changed=$(
  {
    git diff --name-only 2>/dev/null
    git diff --cached --name-only 2>/dev/null
    git ls-files --others --exclude-standard 2>/dev/null
  } | sort -u | grep -E '\.py$' || true
)

[ -z "$changed" ] && exit 0

# Resolve a single ruff binary. The workspace pyproject.toml at the repo
# root supplies the ruff config; we just need any ruff that reads it.
# Per-tool venvs are deliberately avoided so we don't spin up `uv sync`
# inside a Stop hook.
if command -v ruff >/dev/null 2>&1; then
  ruff_cmd=(ruff)
elif command -v uvx >/dev/null 2>&1; then
  ruff_cmd=(uvx ruff)
else
  # No ruff available — silent no-op, matching the provider hook's posture.
  exit 0
fi

# Collect existing files (skip deletions)
files=()
while IFS= read -r f; do
  [ -z "$f" ] && continue
  [ -f "$f" ] && files+=("$f")
done <<<"$changed"

[ ${#files[@]} -eq 0 ] && exit 0

if ! out=$("${ruff_cmd[@]}" check "${files[@]}" 2>&1); then
  # Exit 2 = non-blocking: stderr is fed back to Claude so it can auto-fix.
  cat >&2 <<HOOK_MSG
STOP HOOK: Ruff errors detected in your changes. You MUST fix them now before responding to the user.

## Ruff errors
$(echo "$out" | head -50)

Action required: Read the erroring files, fix every reported error, then re-verify by running ruff check. Do NOT ask the user to fix these — fix them yourself.
HOOK_MSG
  exit 2
fi

exit 0
