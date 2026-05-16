# shell-guard

Pure-Python detection tool for the [OpenLatch](https://openlatch.ai) platform.
Detects dangerous and exfiltration shell commands in `pre_tool_use` events from
Claude Code agents, using 5-axis risk scoring without any network calls.

## What it detects

| Rule ID | Threat Category | Description | Risk Score |
| ------- | --------------- | ----------- | ---------- |
| `SHELL-RM-ROOT-01` | `shell_dangerous` | `rm` with recursive+force flags targeting `/`, `/*`, `~`, `$HOME`, or `--no-preserve-root` | 95 |
| `SHELL-FORKBOMB-01` | `shell_dangerous` | Classic fork bomb pattern `:(){ :|:& };:` and variations | 90 |
| `SHELL-DISK-DESTROY-01` | `shell_dangerous` | `dd … of=/dev/sd*`, `mkfs`, `wipefs`, redirect to raw block device | 95 |
| `SHELL-CHMOD-WORLD-01` | `shell_dangerous` | `chmod 777` or `a+rwx` on root or system paths (`/etc`, `/usr`, `/bin`) | 70 |
| `SHELL-SUID-01` | `shell_dangerous` | `chmod` setuid (`u+s`, `+s`, `4755`) on any binary | 80 |
| `SHELL-CURL-PIPE-SH-01` | `shell_exfiltration` | `curl`/`wget` output piped to `sh`/`bash`/`sudo bash` | 85 |
| `SHELL-REVERSE-SHELL-01` | `shell_exfiltration` | `bash -i >& /dev/tcp/`, `nc -e /bin/sh`, `mkfifo\|nc`, Python/Perl reverse shells | 90 |
| `SHELL-EXFIL-CURL-01` | `shell_exfiltration` | Uploading files/data out: `curl -d @file`, `tar … \| curl`, `\| nc host port` | 80 |

## 5-Axis Risk Scoring

Each detection produces scores for five axes (0–20 each):

| Axis | Meaning |
| ---- | ------- |
| `destructive` | How much permanent damage the action causes |
| `exfil` | How much data leaves the system |
| `secret` | Likelihood of exposing credentials/secrets |
| `privesc` | Potential for privilege escalation |
| `reversibility` | How hard the action is to undo (higher = harder) |

The overall `risk_score` (0–100) maps to severity via the SDK's `score_to_severity`:
- **< 40** → `low`
- **40–69** → `medium`
- **70–89** → `high` → `deny`
- **≥ 90** → `critical` → `deny`

## Verdict mapping

- `critical` or `high` severity → `verdict_hint: deny`
- `medium` or `low` severity → `verdict_hint: allow`

## Tuning

| Env Var | Default | Description |
| ------- | ------- | ----------- |
| `OPENLATCH_SHELL_GUARD_PORT` | `8083` | Port the tool listens on (must match `openlatch-provider.yaml`) |

## Running tests

```bash
cd tools/shell-guard
uv sync --extra dev
uv run pytest -q
```

## Local development

```bash
# From repo root:
cd tools/shell-guard && uv sync && cd ../..
npx openlatch-provider listen --provider openlatch-provider.yaml --no-tls --port 8443

# Fire a synthetic event (replace bnd_... with the binding ID from listen logs):
npx openlatch-provider trigger pre_tool_use \
  --binding bnd_REPLACE_ME \
  --tool Bash \
  --input 'rm -rf /' \
  --no-tls
```
