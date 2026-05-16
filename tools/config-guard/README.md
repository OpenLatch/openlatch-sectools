# config-guard

Detects configuration-plane threats across MCP server definitions, Skills,
rules files, and hooks — including poisoning, rug-pulls, prompt injection,
RCE, and openlatch-hook disabling.

## What it detects

`config-guard` inspects the `data` field of an incoming CloudEvent. The
`data.kind` field routes the artifact to one of four detection families:

| `kind`  | What is inspected                            |
|---------|----------------------------------------------|
| `mcp`   | MCP server name, description, command, url   |
| `skill` | Skill name, description, body/content        |
| `rules` | Rules file content/body                      |
| `hooks` | Hooks dict (key → command)                   |

Unknown `kind` values are passed through as `allow` (no opinion).

## Detection rule IDs

> **Note:** The risk scores below are this repo's best-effort assumption.
> The canonical "Detection rule IDs" table — including any
> organisation-level overrides — lives in the `openlatch-platform` repo,
> not here.

### MCP family (`kind == "mcp"`)

| Rule ID                      | Risk | Description                                                      | Stateful? |
|------------------------------|------|------------------------------------------------------------------|-----------|
| `MCP-POISON-UNICODE-01`      |  85  | Invisible / zero-width chars in name or description              | No        |
| `MCP-POISON-BIDI-01`         |  88  | BiDi override chars in name or description                       | No        |
| `MCP-POISON-HOMOGLYPH-01`    |  80  | Mixed-script confusable (homoglyph) chars in name                | No        |
| `MCP-POISON-IMPERATIVE-01`   |  82  | Imperative injection directive in description                    | No        |
| `MCP-POISON-URLMISMATCH-01`  |  75  | URL host in description ≠ declared `url` host                    | No        |
| `MCP-RUGPULL-01`             |  88  | Name / description / command changed vs `prior_artifact_payload` | **Yes**   |

### Skill family (`kind == "skill"`)

| Rule ID                       | Risk | Description                                                          | Stateful? |
|-------------------------------|------|----------------------------------------------------------------------|-----------|
| `SKILL-NAME-01`               |  60  | Name does not match `^[a-z0-9][a-z0-9-]{0,63}$` (spaces, `..`, `/`, uppercase) | No |
| `SKILL-NAME-HOMOGLYPH-01`     |  80  | Homoglyph, BiDi, or invisible chars in skill name                    | No        |
| `SKILL-DESC-LEN-01`           |  55  | Description length > 1024 characters                                 | No        |
| `SKILL-INJECT-UNICODE-01`     |  82  | Invisible / BiDi chars in description or body                        | No        |
| `SKILL-INJECT-DETAILS-01`     |  78  | `<details>`-hidden imperative instructions in body                   | No        |
| `SKILL-INJECT-COMMENT-01`     |  76  | HTML / Markdown comment hiding imperative directives                 | No        |
| `SKILL-INJECT-FENCED-RUN-01`  |  80  | Fenced `run` / `bash` / `sh` code block in body                     | No        |
| `SKILL-INJECT-CURL-01`        |  85  | `curl` or `wget` piped to shell in body                              | No        |
| `SKILL-COLLISION-01`          |  75  | Skill name collides with an existing `sibling_skill_names` entry     | **Yes**   |

### Rules file family (`kind == "rules"`)

| Rule ID                        | Risk | Description                                             | Stateful? |
|--------------------------------|------|---------------------------------------------------------|-----------|
| `RULES-INJECT-UNICODE-01`      |  82  | Invisible / BiDi chars in content                       | No        |
| `RULES-INJECT-COMMENT-01`      |  76  | Comment-hidden imperative directive in content          | No        |
| `RULES-INJECT-DETAILS-01`      |  78  | `<details>`-hidden instructions in content              | No        |
| `RULES-INJECT-FENCED-RUN-01`   |  80  | Fenced `run` / `bash` / `sh` block in content          | No        |
| `RULES-INJECT-CURL-01`         |  85  | `curl` or `wget` piped to shell in content              | No        |
| `RULES-INJECT-SETUP-URL-01`    |  72  | Setup / install URL directive in content                | No        |

### Hooks family (`kind == "hooks"`)

| Rule ID                         | Risk | Description                                                                    | Stateful? |
|---------------------------------|------|--------------------------------------------------------------------------------|-----------|
| `HOOKS-RCE-01`                  |  92  | Hook command contains shell metacharacters or curl-pipe-shell (potential RCE)  | No        |
| `HOOKS-DISABLE-OPENLATCH-01`    |  90  | OpenLatch hook present in `prior_hooks_block` is missing or emptied            | **Yes**   |

### Stateful rules summary

Four rules require `prior_config_state` populated by the platform
(`needs_prior_config_state: true` in the capability):

| Rule ID                      | Prior field used              |
|------------------------------|-------------------------------|
| `MCP-RUGPULL-01`             | `prior_artifact_payload`      |
| `SKILL-COLLISION-01`         | `sibling_skill_names`         |
| `HOOKS-DISABLE-OPENLATCH-01` | `prior_hooks_block`           |

(No stateful rules in the `rules` family.)

## Capability flags

The `openlatch-tool.yaml` declares:

```yaml
needs_raw_payload: true
needs_prior_config_state: true
```

Both flags are required for the platform to provide the full event payload
and populate `event.prior_config_state`.

## Tuning

| Env var                        | Default | Purpose                               |
|-------------------------------|---------|---------------------------------------|
| `OPENLATCH_CONFIG_GUARD_PORT` | `8087`  | Listening port for the tool process   |

## Running tests

```bash
cd tools/config-guard
uv sync --frozen --extra dev
uv run ruff format .
uv run ruff check .
uv run pytest -q
```

Coverage gate: 70% project / 75% patch (enforced by Codecov per
`.claude/rules/testing.md`).
