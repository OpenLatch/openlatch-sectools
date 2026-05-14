# coinflip-tool

**This is the seed tool for `openlatch-sectools` and is slated for removal once the first real OpenLatch security tool ships.** Don't model new tools on its detection logic — model them on its file layout and SDK usage instead.

A faithful consumer of the public [`openlatch-tool-sdk`](https://pypi.org/project/openlatch-tool-sdk/) package that randomly returns `allow` or `deny` verdicts. It exists so we can validate the full OpenLatch pipeline locally and in CI without writing real detection logic:

```text
Agent (pre_tool_use hook)
   └─► openlatch-client (localhost:7443)
         └─► openlatch-platform (cloud)
               └─► openlatch-provider listen (the built-in provider that bundles this repo's tools)
                     └─► coinflip-tool (THIS — supervised on localhost:8081)
```

## Where to learn the workflow

- **Architecture + local dev tutorial**: see the root [`README.md`](../../README.md).
- **How to author a new tool**: see [`.claude/rules/tool-authoring.md`](../../.claude/rules/tool-authoring.md).
- **Where deploy magic happens**: [`.claude/rules/ci-release.md`](../../.claude/rules/ci-release.md) and the workflow file comments.

## Configuration

| Env var | Default | Effect |
| ------- | ------- | ------ |
| `OPENLATCH_COINFLIP_DENY_PCT` | `30` | Percent of requests to deny (0 = always allow, 100 = always deny). Clamped to `[0, 100]`. |
| `OPENLATCH_COINFLIP_PORT` | `8081` | Port the tool binds on `127.0.0.1`. Must match the binding's `local_endpoint` in the root `openlatch-provider.yaml`. |

The supervisor strips every `OPENLATCH_*` env var before spawning the child to avoid leaking provider credentials, so the canonical way to set the deny percent is via `bindings[].process_override.env` in the root `openlatch-provider.yaml`.

## Running just this tool

```bash
cd tools/coinflip-tool
uv sync
uv run uvicorn coinflip_tool:app --port 8081
```

Then in another terminal:

```bash
curl -s http://127.0.0.1:8081/healthz
# {"status":"ok"}

curl -s -X POST http://127.0.0.1:8081/event \
  -H 'content-type: application/json' \
  -d '{"event_id":"evt_test","event_type":"pre_tool_use","agent":{"platform":"claude-code"},"payload":{}}'
```

But that bypasses the HMAC-verified pipeline — see the root README's tutorial for the realistic loop with `openlatch-provider listen` and `openlatch-provider trigger`.

## Tests

```bash
uv sync --extra dev
uv run pytest
```

Coverage is uploaded to Codecov under the `coinflip-tool` flag.
