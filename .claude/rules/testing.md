# Testing Standards

## Coverage Requirements

| Scope | Minimum | Enforced by |
| ----- | ------- | ----------- |
| Project total | 70 % | Codecov project gate |
| Patch (new/changed code) | 75 % | Codecov patch gate |
| Per-tool flag | 70 % project / 75 % patch | Codecov per-flag thresholds (`codecov.yml`) |

Each tool under `tools/<slug>/` reports its own coverage with a Codecov flag named after the tool slug. A failing flag fails the PR check for that flag without dragging down the rest of the repo.

## Test layout

```
tools/<slug>/
├── src/<slug_underscored>/
└── tests/
    ├── test_detect.py     # Happy-path + error-path for the @tool function
    └── test_healthz.py    # /healthz returns 200
```

For Node tools, swap `tests/` for `tests/` (Vitest) with the same layering.

## Minimum coverage rules

- Every `@tool` endpoint MUST have at least one happy-path test and one error-path test.
- Every verdict variant the tool can emit MUST be exercised.
- Every config knob (env var, etc.) MUST have a test that flips it.
- `/healthz` MUST have a test.

## Smoke tests (E2E)

A smoke job in `pr-checks.yml` does:

1. `docker build .` — proves the runtime image is buildable.
2. `docker run` the image with the coinflip binding only — proves the supervisor can spawn at least one tool.
3. `curl /healthz` on the container — proves the listen daemon answers.
4. `npx openlatch-provider trigger pre_tool_use --binding <bnd> --no-tls` against the running container — proves a full round-trip.

In `deploy.yml`, a stronger smoke runs against the deployed staging URL after every push to `main`.

## What NOT to test

- Don't mock the bundled `@openlatch/provider` — always run the real binary in CI.
- Don't write tests that assume a specific binding ID; resolve it from `openlatch-provider bindings list --output json`.
- Don't snapshot stdout of the supervisor — it's structured but its exact phrasing is `@openlatch/provider`'s contract, not ours.

## Tool test pattern (Python)

```python
from fastapi.testclient import TestClient
from coinflip_tool import app

client = TestClient(app)

def test_healthz_returns_200():
    response = client.get("/healthz")
    assert response.status_code == 200

def test_detect_returns_verdict_shape(monkeypatch):
    monkeypatch.setenv("OPENLATCH_COINFLIP_DENY_PCT", "100")
    response = client.post("/event", json={"event_id": "evt_test", "event_type": "pre_tool_use", "payload": {}})
    body = response.json()
    assert body["verdict_hint"] == "deny"
```

The orchestrator runs `uv run pytest --cov=<slug_underscored> --cov-report=xml` per tool and uploads the result to Codecov tagged with the tool's flag.
