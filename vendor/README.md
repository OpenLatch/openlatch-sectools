# Vendored dependencies

## `openlatch-tool-sdk/`

A **vendored copy** of the `openlatch_tool_sdk` Python package whose canonical
source lives in [`openlatch-provider`](https://github.com/OpenLatch/openlatch-provider)
at `pypi/tool-sdk/` (the contract carrier — see that repo's plan 01).

### Why this is vendored (not a PyPI dependency)

The PyPI-published `openlatch-tool-sdk==1.0.0` predates the provider's PR1 v2
contract and does **not** expose `ActionScore`, `ActionAxes`,
`PriorConfigState`, `score_to_severity`, or `Verdict.actions[]` — the exact
surface the 7 first-party tools in this repo are written against (D-04, D-05,
D-07, D-08). The post-PR1 source was republished under the same `1.0.0` string
(lock-step release, no hand bump — see the initiative INDEX), so the registry
version is unusable here until a fresh publish.

Vendoring keeps tool builds **offline, reproducible, and free of cross-repo git
auth** in CI and the Docker image. Every `tools/<slug>/pyproject.toml` declares
`openlatch-tool-sdk` and points `[tool.uv.sources]` at this directory.

### De-vendor follow-up (tracked)

Drop `vendor/openlatch-tool-sdk/` and depend on the published
`openlatch-tool-sdk` once the provider repo publishes the post-PR1 build to
PyPI. Tracked in the cross-repo initiative INDEX deferred-follow-ups
("De-vendor SDK/schema → published registries"). Do not edit files here by
hand — re-sync from the provider repo if the contract changes.
