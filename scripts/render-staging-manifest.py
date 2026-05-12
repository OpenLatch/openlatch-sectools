# Copyright 2026 OpenLatch, Inc.
# Licensed under the Apache License, Version 2.0 (see LICENSE).
"""Render a staging variant of the root provider manifest.

The deploy workflow calls this with the production-shaped
``openlatch-provider.yaml`` and writes a sibling file with:

- ``providers[].slug``      ``openlatch-sectools`` → ``openlatch-sectools-staging``
- ``providers[].endpoint_url`` swapped to the staging hostname
- ``bindings[].provider``   updated to the staging slug

No templating engine — yaml load → mutate → dump. Reviewable in a diff.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.stderr.write("PyYAML is required: pip install pyyaml or uv pip install pyyaml\n")
    raise


PROD_TO_STAGING = {
    "openlatch-sectools": "openlatch-sectools-staging",
}
PROD_ENDPOINT = "https://sectools.openlatch.ai/v1/event"
STAGING_ENDPOINT = "https://sectools-staging.openlatch.ai/v1/event"


def render(prod_yaml: dict) -> dict:
    """Return a deep-copied staging variant of ``prod_yaml``.

    The function is pure so it can be unit-tested without filesystem
    side effects.
    """
    import copy

    out = copy.deepcopy(prod_yaml)

    if out.get("kind") != "Provider":
        raise SystemExit(
            f"refusing to render: expected kind=Provider, got kind={out.get('kind')!r}"
        )

    for provider in out.get("providers", []):
        slug = provider.get("slug")
        new_slug = PROD_TO_STAGING.get(slug)
        if new_slug:
            provider["slug"] = new_slug
        if provider.get("endpoint_url") == PROD_ENDPOINT:
            provider["endpoint_url"] = STAGING_ENDPOINT

    for binding in out.get("bindings", []):
        new_slug = PROD_TO_STAGING.get(binding.get("provider"))
        if new_slug:
            binding["provider"] = new_slug

    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="production openlatch-provider.yaml")
    parser.add_argument("output", type=Path, help="staging output path")
    args = parser.parse_args()

    prod = yaml.safe_load(args.input.read_text(encoding="utf-8"))
    staging = render(prod)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        yaml.safe_dump(staging, sort_keys=False, default_flow_style=False),
        encoding="utf-8",
    )
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
