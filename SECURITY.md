# Security Policy

OpenLatch is security infrastructure — we hold our own code to the same standard we enforce for AI agents. `openlatch-sectools` is the source of the detection tools that ship built-in with the OpenLatch platform, so its supply-chain and operational posture matters as much as the platform itself.

## Supported Versions

| Version | Supported |
| ------- | --------- |
| Latest release | :white_check_mark: |
| Previous minor | :white_check_mark: (backport on request) |
| Older | :x: |

We recommend always running the latest version.

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Use one of these private channels:

| Method | Details |
| ------ | ------- |
| GitHub Private Reporting | [Report a vulnerability](https://github.com/OpenLatch/openlatch-sectools/security/advisories/new) (preferred) |
| Email | **security@openlatch.ai** |

### What to Include

- Description of the vulnerability and its impact
- Steps to reproduce (minimal reproducible example preferred)
- Affected version(s) and which tool under `tools/` is implicated
- Severity assessment (if known)

### Our Commitment

| Step | Timeline |
| ---- | -------- |
| Acknowledge receipt | Within **2 business days** |
| Triage and initial assessment | Within **5 business days** |
| Fix shipped | Best effort, dependent on severity |
| Public disclosure | After fix is released, coordinated with reporter |

## Acknowledgments

We credit researchers who report vulnerabilities responsibly in our release notes (unless you prefer anonymity). Include your preference in your report.

## Supply Chain Security

- Container images built via GitHub Actions with OIDC, signed with Cosign keyless, and accompanied by Syft SBOMs.
- Production image is pulled by Fly from `registry.fly.io`; archive copy lives at `ghcr.io/openlatch/openlatch-sectools`.
- Inbound webhooks are verified via Standard Webhooks v1 HMAC-SHA256 with replay-cache enforcement (5-minute timestamp window) by the bundled `openlatch-provider` runtime.
- Dependabot bumps `@openlatch/provider`, Python tool dependencies, and GitHub Action SHAs weekly.

Thank you for helping make AI agents safer.
