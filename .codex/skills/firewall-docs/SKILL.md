---
name: firewall-docs
description: Update AI Firewall documentation to match shipped security behavior. Use after code, policy, model, parser, provider, audit, deployment, or operational changes, or when reviewing documentation for inaccurate security claims and missing limitations.
---

# Firewall documentation

Read the implemented code, tests, `START_HERE.txt`, `README.md`, `docs/security.md`, `docs/architecture.md`, and policy before editing documentation.

## Workflow

1. Describe only behavior proven by code and tests; never claim prevention of all leaks.
2. Update request/data-flow diagrams, supported providers/content types, limits, policy defaults, local-model contracts, failure behavior, and operational requirements.
3. State unsupported formats and bypass risks plainly.
4. Keep setup examples synthetic and ensure they do not normalize accepting provider credentials from callers.
5. Document every new dependency/service with its security rationale, offline/network behavior, and update procedure.
6. Preserve the rule that audit/log examples contain metadata only.
7. Cross-check line-by-line against tests and configuration, then run documentation link/format checks if available.

Do not change policy or implementation merely to make documentation simpler.
