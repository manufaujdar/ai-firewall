---
name: firewall-build
description: Implement a scoped AI Firewall security feature with fail-closed behavior and focused tests. Use when fixing a review finding or building policy, detection, redaction, parsing, proxy, authentication, audit, or deployment-enforcement code.
---

# Firewall build

Read `AGENTS.md`, its required project documents, the relevant report finding, and narrow tests before editing.

## Workflow

1. Name the leak/failure path and the invariant the change must preserve.
2. Select one cohesive finding or vertical slice; avoid unrelated refactors.
3. Write or update the narrowest failing tests first when practical.
4. Implement explicit contracts with bounded work, typed failures, and no implicit allow path.
5. Ensure errors, logs, fixtures, and assertions contain only synthetic data and never raw matches or authorization values.
6. Run the narrow test, then the relevant suite, `ruff check .`, and type/security checks available in the repo.
7. Review the exact diff for bypasses, unsafe defaults, dependency additions, and documentation drift.

## Non-negotiable behavior

- Block malformed policy, unsupported content, unhealthy mandatory detectors, invalid model spans, and ambiguous high-risk data.
- Do not weaken the allowlist, TLS validation, redaction, or blocking to pass tests.
- Keep local-model endpoints loopback or Unix-socket only; never enable remote code or runtime downloads.
- Rescan the exact serialized outbound representation after replacement.
- Forward only allowlisted transport headers and inject provider credentials locally.

Report changed files, tests, remaining risks, and any intentionally deferred scope.
