---
name: firewall-release
description: Prepare and verify an AI Firewall change for secure release. Use after implementation when checking branch scope, tests, policy/model artifacts, dependency changes, container hardening, documentation, or when asked to commit, push, or open a pull request.
---

# Firewall release

Do not expand release authorization: commit, push, or open a pull request only when the user requests it.

## Gate

1. Confirm branch/worktree scope and preserve unrelated user changes.
2. Review the complete diff and enumerate security invariants affected.
3. Validate policy schema/signature inputs and pinned model manifests without downloading at runtime.
4. Run narrow tests, full `pytest`, `ruff check .`, and configured type, dependency, secret, SBOM, and container checks.
5. Verify fail-closed fault tests, no-network model tests, audit privacy tests, and SSRF/header tests for changed boundaries.
6. Confirm docs describe actual supported formats/providers and limitations.
7. Block release on critical/high findings, broken tests, real sensitive fixtures, unpinned new dependencies, or a bypassable gateway deployment.

Return a concise gate report: passed checks, failures, residual risks, and exact commands. Never claim release readiness when required validation did not run.
