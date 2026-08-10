# AI Firewall agent guide

Read `START_HERE.txt`, `.ai/CONTEXT.md`, `.ai/MEMORY.md`, `README.md`, `docs/security.md`, `docs/architecture.md`, `config/policy.yaml`, and the relevant tests before substantial changes.

- This project protects outbound AI traffic. Default to fail-closed behavior for malformed policy, unapproved destinations, and ambiguous high-risk data.
- Never place real credentials, private keys, payment data, or identifiable personal/health records in tests, fixtures, logs, or prompts. Use unmistakably synthetic values.
- Preserve the rule that audit logs contain metadata and findings, not raw sensitive payloads or authorization headers.
- Keep detection, policy decisions, redaction, proxying, and audit emission separable and testable.
- Do not weaken the destination allowlist, validation, redaction, or blocking behavior merely to make a test pass.
- New external services or dependencies require a clear security rationale.

Validate Python changes with `pytest` and `ruff check .`; begin with the narrowest relevant test.

Use `.ai/HANDOFF.md` only for active-task continuity. Add durable memory only for explicit approved decisions; never store inspected payloads or sensitive examples there.

## Startup team

Read `.ai/TEAM.md` before multi-role or idea-to-release work. Use its explicit
gears and keep the task contract in `.ai/HANDOFF.md`; this guide's security
requirements and approval boundaries remain authoritative.

## Project agent team

Use the project-local gstack-inspired roles documented in `docs/agent-team.md`:
`$firewall-plan`, `$firewall-build`, `$firewall-models`, `$firewall-review`,
`$firewall-qa`, `$firewall-release`, and `$firewall-docs`.

For parallel work, give each agent non-overlapping file ownership. The primary agent owns shared
entrypoints, integration, and final validation. A role never overrides the fail-closed, synthetic-
fixture, metadata-only audit, allowlist, or dependency rules above.
