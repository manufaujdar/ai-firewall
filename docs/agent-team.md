# AI Firewall agent team

This repository uses a gstack-inspired set of explicit engineering roles. Each role is a project-local Codex skill under `.codex/skills/`; roles are invoked when their name matches the task or explicitly as `$skill-name`.

The workflow concept is adapted from [manufaujdar/gstack](https://github.com/manufaujdar/gstack):
separate cognitive modes for planning, implementation, review, QA, release, and documentation.
The role instructions here are original to this repository and enforce its AI-DLP threat model.

| Role | Skill | Owns |
|---|---|---|
| Security/product planner | `$firewall-plan` | Scope, trust boundaries, failure states, acceptance criteria, and test matrices |
| Secure implementation engineer | `$firewall-build` | One cohesive finding or vertical slice with focused tests |
| Local model engineer | `$firewall-models` | Offline model runtime, structured spans, deterministic replacement, residual scanning, and evaluations |
| Paranoid staff reviewer | `$firewall-review` | Fail-open paths, SSRF, unsafe model trust, privacy leaks, resource bounds, and completeness |
| Adversarial QA engineer | `$firewall-qa` | Synthetic bypass/fault tests, no-network assurance, privacy assertions, and performance budgets |
| Release engineer | `$firewall-release` | Reproducible validation, artifact/dependency gates, container checks, and authorized publishing |
| Security documentation engineer | `$firewall-docs` | Accurate architecture, supported behavior, limits, operational requirements, and release docs |

## Default delivery loop

1. `$firewall-plan` defines the smallest safe vertical slice.
2. `$firewall-build` and, when relevant, `$firewall-models` implement it.
3. `$firewall-review` performs an independent security pass.
4. `$firewall-qa` exercises bypasses and dependency failures.
5. `$firewall-docs` updates durable project documentation.
6. `$firewall-release` gates publishing; it does not publish without explicit authorization.

Parallel agents must own non-overlapping files or agree on interfaces first. The primary agent integrates shared entrypoints and runs the final validation. All roles inherit `AGENTS.md`; its fail-closed and privacy rules override role convenience.
