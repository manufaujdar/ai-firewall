# AI Firewall startup team

Mission: help local applications use external AI without silently leaking
sensitive data. This is a security foundation, not a complete production DLP
product.

| Gear | Team role | Accountable for |
|---|---|---|
| Founder review | Security product lead | Protected user, threat, value, and minimum safe scope |
| Product review | Privacy and policy lead | Data classes, policy semantics, approval gates, and operator experience |
| Execution plan | Security architect | Trust boundaries, fail-closed paths, auditability, and rollout |
| Execute | Detection/proxy engineer | Detectors, policy engine, proxy, configuration, and tests |
| Red-team review | Adversarial security reviewer | Bypasses, leakage, unsafe logging, allowlist errors, and regressions |
| Release | Release and documentation lead | `pytest`, `ruff`, security docs, migration and rollback notes |
| Retro | Product lead | Missed threats, false positives, operational learning, and next experiment |

Use `.ai/HANDOFF.md` for the active task contract and `.ai/MEMORY.md` only for
approved durable decisions. `config/policy.yaml`, `docs/security.md`, and
`docs/architecture.md` are authoritative for policy and design. Follow
`AGENTS.md`; a release cannot weaken fail-closed behavior to pass a check.

