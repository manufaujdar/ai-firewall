# Documentation index

AI Firewall is a local, bounded privacy/DLP gateway for inspecting outbound AI
requests; it is not yet a complete endpoint-security product or production
proxy.

## Authoritative documents

- README.md: scope, quick start, and request flow.
- docs/architecture.md: components and extension boundaries.
- docs/security.md and SECURITY.md: security boundary and reporting.
- docs/technical-overview.md: code, technology, API, and validation baseline.
- AGENTS.md, .ai/, and .codex/skills/firewall-docs: local delivery rules.

## Initial documentation set

| Area | Status |
| --- | --- |
| Product scope and non-goals | Present |
| Architecture and request flow | Present |
| Codebase and module responsibilities | Added |
| Technology and local operations | Added |
| API surface and safe defaults | Added |
| Security and privacy boundary | Present |
| Tests and validation | Present in CI/tests |
| License and third-party provenance | Human follow-up; no GitHub license metadata |

## Reference patterns

Use LLM Guard, Microsoft Presidio, NeMo Guardrails, OWASP AI Testing Guide,
and FastAPI as comparison points. Preserve this repository's smaller,
metadata-only, fail-closed baseline rather than implying feature parity.

