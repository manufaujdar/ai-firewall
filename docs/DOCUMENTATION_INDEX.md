# Documentation index

AI Firewall inspects explicitly integrated JSON requests locally. Forwarding is
disabled; this alpha is not a complete endpoint-security or production DLP product.

## Find the right document

| Task | Start here | Continue with |
| --- | --- | --- |
| Install and run a local scan | [README](../README.md) | [Human start page](../START_HERE.txt) |
| Understand trust and data boundaries | [Security notes](security.md) | [Limitations](limitations.md), [compliance boundary](compliance.md) |
| Find a component or extension point | [Architecture](architecture.md) | [Technical overview](technical-overview.md) |
| Plan a privacy capability | [Privacy enhancement plan](privacy-enhancement-plan.md) | [Model card](model-card-template.md), [dataset card](dataset-card-template.md) |
| Verify a change or prepare a candidate | [Validation protocol](validation-protocol.md) | [Candidate readiness](release-readiness.md), [engineering checks](../TOOLING.md) |
| Contribute or report a vulnerability | [Contributing](../CONTRIBUTING.md) | [Security reporting](../SECURITY.md), [governance](../GOVERNANCE.md) |
| Review source and licensing | [Provenance](provenance.md) | [Apache-2.0 license](../LICENSE), [notice](../NOTICE), [citation](../CITATION.cff) |
| Coordinate agent work | [Agent guide](../AGENTS.md) | [Project team](agent-team.md), [startup team](../.ai/TEAM.md) |

The [frontend review](frontend-review.md) describes a deterministic source audit;
its result does not replace browser, assistive-technology or security validation.
Read the [changelog](../CHANGELOG.md) for recorded changes. Readiness documents
describe their stated candidate and evidence date, not an automatic release approval.

## Repository organisation

| Location | Owns |
| --- | --- |
| `src/ai_firewall/` | API, scanner, policy, authentication, UI and privacy/proxy components |
| `config/` | Machine-readable policy and empty-by-default local model manifest |
| `tests/` | Synthetic runtime and boundary fixtures |
| `docs/` | Human-readable architecture, security, limitations, plans and evidence |
| `scripts/`, `tools/`, `.github/` | Local checks, pinned tool setup and CI workflows |
| `data/` | Local generated audit/history state; keep private runtime data out of Git |
| `.ai/`, `.codex/`, `AGENTS.md` | Task continuity, team roles and agent instructions |
| Root policy and package files | Stable setup, contribution, license, citation and build entry points |

Put new design or verification notes in `docs/` and link them from this index.
Keep executable policy in `config/`, reusable checks in `scripts/` or `tools/`,
and fixtures in `tests/`. Preserve existing paths when organising documentation;
update inbound links when a move is necessary. Never place raw payloads, provider
credentials, generated history or private reports in documentation or fixtures.

## Reference patterns

LLM Guard, Microsoft Presidio, NeMo Guardrails, OWASP AI Testing Guide and FastAPI
are comparison references. They do not establish feature parity or add runtime
dependencies to this repository.

