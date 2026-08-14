# Governance

AI Firewall is currently maintainer-led. The maintainer accepts responsibility for repository
administration, releases, security triage, and final policy changes. Contributors propose changes
through issues and pull requests; security-sensitive changes require an explicit threat-boundary
review and synthetic tests.

## Decision principles

1. Protect local data before adding convenience or coverage claims.
2. Fail closed for malformed policy, unsupported high-risk content, and detector failures.
3. Keep audits metadata-only and examples unmistakably synthetic.
4. Prefer small, reviewable deterministic controls over opaque automation.
5. Document uncertainty, limitations, dependency provenance, and rollback paths.

Policy semantics, supported content types, enabling proxy forwarding, new runtime network access,
or new model/parser dependencies require maintainer approval. A release requires passing tests,
lint, deterministic frontend review, documentation review, and a check for real sensitive fixtures.

If the contributor base grows, the project will publish a maintainer nomination and appeal process
before delegating release or security authority.
