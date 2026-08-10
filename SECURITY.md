# Security policy

AI Firewall is an alpha local gateway, not a complete endpoint-security product.
Do not send real secrets, patient information, payment data, or private prompts
to the example service.

Report suspected vulnerabilities privately to the project maintainer before
opening a public issue. Include a minimal synthetic reproduction and avoid
including credentials or sensitive payloads.

Known limitations include provider-specific credential injection, connection
pinned forwarding, streaming/multimodal inspection, and production identity and
policy administration. See `docs/security.md` for the authoritative boundary.
