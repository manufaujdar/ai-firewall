# Privacy and data boundary

Status: source distribution and local research use only. This file is a
technical privacy boundary, not a jurisdiction-specific privacy policy for a
hosted service.

## Current distribution

The default project is a local gateway. It does not create a hosted account,
advertising profile, analytics service, or remote data store. The browser
console keeps the entered key and payload in page memory. The backend processes
requests ephemerally and records decision metadata in its local audit/SQLite
surfaces; raw prompts, matches, payloads, and authorization headers are not
intended to be stored. Provider forwarding is disabled by default.

Use synthetic data for examples and tests. Do not send patient data, payment
data, credentials, private prompts, or production traces to the example service.

## Deployment responsibility

If an integrator deploys or modifies this project, the integrator becomes
responsible for the data flow it creates. Before handling personal, health,
confidential, or regulated information, the integrator must identify the
controller/processor roles, lawful basis or authorization, user notice and
consent where applicable, approved providers and regions, retention/deletion,
access controls, encryption and key management, incident response, and any
required contracts or institutional approvals. A self-hosted deployment must
publish its own privacy notice and terms of service; this repository does not
provide those notices.

## Legal and compliance boundary

The Apache-2.0 `LICENSE` governs the source code. It is not a privacy policy,
security certification, HIPAA/DPDP/GDPR compliance statement, or permission to
inspect traffic. See `NOTICE`, `SECURITY.md`, and `docs/compliance.md` for the
release and third-party boundaries.

Reviewed: 2026-08-14.
