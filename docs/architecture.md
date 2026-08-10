# Architecture

AI Firewall is an explicit local inspection gateway. Applications must deliberately send a JSON
value to its authenticated API. The scanner evaluates configured rules and calculates the strictest
applicable action. It is not a transparent device-wide interceptor.

## Components

- `main.py`: API boundary, health/readiness, disabled proxy orchestration, and local UI assets
- `scanner.py`: bounded recursive inspection and deterministic sanitization; applies the policy
  default only to unmatched input and blocks detector failures
- `policy.py`: strict versioned YAML policy loading and validation
- `audit.py`: metadata-only security event logging
- `auth.py`: constant-time dedicated local API-key authentication
- `request_limits.py`: body-size enforcement before JSON parsing
- `proxy/`: HTTPS destination and caller-header validation contracts
- `web_ui.py`: dependency-free local review workspace; API keys stay in memory and optional history
  is stored only in the local browser
- `scripts/review_frontend.py`: deterministic network-free source review of frontend quality signals
- `config/policy.yaml`: current rules and approved provider-host metadata

`/health` is dependency-free process liveness. `/ready` checks only whether server authentication
is configured and the audit sink is appendable, returning no dependency details on failure. The
authenticated policy summary never exposes executable regular expressions.

## Current data flow

Trusted local Host -> body-size gate -> API-key authentication -> strict request model -> bounded
JSON traversal -> deterministic rules and validators -> strictest action -> payload suppression or
redaction -> metadata-only audit.

Destination and header modules define fail-closed contracts, but transport is intentionally
configuration-disabled. Validated DNS evidence is not yet pinned to the eventual connection, local
provider credentials are not injected, and the serialized outbound representation is not rescanned.

## Natural next layers

1. Add bounded canonicalization, encoding/fragmentation detectors, residual serialized-byte scans,
   and an explicit low-risk allow policy.
2. Add pinned offline NER with structured spans, health gates, and deterministic replacements.
3. Add provider adapters that inject credentials locally and pin validated connections.
4. Add sandboxed parsers, OCR, archives, and bounded streaming only after validation.
5. Add identity-aware policy, signed artifacts, tamper-evident audit, and OS/network enforcement.

See `limitations.md` for the authoritative supported-content and deployment boundary.
