# Architecture

The starter framework is an explicit local gateway. Applications send outbound AI requests to the gateway instead of directly to a provider. The scanner walks arbitrary JSON, evaluates configured rules, and calculates the strictest applicable action. A destination allowlist reduces server-side request-forgery risk.

## Components

- `main.py`: API boundary, destination validation, and upstream forwarding
- `scanner.py`: recursive content inspection and sanitization; applies the policy default only to
  unmatched input and blocks detector failures
- `policy.py`: declarative YAML policy loading
- `audit.py`: metadata-only security event logging
- `config/policy.yaml`: initial rules and approved AI provider hosts

`/health` is dependency-free process liveness. `/ready` checks only whether server authentication
is configured and the audit sink is appendable, returning no dependency details on failure.

## Natural next layers

1. Add provider adapters that inject credentials locally and normalize streaming APIs.
2. Add entropy detection, file parsers, OCR, and a trained named-entity recognizer.
3. Add identity-aware policy, exceptions, signed policies, and tamper protection.
4. Add endpoint enforcement through managed proxy/PAC settings, an OS network extension, or an enterprise egress gateway.
5. Inspect streaming and multimodal requests and apply equivalent controls to responses.
