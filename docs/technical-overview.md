# Technical overview

Status: documented alpha baseline. This document describes the repository as
implemented on the default branch; it is not a production-readiness claim.

## Runtime and dependencies

- Python 3.11 or newer.
- FastAPI and Uvicorn provide the HTTP boundary.
- Pydantic Settings loads configuration.
- PyYAML loads the declarative policy.
- HTTPX is available for the future/guarded upstream boundary.
- Development checks use pytest, pytest-asyncio, and Ruff.
- The package is built from src/ai_firewall.

## Codebase map

- main.py: application boundary and route orchestration.
- scanner.py: recursive JSON inspection, sanitization, strictest-action selection, and fail-closed detector handling.
- policy.py and config.py: policy model, YAML loading, and settings.
- models.py: request/response domain contracts.
- auth.py: local API-key boundary.
- audit.py: metadata-only JSONL event recording.
- proxy/destination.py and proxy/headers.py: destination and safe-header checks.
- request_limits.py: request-size and boundary checks.
- web_ui.py: dependency-free local scan console.
- tests/: API, auth, configuration, policy, scanner, proxy, and limit coverage.

## Contract summary

local caller -> authentication -> request limits -> recursive scan -> policy
decision -> allow, redact, or block -> metadata-only audit.

Approved destinations and safe headers are validated separately. Audit events
must not contain raw prompts, secrets, or sensitive payloads. The proxy route is
intentionally unavailable until provider adapters, credential injection, DNS
connection pinning, and equivalent tests exist.

## Verification and gaps

Run the documented pytest and Ruff checks plus the CI workflow. Add synthetic
fixtures for nested JSON, encoding, oversized input, detector failure, unsafe
destinations, and audit redaction. Streaming, multimodal input,
provider-response scanning, signed policy distribution, enterprise identity,
and OS-level enforcement remain future work. A human owner must approve any
license, deployment, credential-handling, or clinical-data boundary.

