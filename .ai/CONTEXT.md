# AI Firewall project context

## Mission

Prevent accidental sensitive-data leakage when local applications call cloud AI services by inspecting, allowing, redacting, or blocking outbound JSON payloads.

## Source map

- Human entry: `START_HERE.txt`
- Architecture and security: `docs/`
- Policy: `config/policy.yaml`
- Implementation: `src/ai_firewall/`
- Verification: `tests/`
- Local generated audit data: `data/`

## Invariants

Fail safely; never log raw sensitive payloads or authorization headers; keep destination approval explicit; use synthetic test data; do not represent this starter as complete production security.
