---
name: firewall-qa
description: Run adversarial, privacy-preserving QA for AI Firewall changes. Use for security regression testing, bypass testing, malformed inputs, model/parser fault injection, proxy enforcement, audit privacy, performance budgets, or release readiness.
---

# Firewall QA

Read the change, its acceptance criteria, and relevant policy. Use only unmistakably synthetic secrets, identities, health/payment data, destinations, and documents. Deny external network access during tests.

## Test order

1. Run the narrow functional test and record the exact command.
2. Exercise clean allow, deterministic replace, and block outcomes.
3. Exercise every dependency failure: malformed policy, detector/model timeout or crash, parser error, DNS rejection, upstream failure, audit failure, and disk/resource exhaustion where applicable.
4. Try encoding, fragmentation, Unicode confusables, zero-width characters, nested structures, stream-frame splits, and serializer drift.
5. Assert no synthetic source value or authorization marker appears in responses, exceptions, logs, audit records, metrics, snapshots, or temporary files.
6. Verify size, depth, decompression, archive, pixel/frame, time, and concurrency budgets.
7. Run the relevant suite, `ruff check .`, and available type/security checks.

Do not fix failures in report-only requests. For implementation requests, make one minimal fix at a time and rerun the failing test before the wider suite. Return a release-readiness verdict and unresolved risks.
