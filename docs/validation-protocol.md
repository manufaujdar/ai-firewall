# Validation protocol

Use this protocol before claiming support for a new detector, content type, provider, or deployment.

## Evidence set

1. Define the protected data class and attacker transformations.
2. Create a synthetic positive, near-miss, and benign corpus with provenance.
3. Measure recall, precision, false-positive rate, latency, and resource use by data class.
4. Fault every mandatory dependency and prove that ambiguous requests do not reach egress.
5. Test Unicode, zero-width characters, encoding, fragmentation, nested structures, serializer
   drift, timeouts, oversized input, concurrency, and storage failure where relevant.
6. Recursively verify that source values and authorization markers do not appear in responses,
   errors, logs, audit records, reports, snapshots, or temporary files.
7. Record operating system, Python version, policy digest, dependency resolution, and test command.

## Release gate

A capability is experimental until it has reproducible synthetic results, independent review, a
documented failure policy, an explicit rollback, and validation on every supported platform. Never
convert experimental performance into a general leak-prevention claim.
