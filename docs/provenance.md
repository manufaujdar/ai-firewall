# Provenance and third-party dependencies

Every imported policy, model, dataset, detection pattern, parser, or test corpus must record:

- Source URL and immutable revision or digest
- Author or publisher and retrieval date
- License and redistribution constraints
- Intended use and known limitations
- Validation performed locally
- Network/runtime behavior and update procedure
- Reviewer and rollback method

Do not commit patient data, personal records, credentials, raw captures, production prompts,
proprietary incident traces, or unverified model weights. Dependency updates should be proposed by
automation, reviewed for release notes and transitive changes, tested offline where practical, and
merged deliberately. Runtime model downloads and `trust_remote_code` are prohibited.
