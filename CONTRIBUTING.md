# Contributing

AI Firewall is a security-sensitive foundation. Keep changes small, explain the
trust-boundary impact, and use synthetic payloads only.

Before opening a pull request:

```bash
python -m pytest
ruff check .
python scripts/review_frontend.py
```

Do not weaken fail-closed behavior, destination validation, redaction, or
metadata-only audit logging to make a test pass. Provider credentials, private
prompts, patient data, and production traces must never enter the repository.

The proxy-forwarding path is intentionally not a production security boundary;
changes that enable or extend it require a documented security review.

All contributors must follow `CODE_OF_CONDUCT.md`. Changes to policy semantics, supported
content types, runtime network access, models, parsers, authentication, auditing, or forwarding
must complete the trust-boundary section in the pull-request template. See `GOVERNANCE.md` and
`docs/validation-protocol.md` for decision and evidence requirements.
