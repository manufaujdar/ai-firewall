---
name: firewall-models
description: Design, implement, or review private local-model detection and sensitive-entity replacement for AI Firewall. Use for NER/classifiers, Ollama/ONNX/Transformers runtimes, model manifests, inference workers, pseudonymization, replacement validation, evaluation, or model health behavior.
---

# Local model engineering

Read the project security invariants and the local-model sections of `security_best_practices_report.md` before acting.

## Architecture contract

1. Use deterministic detectors first and local token classification/NER for contextual PII.
2. Require structured spans with type, offsets, confidence, model ID, and digest. Never accept free-form rewritten source as authoritative.
3. Validate Unicode offsets, overlaps, confidence, output schema, latency, and resource budgets.
4. Replace spans deterministically with typed stable placeholders. Make synthetic generation optional and validate its output.
5. Rescan serialized output independently and block residual high-risk findings.
6. Load only pinned local artifacts; disable network, telemetry, remote code, and startup downloads.
7. Treat timeout, crash, malformed output, missing mandatory model, or version mismatch according to explicit fail-closed policy.

## Verification

Use unmistakably synthetic entities. Test model crash/timeout, malformed and overlapping spans, Unicode, prompt injection against generative classifiers, no-network behavior, deterministic output, residual leakage, and logs/audits. Record model purpose, digest, license, evaluation corpus provenance, thresholds, and known coverage gaps.
