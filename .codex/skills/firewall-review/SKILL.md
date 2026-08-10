---
name: firewall-review
description: Perform a paranoid pre-landing review of AI Firewall code, policy, model, parser, proxy, audit, or deployment changes. Use when reviewing a branch/diff or checking for fail-open behavior, data leaks, SSRF, bypasses, unsafe model trust, or missing adversarial tests.
---

# Firewall review

Read `AGENTS.md`, required project documents, relevant tests, and the complete diff. Review code outside the diff when a policy action, content type, provider, detector, or state is added.

## Two-pass review

### Critical pass

- Trace every attacker-controlled input to outbound network, logs, errors, disk, model runtime, and audit sinks.
- Find implicit allow behavior, exception fallthrough, skipped detectors, unsupported content passthrough, and serialization changes after scanning.
- Check HTTPS/DNS/IP/port/path validation, redirects, environment proxies, forwarded headers, and local credential ownership.
- Treat local-model output as untrusted. Verify schema, spans, timeouts, health gates, artifact digests, offline behavior, and residual rescan.
- Check body/decompression/archive/pixel/frame/depth/match/time/concurrency bounds.

### Completeness pass

- Verify all enum/action/content/provider states and failure transitions.
- Check metadata-only audit/log/error behavior and concurrency/disk-full handling.
- Look for test gaps, flaky network dependencies, real-looking sensitive fixtures, stale docs, and unjustified dependencies.

Report only evidence-backed findings with severity, exact location, impact, safe fix, and false-positive notes. Do not modify code unless asked to address findings.
