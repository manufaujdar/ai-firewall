---
name: firewall-plan
description: Pressure-test and scope AI Firewall product or engineering plans before implementation. Use for new features, architectural changes, provider/model integrations, policy changes, parser support, deployment enforcement, or any request that crosses a sensitive-data trust boundary.
---

# Firewall planning

Read `AGENTS.md`, the required project documents it names, `security_best_practices_report.md`, and relevant code/tests.

## Workflow

1. State the user outcome and the threat or leak path it addresses.
2. Identify existing code that already solves part of the problem.
3. Draw the data flow from local caller through parsing, detection, decision, replacement, residual scan, proxy, and audit.
4. Mark trust boundaries, attacker-controlled inputs, mandatory detectors, and every failure state.
5. Define the minimum safe slice. Unsupported or ambiguous high-risk inputs must block.
6. Specify files, public contracts, state transitions, migration needs, and test matrix.
7. Record deferred work explicitly; do not hide it behind permissive fallbacks.

## Required checks

- Keep detection, policy, replacement, proxy, and audit separately testable.
- Prefer deterministic span replacement; never make a generative rewrite the only DLP control.
- Require offline/pinned local models and block when mandatory inference is unavailable or malformed.
- Preserve metadata-only logging and local credential injection.
- Include adversarial, timeout, size/depth, SSRF, concurrency, and no-network tests where relevant.

Return an opinionated plan with risks and acceptance criteria. Do not edit code unless the user also asks for implementation.
