# Deterministic frontend review

`scripts/review_frontend.py` performs a local, network-free source audit of the operator console.
It checks required accessibility landmarks, focus treatment, responsive CSS, explicit limitations,
local-only messaging, secure DOM rendering signals, and maintainability boundaries. It is a
repeatable gate, not a substitute for assistive-technology testing, usability research, browser
security review, or visual inspection.

Run:

```bash
python scripts/review_frontend.py
```

Future AI-assisted reviews may help with critique, but must not receive real payloads, credentials,
audit files, or private screenshots. Deterministic checks and human review remain authoritative.
