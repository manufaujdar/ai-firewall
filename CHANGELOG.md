# Changelog

## Unreleased

- Added `PRIVACY_AND_DATA_BOUNDARY.md` and linked it from the README to distinguish the Apache-2.0 source license from deployment-specific privacy and service terms.
- Prepared version 0.1.1 with a calmer accessible local review workspace, local-only synthetic
  history, report downloads, copyable qualified review briefs, and explicit quality gates.
- Added Apache-2.0 release metadata, citation, governance, conduct, compliance, validation,
  provenance, model-card, dataset-card, pull-request, and Dependabot guidance.
- Added a deterministic local frontend review and regression tests without external AI calls.

- Added a loopback local scan/policy console for synthetic API verification; it
  stores no API key and does not enable forwarding.

- Added an authenticated, metadata-only `/v1/policy` summary endpoint that never exposes rule regexes.
- Enforced `policy.default_action` for unmatched scans while preserving explicit rule actions and
  failing closed on detector errors.
- Added generic `/ready` checks for authentication and audit storage while retaining `/health` as
  liveness.
- Pinned CI actions to known immutable SHAs and documented remaining dependency and container-image
  pinning gaps.
- Prepared contributor, security, and CI guidance for public review.

## 0.1.0

- Added deterministic JSON scanning, policy decisions, metadata-only audit
  events, scan API, and fail-closed destination validation.
