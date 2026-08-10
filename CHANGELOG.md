# Changelog

## Unreleased

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
