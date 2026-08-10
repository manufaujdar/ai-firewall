# Security notes

- Bind the development service to `127.0.0.1`; do not expose it publicly without authentication and TLS.
- Keep provider credentials in a secret manager or inject them within provider adapters.
- Avoid logging prompts, headers, matches, or redacted source values.
- Treat regex rules as one detection layer. They can produce false positives and can be bypassed with encoding or fragmentation.
- Validate DNS/IP destinations in production to prevent redirects or DNS rebinding to private networks.
- Enforce maximum decompressed body size and add parsers for file uploads before allowing multipart data.
- Protect policies and binaries from local tampering if this becomes an endpoint control.
- Obtain legal and employee-consent review before inspecting user traffic or deploying TLS interception.

## Current enforced boundaries

- Scan and proxy routes require the dedicated local API-key header; a missing server key makes
  protected routes unavailable. Liveness remains unauthenticated and returns status only.
- Readiness fails with one generic response when authentication is unconfigured or the
  metadata-only audit sink cannot be opened. It does not expose key or filesystem details.
- Request bodies are bounded before JSON parsing, and malformed or conflicting content lengths
  are rejected.
- Interactive API documentation is disabled and local Host headers are allowlisted.
- Proxy destinations require HTTPS, an exact configured hostname, port 443, and DNS answers that
  are all globally routable. Redirects and environment proxy settings are disabled.
- All caller headers are discarded at the outbound boundary, including authorization headers.
- Proxy forwarding cannot be enabled by configuration in this milestone.

Connection pinning to the validated DNS answer and provider-specific local credential injection
are not implemented yet. Until both are complete, treat proxy forwarding as a development feature,
not a production SSRF boundary.

## Supply-chain limitations

GitHub Actions are pinned to immutable commit SHAs. The Python dependency declarations still use
bounded version ranges without a hash-locked resolution, and the Docker base image still uses a
mutable tag rather than a verified digest. These gaps remain open until maintainers generate and
review a lockfile and image digest through an approved release process; no hashes or digests are
guessed in this repository.
