# Security notes

- Bind the development service to `127.0.0.1`; do not expose it publicly without authentication,
  TLS, rate limits, and a reviewed deployment boundary.
- Keep provider credentials in a secret manager and inject them only within future provider adapters.
- Never log prompts, headers, matches, redacted source values, or exported operator reports.
- Treat regular expressions as one detection layer. They produce false positives and can be bypassed
  through context, encoding, fragmentation, normalization, or unsupported media.
- Protect policies and binaries from local tampering if this becomes an endpoint control.
- Obtain legal and employee-consent review before inspecting traffic or considering TLS interception.
- Browser storage is not used. Exports and copied briefs contain metadata only; the structured scan
  response is transient in page memory.

## Current enforced boundaries

- Scan and policy routes require a dedicated local API-key header; missing server key material makes
  protected routes unavailable. Liveness returns status only.
- Readiness fails with one generic response when authentication is unconfigured or the metadata-only
  audit sink cannot be opened. It exposes no key or filesystem details.
- Request bodies are bounded before JSON parsing; malformed or conflicting content lengths reject.
- JSON traversal bounds depth and node count and rejects unsupported, cyclic, or non-finite values.
- Every scan route uses the local privacy orchestrator. Redacted JSON is serialized and rescanned;
  residual findings or serialization errors block.
- Real-time events accept only allowlisted metadata keys. The SQLite schema has no payload, prompt,
  match, header, or sanitized-content column and retains at most 1,000 local summaries.
- The local model manifest is empty by default. Configured models require local relative artifacts,
  SHA-256 pins, structured non-overlapping spans, entity allowlists, confidence thresholds, and
  deadlines. Artifact, runtime, inference, or span failures block.
- Interactive API documentation is disabled and local Host headers are allowlisted.
- Browser responses deny framing, MIME sniffing, referrer disclosure, sensitive device APIs, and
  content loads outside the local origin through restrictive response headers.
- Destinations require HTTPS, an exact configured hostname, port 443, and globally routable DNS
  answers. Redirects and environment proxy settings are disabled.
- Caller headers are discarded at the outbound boundary, including authorization headers.
- Proxy forwarding cannot be enabled by environment configuration in this milestone.

Connection pinning to the validated DNS answer, provider-specific credential injection, final-byte
rescan, and response bounds are not implemented. Forwarding is therefore unavailable. Files, media,
encoded or fragmented secrets, Unicode confusables, streaming provider protocols, and semantic
personal-data detection remain unsupported. SSE reports graph progress only; it does not make
provider streaming safe. A redacted decision is not proof that no sensitive information remains.

## Supply-chain limitations

GitHub Actions are pinned to immutable commit SHAs. Python declarations use bounded version ranges
without a hash-locked resolution, and the Docker base image uses a mutable tag. Maintainers must
generate and review a lockfile and image digest during a separately approved release process; this
repository does not invent hashes or claim reproducible builds without them.

See `limitations.md`, `validation-protocol.md`, and `provenance.md`.
