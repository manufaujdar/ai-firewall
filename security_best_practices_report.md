# AI Firewall historical security review and implementation blueprint

> **Status update (2026-08-10):** this document preserves the original baseline review and target
> architecture. The repository has since implemented strict default-block policy validation,
> request limits, local API-key authentication, HTTPS/DNS destination validation, caller-header
> stripping, disabled-by-configuration forwarding, generic readiness, trusted Host enforcement,
> browser security headers, and substantially expanded synthetic tests. Connection pinning, local
> provider credential injection, residual serialized-byte scanning, audit hardening, broad content
> parsing, local models, signed artifacts, and OS/network enforcement remain open. Use
> `docs/security.md` and `docs/limitations.md` for the current authoritative boundary.

## Executive summary

The repository is a useful starter, not yet an enforceable data-loss-prevention firewall. It has
several sound foundations: detection, policy, proxying, and audit emission are separate modules;
blocked scans do not return the original payload; destinations use an exact hostname allowlist;
YAML is loaded with `safe_load`; the container runs as a non-root user; and audits omit raw
payloads and authorization headers.

The highest-risk gaps are that the policy defaults to `allow`, request size limits are configured
but never enforced, API callers are unauthenticated, outbound URL validation is not resistant to
DNS/IP/port tricks, and caller-supplied headers are forwarded without an allowlist. Inspection is
regex-only and covers JSON string values only. It does not handle encoded/fragmented secrets,
files, images, archives, streaming, or multimodal requests, and it has no local-model runtime.

A high-quality design should not ask a generative model to rewrite the whole prompt. It should
combine deterministic detectors with a local NER/classification model, produce character spans,
replace those spans with typed stable placeholders, and rescan the result before egress. If a
required local detector is unavailable, times out, returns malformed spans, or leaves an ambiguous
high-risk finding, the request must be blocked. No system can promise prevention of *all* leaks;
the realistic goal is layered controls, measurable coverage, fail-closed handling, and OS/network
enforcement so applications cannot bypass the gateway.

## Original scope and validation

The statements below record the repository state at the time of the original review; they are not
current test results. The original review covered all then-existing source, tests, policy,
deployment files, and project-required documentation.
The codebase is Python 3.11+ with FastAPI, Pydantic, HTTPX, and PyYAML.

- `ruff check .`: passed.
- `python3 -m compileall -q src tests`: passed.
- `pytest`: not successfully completed. The `.venv/bin/pytest` launcher points to a previous
  workspace path. Importing pytest through the underlying Python with the venv site-packages then
  hung and was interrupted. Repair/recreate the virtual environment before relying on test status.
- The complete working tree, including existing source files, is currently untracked. No existing
  implementation files were changed by this review.

## Security findings

### High severity

#### AF-001 — Policy can silently fail open

- Rule ID: FAIL-CLOSED-001
- Location: `config/policy.yaml:2`; `src/ai_firewall/policy.py:28-46`
- Evidence: the shipped `default_action` is `allow`; missing `default_action` also becomes `allow`,
  and missing `rules` or `allowed_hosts` silently becomes an empty collection.
- Impact: a truncated, incomplete, or mistakenly weakened policy can allow content the firewall
  does not understand. `settings.fail_closed` only affects upstream HTTP errors and does not make
  policy or detection fail closed.
- Fix: validate policy with a strict schema; reject unknown/missing fields, duplicate rule IDs,
  unsupported validators/actions, empty rule sets, and unsigned/expired policies. Make the safe
  default `block`, with explicit low-risk allow rules.
- Mitigation: refuse startup if policy validation or signature verification fails.
- False-positive notes: startup currently fails for some malformed YAML, but not for structurally
  valid policies that omit security-critical collections or use the permissive defaults above.

#### AF-002 — Body, nesting, and compute limits are not enforced

- Rule ID: FASTAPI-LIMITS-001
- Location: `src/ai_firewall/config.py:13`; `src/ai_firewall/models.py:21-35`;
  `src/ai_firewall/scanner.py:50-65`
- Evidence: `max_payload_bytes` is never read; payloads use `Any`; the recursive scanner has no
  depth, node, string-length, match-count, or detector-time budget.
- Impact: an unauthenticated caller can consume memory/CPU, trigger recursion failures, or create
  detector latency that prevents the firewall from protecting other requests.
- Fix: reject oversized compressed and decompressed bodies before JSON parsing; enforce depth,
  node, string, file, archive-expansion, match, and total scan-time limits.
- Mitigation: add strict reverse-proxy body/rate limits while app-level controls are built.
- False-positive notes: an undocumented edge limit may exist in deployment; none is visible here.

#### AF-003 — Destination validation is incomplete for an outbound proxy

- Rule ID: FASTAPI-SSRF-001
- Location: `src/ai_firewall/main.py:43-48,62-64`
- Evidence: only the parsed hostname is compared with the allowlist. HTTP is permitted, arbitrary
  ports are permitted, DNS results are not validated, resolved addresses are not pinned, and
  private, loopback, link-local, multicast, and metadata ranges are not rejected.
- Impact: DNS rebinding/poisoning or an allowed hostname resolving internally could reach local or
  cloud-internal services. Plain HTTP can disclose sanitized content and provider credentials.
- Fix: require HTTPS, exact host and allowed-port tuples, resolve and validate every address,
  connect to a validated/pinned address while preserving TLS SNI/certificate validation, and keep
  redirects disabled or revalidate every hop.
- Mitigation: enforce an OS/container egress allowlist independently of application checks.
- False-positive notes: HTTPX does not follow redirects by default, which reduces redirect risk,
  but this invariant is implicit and untested.

#### AF-004 — Scan and proxy endpoints have no caller authentication

- Rule ID: FASTAPI-AUTH-001
- Location: `src/ai_firewall/main.py:23,30-44`; `Dockerfile:11`
- Evidence: no router dependency or middleware authenticates callers; the image listens on
  `0.0.0.0`. Compose binds the published port to loopback, but other deployment modes may not.
- Impact: any process or reachable host can use the service as a proxy, consume local-model
  resources, inspect policy metadata, and cause audit/availability impact.
- Fix: authenticate clients with local mTLS, Unix-domain-socket peer identity, or short-lived
  workload tokens; authorize destination/model/action per client; protect all non-liveness routes
  at the router boundary.
- Mitigation: bind a Unix socket or loopback only and apply host firewall rules.
- False-positive notes: a production reverse proxy could add authentication; it is not present in
  this repository and must be verified rather than assumed.

#### AF-005 — Arbitrary caller headers are forwarded upstream

- Rule ID: PROXY-HEADERS-001
- Location: `src/ai_firewall/models.py:31-35`; `src/ai_firewall/main.py:62-64`
- Evidence: `headers: dict[str, str]` is passed directly to HTTPX.
- Impact: hop-by-hop headers, `Host`, forwarding headers, content-length/encoding metadata, custom
  provider control headers, and caller-supplied credentials can cross the trust boundary. This
  increases request smuggling, routing, identity-confusion, and credential-handling risk.
- Fix: discard all caller headers by default; copy only explicitly supported semantic headers;
  construct transport headers inside provider adapters; inject credentials from a local secret
  store and never accept provider authorization from clients.
- Mitigation: immediately deny `authorization`, `proxy-authorization`, `host`, `connection`,
  `transfer-encoding`, `content-length`, `forwarded`, and all `x-forwarded-*` input headers.
- False-positive notes: HTTPX may normalize some transport headers, but that is not a security
  boundary and does not address provider-specific headers.

#### AF-006 — Inspection coverage is inadequate for the stated mission

- Rule ID: DLP-COVERAGE-001
- Location: `src/ai_firewall/scanner.py:29-63`; `config/policy.yaml:5-41`
- Evidence: six regular-expression rules inspect only Python string values. Keys, encoded values,
  fragmented secrets, entropy, credentials with provider-specific checksums, names/addresses/
  health identifiers, documents, images, OCR, archives, audio, and streaming frames are absent.
- Impact: common transformations and unsupported content types can bypass inspection and leak
  sensitive information to an approved AI provider.
- Fix: implement the layered detector/parser/local-model blueprint below and block unsupported or
  ambiguous high-risk content.
- Mitigation: accept only a narrowly documented JSON/provider subset until each format is covered.
- False-positive notes: none; the limitation is explicitly acknowledged in `docs/security.md`.

### Medium severity

#### AF-007 — No local-model isolation, contract, or fail-closed behavior exists

- Rule ID: LOCAL-MODEL-001
- Location: repository-wide; `docs/architecture.md:14-19`
- Evidence: no local inference runtime, model registry, signed model manifest, span schema,
  timeout/circuit breaker, health gate, or output validator exists.
- Impact: adding a model ad hoc could send data to a remote endpoint, load untrusted model code,
  hallucinate replacements, or silently fail and pass uninspected content.
- Fix: allow only loopback/Unix-socket inference, pin model artifacts by digest, disable remote
  code/network access, require structured span output, validate offsets/types/confidence, and block
  when a required detector is unhealthy.
- Mitigation: keep local-model inspection disabled until its readiness gate and rescan tests pass.
- False-positive notes: no model integration exists yet; this is a required-design finding.

#### AF-008 — The proxy does not safely support streaming or response inspection

- Rule ID: PROXY-STREAM-001
- Location: `src/ai_firewall/main.py:62-74`
- Evidence: the complete upstream response is buffered into memory and returned without inspection.
  Streaming request frames and provider streaming protocols are not handled.
- Impact: large responses cause memory pressure; future passthrough streaming could accidentally
  bypass inspection; provider/tool responses could return secrets into a less-trusted client.
- Fix: implement bounded stream parsers with message/frame reassembly, inspect before flush, apply
  response policy separately, cap buffers, and terminate streams on detector failures.
- Mitigation: disable streaming and cap upstream response size until implemented.
- False-positive notes: outbound request leakage is the primary mission, but symmetric response
  controls are required for a robust AI gateway and agent/tool workflows.

#### AF-009 — Audit writing is not hardened for concurrency, integrity, or availability

- Rule ID: AUDIT-001
- Location: `src/ai_firewall/audit.py:9-22`; `src/ai_firewall/main.py:36-51`
- Evidence: synchronous file I/O occurs in async routes; writes are unlocked; there is no bounded
  queue, rotation, integrity chain/signature, explicit restrictive creation mode, or audit failure
  policy.
- Impact: concurrent writes can become unreliable, disk exhaustion can impair the service, and a
  local attacker can modify history. An audit write failure currently causes request failure, but
  the behavior is implicit and unclassified.
- Fix: emit typed metadata-only events to a bounded writer, use restrictive permissions, rotation,
  integrity chaining/signing, health metrics, and an explicit fail-closed policy for required audit.
- Mitigation: mount a quota-limited, owner-only audit directory and monitor disk space.
- False-positive notes: small append writes are often atomic on local filesystems, but portability
  and tamper evidence are not guaranteed.

#### AF-010 — Policy and model artifacts are not authenticated

- Rule ID: SUPPLY-CHAIN-001
- Location: `src/ai_firewall/policy.py:28-46`; `docker-compose.yml:6-8`
- Evidence: any readable YAML at the configured path is trusted; no schema version support matrix,
  signature, digest, issuer, expiry, rollback protection, or last-known-good policy exists.
- Impact: local tampering or operational mistakes can disable detection while leaving the service
  apparently healthy.
- Fix: verify signed manifests and immutable artifact digests before activation; apply atomic policy
  reload with monotonic versions and retain a verified last-known-good snapshot.
- Mitigation: retain the read-only mount and enforce host file ownership/permissions.
- False-positive notes: the config volume is read-only inside the container, not on the host.

#### AF-011 — Production API hardening is not configured

- Rule ID: FASTAPI-BASELINE-001
- Location: `src/ai_firewall/main.py:23`; `Dockerfile:11`
- Evidence: default OpenAPI/docs endpoints remain enabled; there is no TrustedHost middleware,
  centralized generic exception shaping, security-header middleware, explicit production worker/
  timeout configuration, or visible rate limiting.
- Impact: deployment details are exposed and common availability/host-header protections depend on
  undocumented infrastructure.
- Fix: use an app factory with production settings, disable/protect docs, validate Host, add safe
  error responses and resource controls, and document trusted-proxy configuration.
- Mitigation: enforce equivalent controls at a local reverse proxy.
- False-positive notes: CORS is correctly absent; TLS may legitimately terminate outside the app.

#### AF-012 — The test suite does not exercise security boundaries

- Rule ID: TEST-SECURITY-001
- Location: `tests/test_api.py:9-24`; `tests/test_scanner.py:10-37`
- Evidence: six basic tests cover health and four patterns. There are no malformed-policy, auth,
  size/depth, SSRF/DNS, header, audit leakage, model-failure, parser, encoding, concurrency,
  streaming, fuzz, or bypass tests.
- Impact: regressions can silently create fail-open paths in the highest-risk code.
- Fix: add the test inventory below, run it without network access, and gate merges on tests,
  linting, type checking, dependency audit, and secret scanning.
- Mitigation: manually restrict accepted inputs and deployment exposure until coverage exists.
- False-positive notes: no external CI configuration is present.

## Target security architecture

The outbound path should be:

1. Authenticate the local workload and authorize its provider/model/use case.
2. Enforce raw/decompressed size, nesting, node, file, archive, and time budgets.
3. Normalize a provider request into a canonical content/attachment/tool schema.
4. Parse supported content locally; block unknown, encrypted, corrupted, or over-budget content.
5. Run deterministic secret/structured/entropy/encoding detectors.
6. Run pinned local NER/classification models in a network-denied sandbox.
7. Merge and resolve spans conservatively; policy decides allow, typed replacement, or block.
8. Replace spans without generative rewriting. Use stable synthetic placeholders when semantic
   continuity is needed; keep any reversible mapping in an encrypted local, short-lived vault.
9. Rescan the exact serialized bytes that will leave the machine. Block on residual findings,
   serialization drift, detector/model failure, or ambiguity above policy thresholds.
10. Resolve and pin an approved HTTPS destination, inject provider credentials locally, forward
    only allowlisted headers, and emit a metadata-only tamper-evident audit event.
11. Enforce the same destination policy at the OS/container network layer so bypass is difficult.

## Complete file blueprint

The list below is the recommended production-oriented boundary. Files marked **modify** already
exist; all others are new. Keeping these responsibilities separate makes every fail-closed path
independently testable.

### 1. Application boundary and middleware

| File | Purpose |
|---|---|
| `src/ai_firewall/main.py` **modify** | Minimal process entrypoint; construct the app only. |
| `src/ai_firewall/app.py` | Environment-aware FastAPI app factory; disable docs in production and register lifespan, middleware, routers, and safe exception handlers. |
| `src/ai_firewall/lifecycle.py` | Validate policy/models on startup, build clients and queues, expose readiness, and close/zeroize resources on shutdown. |
| `src/ai_firewall/api/dependencies.py` | Central authenticated-client, policy snapshot, scan budget, and request-context dependencies. |
| `src/ai_firewall/api/routes/health.py` | Separate unauthenticated liveness from authenticated readiness; reveal no rule/model inventory publicly. |
| `src/ai_firewall/api/routes/scan.py` | Strict scan-only contract with authorization, quotas, and safe response shaping. |
| `src/ai_firewall/api/routes/proxy.py` | Thin orchestration endpoint; no detection, URL, or credential logic inline. |
| `src/ai_firewall/api/routes/admin.py` | Optional privileged policy/model status and reload endpoints with separate authorization; no payload access. |
| `src/ai_firewall/middleware/body_limit.py` | Enforce raw and decompressed request limits before parsing. |
| `src/ai_firewall/middleware/request_context.py` | Generate random request IDs and carry client/policy metadata without payload data. |
| `src/ai_firewall/middleware/security_headers.py` | Add API-appropriate security headers and production Host validation configuration. |
| `src/ai_firewall/middleware/errors.py` | Convert exceptions into generic client errors while retaining metadata-only diagnostics. |

### 2. Configuration, policy, and decision engine

| File | Purpose |
|---|---|
| `src/ai_firewall/config.py` **modify** | Strict settings, secret references, environment validation, safe production defaults, and all resource limits. |
| `src/ai_firewall/models.py` **modify** | Remove broad transport models and `Any` where possible; keep only shared public DTOs with `extra="forbid"`. |
| `src/ai_firewall/policy.py` **modify** | Compatibility facade or remove after migration; never retain permissive fallback parsing. |
| `src/ai_firewall/policy/schema.py` | Strict versioned Pydantic schema for clients, providers, content classes, detectors, thresholds, replacement modes, and failure actions. |
| `src/ai_firewall/policy/loader.py` | Bounded YAML loading, schema validation, atomic activation, last-known-good handling, and safe reload. |
| `src/ai_firewall/policy/signatures.py` | Verify policy manifest signatures/digests, issuer, expiry, and rollback protection. |
| `src/ai_firewall/policy/evaluator.py` | Pure decision function: findings + client + destination + content type + detector health to allow/replace/block. |
| `src/ai_firewall/policy/exceptions.py` | Typed policy errors that always map to block/unready, never implicit allow. |
| `config/policy.yaml` **modify** | Default-block policy with explicit supported flows, mandatory detectors, confidence bands, and failure behavior. |
| `config/policy.schema.json` | Machine-readable policy schema for editors, CI, and offline validation. |
| `config/providers.yaml` | Approved HTTPS host/port/API-path tuples and permitted provider features. |
| `config/models.yaml` | Local model IDs, immutable digests, runtime, memory/time budgets, purpose, license, and minimum versions. |

### 3. Detection pipeline

| File | Purpose |
|---|---|
| `src/ai_firewall/scanner.py` **modify** | Compatibility facade; delegate to the bounded orchestrator and remove unbounded recursive traversal. |
| `src/ai_firewall/detection/types.py` | Immutable normalized document, span, finding, evidence-class, confidence, and detector-health types; never store matched raw text in findings. |
| `src/ai_firewall/detection/base.py` | Detector protocol with capabilities, input classes, timeout, and deterministic failure contract. |
| `src/ai_firewall/detection/orchestrator.py` | Parallel safe detector execution, global budgets, mandatory-detector health gate, span merge, and conservative conflict handling. |
| `src/ai_firewall/detection/regex.py` | Existing policy patterns with bounded input, match limits, safe-regex checks, and validator-aware replacement spans. |
| `src/ai_firewall/detection/secrets.py` | Provider-aware credential/private-key/token detectors with format/checksum/context validation. |
| `src/ai_firewall/detection/structured.py` | Luhn cards plus national IDs, phones, emails, IPs, account identifiers, and configurable regional validators using synthetic tests only. |
| `src/ai_firewall/detection/entropy.py` | High-entropy token detection with context and allowlists to reduce false positives. |
| `src/ai_firewall/detection/encoded.py` | Bounded base64/URL/hex/JWT decoding and recursive inspection with expansion/depth limits; never execute content. |
| `src/ai_firewall/detection/fragmentation.py` | Detect secrets split across JSON fields, messages, tool arguments, or stream frames using bounded canonical views. |
| `src/ai_firewall/detection/context.py` | Contextual scoring and allowlisted public/example data handling without weakening critical secret rules. |
| `src/ai_firewall/detection/local_ner.py` | Convert local token-classification/NER output into validated spans for person, location, organization, health, and other configured PII. |
| `src/ai_firewall/detection/local_classifier.py` | Local document/sentence sensitivity classification as a conservative policy signal, not a replacement generator. |
| `src/ai_firewall/detection/residual.py` | Rescan final serialized egress bytes with independent detectors and block residual sensitive spans. |

### 4. Local model runtime

| File | Purpose |
|---|---|
| `src/ai_firewall/local_models/spec.py` | Strict model manifest and structured inference input/output schemas. |
| `src/ai_firewall/local_models/registry.py` | Load only allowlisted local artifacts, verify SHA-256/signatures, reject mutable revisions and remote code. |
| `src/ai_firewall/local_models/runtime.py` | Runtime-neutral inference interface with deadlines, concurrency/memory limits, cancellation, and circuit breakers. |
| `src/ai_firewall/local_models/transformers_runtime.py` | Optional in-process Transformers implementation with offline mode and `trust_remote_code=False`. |
| `src/ai_firewall/local_models/ollama_runtime.py` | Optional loopback/Unix-socket Ollama adapter that rejects non-local endpoints and requires JSON-schema output. |
| `src/ai_firewall/local_models/onnx_runtime.py` | Preferred bounded ONNX token-classification runtime for predictable, non-generative NER. |
| `src/ai_firewall/local_models/sandbox.py` | Launch/verify an isolated worker with no network, read-only model mount, resource limits, and restricted IPC. |
| `src/ai_firewall/local_models/worker.py` | Dedicated inference worker process that accepts normalized text and returns spans only; no logging of content. |
| `src/ai_firewall/local_models/health.py` | Warmup, self-tests with synthetic canaries, readiness, drift/version telemetry, and fail-closed health state. |
| `src/ai_firewall/local_models/prompts.py` | Versioned local-classifier prompts/schema if a generative local model is used; explicitly prohibit returning or persisting source text. |

### 5. Replacement and pseudonymization

| File | Purpose |
|---|---|
| `src/ai_firewall/redaction/types.py` | Replacement plan, stable entity ID, overlap, reversibility, and provenance types. |
| `src/ai_firewall/redaction/spans.py` | Validate Unicode offsets, normalize spans, resolve overlaps by severity/specificity, and reject malformed model output. |
| `src/ai_firewall/redaction/replacer.py` | Deterministic typed placeholders such as `[PERSON_1]`; preserve structure without asking a model to rewrite the whole input. |
| `src/ai_firewall/redaction/synthesizer.py` | Optional local generation of format-compatible synthetic values under strict type constraints and post-generation validation. |
| `src/ai_firewall/redaction/pseudonyms.py` | Request/session-scoped consistent pseudonyms so repeated entities retain meaning across a conversation. |
| `src/ai_firewall/redaction/vault.py` | Optional encrypted, TTL-bound, capacity-limited local mapping for authorized rehydration; disabled by default. |
| `src/ai_firewall/redaction/validator.py` | Verify replacements match the plan, the source never reappears, and serialized output passes the residual scan. |
| `src/ai_firewall/redaction/rehydrator.py` | Optional inbound rehydration after authorization, exact placeholder matching, TTL checks, and metadata-only audit. |

### 6. Content normalization and safe parsers

| File | Purpose |
|---|---|
| `src/ai_firewall/content/types.py` | Canonical text segment, attachment, image region, message, tool argument, and provenance types. |
| `src/ai_firewall/content/limits.py` | Shared depth, bytes, pages, pixels, frames, archive ratio, and parse-time budget enforcement. |
| `src/ai_firewall/content/json.py` | Iterative bounded JSON walker that inspects keys and values and preserves safe reconstruction paths. |
| `src/ai_firewall/content/text.py` | Unicode normalization and confusable/zero-width handling while preserving an offset map to original content. |
| `src/ai_firewall/content/files.py` | Magic-byte type detection, filename distrust, encrypted/unsupported-file rejection, and parser dispatch. |
| `src/ai_firewall/content/pdf.py` | Sandboxed bounded PDF text extraction; block malformed/encrypted PDFs; preserve page provenance. |
| `src/ai_firewall/content/office.py` | Sandboxed DOCX/PPTX/XLSX extraction without macros, external links, or formula execution. |
| `src/ai_firewall/content/images.py` | Decode with pixel/frame limits, strip metadata, and produce image regions for OCR/redaction. |
| `src/ai_firewall/content/ocr.py` | Local OCR adapter returning text spans and bounding boxes for image redaction. |
| `src/ai_firewall/content/archives.py` | Safe allowlisted archive extraction with entry/path/count/size/ratio limits; reject nesting and encryption by policy. |
| `src/ai_firewall/content/audio.py` | Optional local speech-to-text with duration/size limits and timestamped spans; block audio until enabled. |

### 7. Destination, provider, and transport security

| File | Purpose |
|---|---|
| `src/ai_firewall/proxy/destination.py` | Validate HTTPS scheme, exact IDNA-normalized host, allowed port and API path, and reject URL userinfo/fragments. |
| `src/ai_firewall/proxy/resolver.py` | Resolve all addresses, reject special/private ranges, pin the validated result, and defend against DNS rebinding. |
| `src/ai_firewall/proxy/headers.py` | Build a minimal header allowlist; strip hop-by-hop, Host, forwarding, length, and caller authorization headers. |
| `src/ai_firewall/proxy/credentials.py` | Fetch provider credentials by opaque reference from OS keychain/secret manager; redact and zeroize where feasible. |
| `src/ai_firewall/proxy/client.py` | Hardened HTTPX transport: TLS verification, bounded pool/timeouts, no environment proxy inheritance, no redirects by default. |
| `src/ai_firewall/proxy/streaming.py` | Bounded SSE/chunk parser with frame reassembly and inspection-before-flush semantics. |
| `src/ai_firewall/proxy/response.py` | Bounded response scanning, safe header copying, content-type validation, and optional placeholder rehydration. |
| `src/ai_firewall/providers/base.py` | Adapter contract for normalization, credential injection, request serialization, streaming, and response parsing. |
| `src/ai_firewall/providers/openai.py` | Explicitly supported OpenAI routes/fields and multimodal/tool normalization. |
| `src/ai_firewall/providers/anthropic.py` | Explicitly supported Anthropic routes/fields and stream events. |
| `src/ai_firewall/providers/google.py` | Explicitly supported Gemini routes/fields and stream events. |
| `src/ai_firewall/providers/generic.py` | Disabled by default; narrow schema-based adapter for explicitly configured providers only. |

### 8. Client identity, authorization, and abuse resistance

| File | Purpose |
|---|---|
| `src/ai_firewall/security/identity.py` | Map mTLS certificate, Unix peer, or workload token to a stable client identity. |
| `src/ai_firewall/security/authentication.py` | FastAPI dependency for constant-time credential validation and generic failures. |
| `src/ai_firewall/security/authorization.py` | Enforce client-to-provider/model/content/action permissions and per-client exception scope. |
| `src/ai_firewall/security/rate_limit.py` | Bounded per-client concurrency, request, byte, and expensive-model quotas without logging payloads. |
| `src/ai_firewall/security/key_management.py` | OS keychain/KMS abstraction and key rotation for audit signing and optional pseudonym vault encryption. |

### 9. Audit, metrics, and privacy-safe operations

| File | Purpose |
|---|---|
| `src/ai_firewall/audit.py` **modify** | Compatibility facade; prohibit raw payload/header/match fields at the type boundary. |
| `src/ai_firewall/auditing/events.py` | Versioned allowlisted metadata-only event schemas. |
| `src/ai_firewall/auditing/writer.py` | Bounded async queue, locked atomic append/batch, restrictive permissions, rotation, and explicit failure policy. |
| `src/ai_firewall/auditing/integrity.py` | Hash-chain/sign audit records and verify sequence integrity without hashing raw sensitive values. |
| `src/ai_firewall/auditing/retention.py` | Size/time retention and safe deletion policy that cannot target broad paths. |
| `src/ai_firewall/observability/metrics.py` | Low-cardinality counts/latencies/health only; never content, paths, tokens, or raw destination URLs. |
| `src/ai_firewall/observability/logging.py` | Structured logging filters that remove auth/cookies/query data and prevent exception object leakage. |
| `src/ai_firewall/observability/health.py` | Aggregate policy, model, audit, disk, resolver, and provider-adapter readiness. |

### 10. CLI and deployment enforcement

| File | Purpose |
|---|---|
| `src/ai_firewall/cli.py` | Offline `validate-policy`, `verify-models`, `self-test`, and `audit-verify` commands using synthetic inputs only. |
| `src/ai_firewall/__main__.py` | Safe CLI entrypoint; never start a public listener implicitly. |
| `deploy/model-worker.Dockerfile` | Network-denied non-root local inference worker with read-only pinned artifacts. |
| `deploy/seccomp/firewall.json` | Narrow syscall profile for the API container, validated per target platform. |
| `deploy/seccomp/model-worker.json` | Narrower inference-worker syscall profile. |
| `deploy/healthcheck.py` | Local readiness check with no policy details or secrets. |
| `deploy/egress-policy.example.yaml` | Example Kubernetes/CNI or host egress rules allowing only configured provider IP strategy and local model IPC. |
| `Dockerfile` **modify** | Pin base image by digest, use reproducible installs, add healthcheck, read-only root filesystem support, and remove build caches/tools. |
| `docker-compose.yml` **modify** | Internal model network only, no model egress, read-only filesystems, dropped capabilities, resource limits, tmpfs, and explicit health dependencies. |
| `pyproject.toml` **modify** | Add constrained optional parser/model extras, type checker/test tools, CLI entrypoint, and security tooling. Every new parser/model dependency needs documented rationale. |
| `requirements.lock` | Hash-pinned reproducible runtime dependency lock generated by the chosen package workflow. |

### 11. Required tests

| File | Purpose |
|---|---|
| `tests/conftest.py` | Isolated app factory, network-deny fixture, synthetic policies/models, temp audit/vault, and strict timeouts. |
| `tests/unit/test_policy_schema.py` | Reject omissions, unknown fields, duplicates, invalid regex/validators, permissive defaults, expiry, and unsupported versions. |
| `tests/unit/test_policy_signatures.py` | Signature, digest, expiry, rollback, atomic reload, and last-known-good tests. |
| `tests/unit/test_decisions.py` | Strictest-action, mandatory-detector failure, ambiguity, client scope, and default-block truth table. |
| `tests/unit/test_limits.py` | Raw/decompressed size, depth, nodes, strings, pages, pixels, frames, matches, archive ratio, and time budgets. |
| `tests/unit/test_regex_detector.py` | Overlaps, validator-aware spans, Unicode, match caps, and ReDoS time budgets. |
| `tests/unit/test_secret_detector.py` | Synthetic provider token/private-key formats and near-miss cases; never real credentials. |
| `tests/unit/test_entropy_detector.py` | Context thresholds, public hashes, generated test tokens, and false-positive controls. |
| `tests/unit/test_encoding_detector.py` | Nested base64/URL/hex/JWT limits, expansion bombs, and fragmented values. |
| `tests/unit/test_local_ner.py` | Span alignment, confidence bands, malformed offsets, Unicode, model timeout/crash, and no-content logging. |
| `tests/unit/test_redaction.py` | Overlaps, stable typed pseudonyms, structure preservation, no source substring in output, and residual scan. |
| `tests/unit/test_vault.py` | Encryption, TTL, capacity, authorization, rotation, crash cleanup, and disabled-by-default behavior. |
| `tests/unit/test_json_content.py` | Keys and values, extreme nesting, non-string types, canonicalization, and reconstruction. |
| `tests/unit/test_file_parsers.py` | Magic bytes, malformed/encrypted files, external references, macros, formulas, and parser sandbox failures. |
| `tests/unit/test_images_ocr.py` | Pixel/frame/metadata limits, local OCR boxes, visual replacement, and residual OCR scan. |
| `tests/unit/test_archives.py` | Traversal, symlinks, nesting, entry count, compression ratio, encryption, and unsupported types. |
| `tests/unit/test_destination.py` | HTTP rejection, userinfo, IDNA, trailing dots, case, ports, paths, IPv4/IPv6 special ranges, and metadata IPs. |
| `tests/unit/test_dns_pinning.py` | Multiple answers, rebinding, resolution changes, private answer among public answers, and TOCTOU resistance. |
| `tests/unit/test_headers.py` | Authorization/Host/hop-by-hop/forwarding stripping and minimal provider-specific allowlists. |
| `tests/unit/test_credentials.py` | Local injection, client credential rejection, rotation, and assurance that errors/audits never contain values. |
| `tests/unit/test_streaming.py` | Split secrets across frames, buffer caps, malformed SSE, cancellation, detector failure, and inspect-before-flush. |
| `tests/unit/test_audit_privacy.py` | Recursively assert events/logs/exceptions never contain synthetic payload, matches, auth, cookies, or vault values. |
| `tests/unit/test_audit_integrity.py` | Concurrent writes, rotation, tamper detection, disk-full behavior, permissions, and sequence validation. |
| `tests/api/test_auth.py` | Every non-liveness route denied by default; client authorization and rate limits. |
| `tests/api/test_scan.py` | Strict schemas, content limits, blocked payload suppression, replacement output, and safe findings. |
| `tests/api/test_proxy.py` | End-to-end normalized scan/rescan/credential/destination flow with a local fake upstream only. |
| `tests/api/test_errors.py` | Generic errors for parse, policy, model, resolver, audit, and upstream failures with no sensitive details. |
| `tests/integration/test_local_model_worker.py` | Offline pinned loading, no-network sandbox, warmup, crash/restart, deadlines, and resource caps. |
| `tests/integration/test_provider_adapters.py` | Recorded fully synthetic protocol fixtures for each supported provider and streaming mode. |
| `tests/integration/test_fail_closed_matrix.py` | Kill/fault every dependency and verify no ambiguous high-risk request reaches the fake upstream. |
| `tests/property/test_scanner_properties.py` | Property tests: source spans removed, output serializable, deterministic decisions, bounded work, and idempotent replacement. |
| `tests/fuzz/test_json_and_stream_fuzz.py` | Coverage-guided malformed JSON/SSE/chunk input without network or sensitive seed data. |
| `tests/security/test_ssrf.py` | Controlled resolver/transport tests for loopback, RFC1918, link-local, metadata, IPv6, DNS rebinding, and redirects. |
| `tests/security/test_bypass_corpus.py` | Synthetic obfuscation/fragmentation/confusable/encoding cases with expected policy outcomes. |
| `tests/security/test_no_network.py` | Assert scanners, parsers, and local models cannot open non-approved sockets. |
| `tests/performance/test_budgets.py` | Latency/memory/concurrency budgets and adversarial worst cases for every detector/parser. |

Existing `tests/test_api.py` and `tests/test_scanner.py` should either be expanded and moved into
this structure or retained as small smoke tests; do not duplicate them unchanged.

### 12. CI and supply-chain files

| File | Purpose |
|---|---|
| `.github/workflows/ci.yml` | Run lint, format check, type check, unit/integration/security tests, and build with network denied where feasible. |
| `.github/workflows/security.yml` | Dependency audit, secret scan, static analysis, SBOM, image scan, and scheduled patch checks. |
| `.github/dependabot.yml` | Controlled dependency update proposals for Python, Actions, and container images. |
| `scripts/verify_release.py` | Verify clean source, tests, lock hashes, policy/model manifests, SBOM, image digest, and synthetic self-test before release. |
| `scripts/download_model.py` | Explicit offline artifact fetch by approved URL and digest; never dynamically download during service startup. |
| `scripts/generate_sbom.sh` | Generate an SBOM with a pinned tool; contains no runtime data. |

## Recommended implementation order

1. **Containment first:** AF-001 through AF-005, app-level body limits, default-block policy,
   authentication, HTTPS/DNS/IP validation, header allowlisting, and local credential injection.
2. **Deterministic DLP:** bounded canonicalization, secret/structured/entropy/encoding detectors,
   replacement spans, final serialized-byte rescan, and audit hardening.
3. **Local model layer:** pinned offline NER first; optional local classifier second. Add the
   generative synthesizer only after deterministic placeholders are proven and keep it optional.
4. **Content breadth:** provider adapters, files/OCR/archives/audio, then bounded streaming.
5. **Enforcement and assurance:** OS/container egress controls, signed policy/model supply chain,
   fuzz/property/adversarial tests, CI, metrics, and operational runbooks.

The minimum credible first production milestone is not the whole blueprint. It is phases 1 and 2
with only JSON/text provider requests enabled, every unsupported content type blocked, local NER
healthy and mandatory when policy requires it, and independent network egress enforcement in place.
