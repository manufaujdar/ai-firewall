# Research and deployment limitations

AI Firewall is an open-source research prototype, not a guarantee against data loss and not an
endpoint-security product. It only inspects requests deliberately sent to its authenticated local
API. Applications can bypass it unless separate OS, browser, device-management, or network egress
controls force traffic through an approved path.

## Current supported boundary

- JSON values accepted by `/v1/scan`
- Deterministic configured regular expressions and a Luhn validator
- Bounded request size, object depth, and node count
- Metadata-only audit events
- Metadata-only local SQLite summaries and real-time graph events
- Residual serialized-output scan after deterministic redaction
- Offline model artifact/digest/span contracts with an empty default registry
- Local API-key authentication and trusted Host enforcement

## Unsupported or incomplete

- File uploads, documents, archives, images, OCR, audio, video, and clipboard monitoring
- Encoded, fragmented, encrypted, obfuscated, or visually confusable secrets
- Streaming request or response inspection
- A validated local NER or sensitivity model and sandboxed runtime (framework only; none enabled)
- Provider credential injection and DNS connection pinning
- Signed policy distribution, tamper resistance, enterprise identity, and centralized administration
- Browser-extension, system-proxy, VPN, EDR, or OS network-extension enforcement

Pattern matches can be false positives or miss sensitive context. A redacted result is not proof
that a payload is safe. Operators must review results, establish an approved data-classification
policy, and validate the complete deployment in their own threat model before using real data.
