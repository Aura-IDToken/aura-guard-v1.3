# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.3.x | YES — current Atom-Grade line |
| 1.2.x | security fixes only until 2026-12-31 |
| < 1.2 | not supported (known case-sensitivity bug — please upgrade) |

## Reporting a vulnerability

Send a report to **security@aura-idtoken.example** (encrypted with the PGP key
published on the project landing page). A maintainer will acknowledge within
**3 business days** and provide a fix or mitigation within **30 days**.

Please do **not** open GitHub issues for security findings.

## Threat model

A full STRIDE-style analysis lives in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).
The high-level guarantees:

* **Tamper detection** — the on-disk JSONL audit log is hash-chained from the
  canonical genesis hash. Any field-level or order-level mutation breaks the
  chain and is flagged by `aura-replay` (exit code 2).
* **Policy authenticity** — every policy YAML must be accompanied by a valid
  Ed25519 signature signed by a key listed in `trusted_signers.json`. Missing
  / invalid signatures fail-closed at policy load time.
* **Authentication** — the `/v1/audit` endpoint requires a constant-time-
  compared API key on `X-API-Key` or `Authorization: Bearer`. In production
  combine with mTLS at the reverse proxy / sidecar layer.
* **Fail-closed** — any audit-log write failure flips a halted flag.
  Subsequent requests return HTTP 503 and `/ready` returns 503. The operator
  must restart the service after restoring filesystem capacity.
* **Memory safety** — the runtime is built with `#![forbid(unsafe_code)]`.

## Out-of-scope

Network-layer DoS, kernel exploits, supply-chain attacks on the build host,
and AI hallucination detection are explicitly out-of-scope for the runtime
itself. See `docs/THREAT_MODEL.md` §5.

## Supply chain

Releases are built with `cargo build --locked --release`, scanned with
`cargo-audit` and `cargo-deny`, and accompanied by a CycloneDX SBOM
(`sbom.cdx.json`). Signed releases (cosign / sigstore) are planned for v1.4.
