# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.3.x | yes |
| < 1.3 | no |

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository if it is
enabled. If private reporting is unavailable, contact the maintainers through a
non-public channel before disclosing details.

Please do **not** open GitHub issues for security findings.

### What to include

Please include:

* affected version or commit,
* deployment assumptions (`AURA_*` settings, reverse proxy, TSA usage),
* reproduction steps or proof-of-concept,
* impact assessment and any suggested mitigations.

We aim to acknowledge reports within 3 business days. Remediation timelines are
best-effort and depend on severity, exploitability, and release scope.

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
* **CORS deny-by-default** — the runtime does not emit any
  `Access-Control-Allow-Origin` header unless `AURA_ALLOWED_ORIGINS` is
  set to a strict allow-list (comma-separated, no wildcards).
* **Fail-closed** — any audit-log write failure flips a halted flag.
  Subsequent requests return HTTP 503 and `/ready` returns 503. The operator
  must restart the service after restoring filesystem capacity.
* **Memory safety** — the runtime is built with `#![forbid(unsafe_code)]`.

## Configuration guardrails

Security-relevant startup checks enforced by `Config::validate`:

* `AURA_API_KEY` is mandatory unless `AURA_AUTH_DISABLED=true`.
* API keys shorter than 32 bytes are rejected.
* Well-known placeholder API keys (for example `changeme`, `password`,
  `apikey`) are rejected.
* `AURA_AUTH_DISABLED=true` is rejected when binding to a non-loopback address.

## Verification and evidence operations

Security-sensitive operator workflows that are implemented in the current tree:

* `aura-replay --verify-lineage` checks that each logged `policy_hash`
  still matches the signed policy bytes on disk.
* `aura-replay --verify-segments` adds manifest-chain and Merkle verification.
* `aura-seal verify-tst --tsa-roots <bundle.pem>` performs strict RFC 3161 /
  RFC 5652 verification against operator-pinned trust anchors.
* `aura-seal verify-tst` without `--tsa-roots` is intentionally weaker:
  imprint-only verification for backward compatibility.

## Out-of-scope

Network-layer DoS, kernel exploits, supply-chain attacks on the build host,
and AI hallucination detection are explicitly out-of-scope for the runtime
itself. See `docs/THREAT_MODEL.md` §5.

## Supply chain

The CI workflow in `.github/workflows/ci.yml` currently runs:

* `cargo build --locked --release --all-targets`
* `cargo test --locked --all-targets`
* `cargo clippy --all-targets --all-features -- -D warnings`
* `cargo audit --deny warnings --ignore RUSTSEC-2023-0071`
* `cargo deny check`
* `cargo cyclonedx --format json --override-filename sbom.cdx`

The generated CycloneDX artifact is `sbom.cdx.json`. The `cargo-audit` ignore
for `RUSTSEC-2023-0071` is intentional and documented in `deny.toml`: this
codebase uses `rsa` only for public-key verification in the strict TSA token
verifier, not for private-key operations affected by the advisory.
