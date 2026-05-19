# Roadmap

Semver-style. Dates are targets, not commitments. v1.4+ items are intentionally
out of scope for v1.3 to keep the deterministic core small and reviewable.

## Shipped in v1.3

* **Bootstrap fail-closed gate** — exit code `78` (`EX_CONFIG`) if any
  expected policy fails to load and signature-verify at boot. Runtime
  `resolve_policy` is cache-only (no lazy-load path).
* Shadow normalizer (SHADOW_SPEC v1.0): NFKC + hidden-char strip + confusable
  folding + lowercase.
* Semantic validators: Luhn (CC), PESEL (PL national ID), IBAN mod-97.
* Hash-chained audit log (`chain_hash`, `prev_hash`, canonical genesis).
* Ed25519 policy signing (`aura-sign-policy`), fail-closed verification.
* `aura-replay` offline CLI — exit 2 on `CHAIN BREAK`, exit 3 on
  `LINEAGE MISMATCH` (`--verify-lineage`; legacy `--recompute` alias).
* API-key authentication, body limit, request timeout, structured tracing,
  Prometheus `/metrics`, `/health` `/ready` `/version`.
* Multi-stage distroless Dockerfile, docker-compose, systemd unit.
* GitHub Actions CI: build / fmt / clippy `-D warnings` / test / `cargo-audit`
  / `cargo-deny` / CycloneDX SBOM artifact.
* 21 unit + 2 bootstrap fail-closed + 10 golden + 6 HTTP integration tests.

## Shipped in v1.4 — Evidence anchoring

* **Merkle batching (RFC 6962)** — contiguous slices of the audit log are
  sealed into segment manifests with a left-heavy Merkle root and
  inclusion proofs in `O(log N)`.
* **Segment-chain** — each manifest pins the previous manifest's hash,
  closing the gap between per-entry tampering (already detected) and
  manifest-level tampering (deletion, reordering, forged replacement).
* **`aura-seal` CLI** — offline `verify`, `verify-chain`, `proof`,
  `verify-tst`. Exit codes `4` / `5` / `6` for segment-chain break,
  log/manifest mismatch, and TST invalid.
* **Optional RFC 3161 timestamping** — opt-in via `AURA_TSA_URL`,
  fail-open on TSA outages, Prometheus `aura_tsa_requests_total` and
  `aura_tsa_request_failures_total`. Off by default to keep the
  deterministic core network-free.

## v1.5 — Enterprise & ops

* **Full `.tsr` verification** — ASN.1 parse of `TSTInfo`, PKIX chain
  validation against an operator-pinned TSA root, `SignedData`
  signature verification. v1.4 currently only checks
  `messageImprint == SHA-256(preimage)`.
* **cosign / sigstore** release attestations for both the binary and the SBOM.
* **OpenTelemetry** spans / OTLP exporter alongside the existing tracing JSON.
* **mTLS** termination inside `axum` (currently delegated to the reverse proxy).
* **Helm chart** + **Kubernetes operator** for declarative deployment.
* **RBAC** on policy management endpoints, multi-tenant policy directories.
* **HA clustering** with synchronized chain heads (gossip + leader election).
* **SIEM connectors** — Splunk HEC, Elastic Common Schema, AWS CloudTrail
  format adapters.
* **HSM signing** for policy keys (PKCS#11).
* **Encrypted Evidence Vault** — optional sealed store for raw prompts so a
  new `aura-replay --re-evaluate` mode can reproduce the full model
  decision while preserving GDPR data minimization at rest. (Today's
  `--verify-lineage` only proves policy-hash continuity, not model output;
  the rename was made specifically to stop overpromising on that front.)

## v1.6 — Governance platform (2027)

* Policy approval workflows (4-eye review).
* Human-review queue UI for `REVIEW` decisions.
* Cross-policy simulation (replay traffic against a candidate policy without
  modifying the live chain).
* Compliance evidence export bundles (PDF + JSONL + Merkle proof).

## v2.0 — Reference implementation (2027)

* **EVIDENCE_SPEC v1.1** — 162-byte binary evidence envelope, bit-for-bit
  reproducible across implementations.
* Conformance harness with cross-language verifiers (Python, C reference).
* **WORM media** adapters (immutable buckets, MinIO Object Lock, tape).
* **Formal verification** of the decision engine and chain construction with
  Kani / Prusti.
* **Remote attestation** (TPM, AMD SEV-SNP, Intel TDX).
