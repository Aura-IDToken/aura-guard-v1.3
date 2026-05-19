# Changelog

All notable changes to this project are documented in this file.
The format is loosely based on [Keep a Changelog](https://keepachangelog.com/),
versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added — v1.4 (Merkle batching + optional RFC 3161 timestamping)
- **`src/merkle.rs`** — RFC 6962 leaf/node hashing
  (`SHA-256(0x00||leaf)`, `SHA-256(0x01||left||right)`), left-heavy
  Merkle root, audit-path proof generation and verification. Independent
  of every other subsystem; reusable from external verifiers.
- **`src/segment.rs`** — Segment manifests
  (`logs/segments/NNNNNN.manifest.json`). Each manifest pins a
  contiguous slice of the audit log via its Merkle root, the previous
  manifest's `segment_chain_hash`, and the head `chain_hash` at close.
  Genesis seed: `SHA-256("AURA-GUARD-SEGMENT-GENESIS-v1")`. Manifests
  are written atomically (temp → rename → fsync) and never re-opened.
- **`src/sealer.rs`** — Runtime segment sealer with dual triggers
  (`AURA_SEGMENT_SIZE` entry count and `AURA_SEGMENT_INTERVAL_SECONDS`
  wall-clock) plus graceful shutdown flush. Crash-recovery primes the
  open-segment buffer from any unsealed audit-log tail.
- **`src/bin/aura-seal`** — Offline verifier and proof generator.
  Subcommands: `verify`, `verify-chain`, `proof --seq N`,
  `verify-tst [--segment-id N]`. Exit codes `4` (segment-chain break),
  `5` (manifest/log mismatch), `6` (TST invalid).
- **`aura-replay --verify-segments`** — Verifies both the per-entry
  chain and the segment-chain in a single pass.
- **`src/rfc3161.rs`** — Minimal hand-rolled DER encoder for
  `TimeStampReq` (SHA-256). Optional RFC 3161 submission is **off by
  default**; enable with `AURA_TSA_URL`. Submission runs on
  `tokio::task::spawn_blocking`, persists the raw `TimeStampResp`
  bytes to `logs/segments/NNNNNN.tsr`, and is **fail-open** —
  transport errors, HTTP failures, and imprint mismatches are logged
  and counted (`aura_tsa_request_failures_total`) but never halt the
  service.
- **Threat-model coverage**: detects single-entry tampering, sealed
  manifest forgery, manifest deletion or reordering, manifest
  backdating (when TSA stamping is enabled).
- New configuration: `AURA_SEGMENTS_DIR`, `AURA_SEGMENT_SIZE` (default
  `1000`, `0` disables), `AURA_SEGMENT_INTERVAL_SECONDS` (default
  `60`, `0` disables), `AURA_TSA_URL` (unset by default),
  `AURA_TSA_TIMEOUT_SECONDS` (default `10`).
- New metrics: `aura_segments_sealed_total`,
  `aura_segment_entries_total`, `aura_segments_open_entries`,
  `aura_segments_seal_errors_total`, `aura_tsa_requests_total`,
  `aura_tsa_request_failures_total`.
- New dependency: `ureq` 2.10 with `rustls` (pure-Rust TLS, no system
  OpenSSL). Pulled only when `AURA_TSA_URL` is set at runtime.
- [`docs/segments-and-timestamping.md`](docs/segments-and-timestamping.md)
  — Architecture, layout-on-disk, manifest schema, sealing triggers,
  verifier walkthrough, threat-model addendum, metric reference.

### Changed
- **CORS hardened to deny-by-default.** The runtime no longer emits
  `Access-Control-Allow-Origin: *`. Configure
  `AURA_ALLOWED_ORIGINS="https://app.example.com,https://ops.example.com"`
  to opt into a strict allow-list. Wildcards are intentionally
  unsupported.
- README restructured around the standard OSS infrastructure template
  (features → quickstart → demo → threat model → architecture → exit
  codes → benchmarks → deployment → security → roadmap → license).
- Branding cleanup: removed marketing-style "Atom-Grade" suffix from
  README, CHANGELOG, ROADMAP, `Cargo.toml`, OpenAPI spec, and the
  replay-demo talking points.
- `scripts/replay-demo.sh` now prints structured step headers and the
  observed exit code at each phase.

### Added
- [`docs/exit-codes.md`](docs/exit-codes.md) — canonical exit-code
  contract for supervisors (systemd `RestartPreventExitStatus=78`,
  Kubernetes CrashLoopBackOff guidance), now including `4`/`5`/`6` for
  the segment + TST verifiers.
- [`docs/policy-signing.md`](docs/policy-signing.md) — Ed25519 key
  management, rotation, and multi-signer workflow notes.
- [`docs/deployment.md`](docs/deployment.md) — Docker / systemd /
  Kubernetes runbooks and a hardening checklist.

### Deferred to v1.5
- Full ASN.1 parsing of `TSTInfo`, PKIX certificate-chain validation,
  and signature verification of the TSA `SignedData`. `aura-seal
  verify-tst` currently checks `messageImprint == SHA-256(preimage)`,
  which is sufficient to detect bait-and-switch and post-stamp
  tampering, but does not yet anchor trust in an operator-pinned root.

## [1.3.0] — 2026-05-12

### Added
- **Bootstrap fail-closed gate.** Aura-Guard now refuses to start (exit
  code `78`, `sysexits.h::EX_CONFIG`) if any policy listed in
  `EXPECTED_POLICIES` fails to load and signature-verify at boot.
  Previously a `warn!` was emitted and the runtime continued with a
  lazy-load fallback — a temporal integrity gap that violated the
  protocol's deterministic-evidence contract.
- Runtime `resolve_policy` is now **cache-only**: unknown policies return
  HTTP 400 with a "not pre-loaded at boot" message instead of touching
  disk on the hot path.
- `aura-replay --verify-lineage` (replaces the misleadingly named
  `--recompute`). The legacy flag is retained as a deprecated alias and
  prints a one-time stderr warning. The new name reflects what the CLI
  actually checks: cryptographic *continuity* between the policy
  on-disk and the policy referenced by each entry — **not** model
  re-execution. Mismatches abort with exit code 3 (`LINEAGE MISMATCH`).
- Integration test `tests/bootstrap_fail_closed.rs` that spawns the real
  binary and asserts exit code `78` for missing-policy and
  missing-signer scenarios.
- SHADOW_SPEC v1.0 normalizer (NFKC + hidden-char strip + confusable fold +
  lowercase) with the original input preserved for the evidence hash.
- Semantic validators: Luhn (credit card / IMEI), PESEL checksum + date
  sanity, IBAN mod-97.
- Hash-chained audit log (`prev_hash` + `chain_hash`) seeded by a canonical
  genesis hash `SHA-256("AURA-GUARD-GENESIS-v1.3")`.
- Ed25519 policy signature enforcement with `aura-sign-policy` tooling and
  `policies/trusted_signers.json` verifier registry.
- `aura-replay` offline CLI returning exit code 2 on `CHAIN BREAK DETECTED`.
- API-key authentication (`X-API-Key` / `Bearer`, constant-time compare),
  body limit, request timeout, structured `tracing` logs, Prometheus
  `/metrics`, `/health`, `/ready`, `/version`.
- 20+ unit tests, 9 golden policy tests, 6 HTTP integration tests.
- GitHub Actions CI: `fmt`, `clippy -D warnings`, `test --locked`,
  `cargo-audit`, `cargo-deny`, CycloneDX SBOM artifact.
- Multi-stage distroless Dockerfile, docker-compose, hardened systemd unit.
- OpenAPI 3.0 spec for `/v1/audit`.

### Fixed
- v1.2 regression where SHADOW input was lowercased *before* uppercase regex
  literals (e.g. `PL[0-9]{26}`) had a chance to fire — now patterns are
  compiled with `(?i)` so the original YAML remains readable.
- v1.2 false positives on credit card / PESEL / IBAN detection — all three
  now run a semantic checksum *after* the regex match.
- v1.2 silent log-write fallback (warning printed but request still
  acknowledged) — replaced with `halt-on-log-failure`: the writer flips a
  halted flag and the API returns HTTP 503 until the operator restarts.

### Removed
- Unauthenticated `/v1/audit` access (now always requires an API key unless
  `AURA_AUTH_DISABLED=true`, which is for local dev and the test suite only).

## [1.2.0] — 2026-04 — superseded
See the v1.2 readiness report for details. Not recommended for new
deployments — please upgrade to 1.3.x.
