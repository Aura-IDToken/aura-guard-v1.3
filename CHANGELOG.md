# Changelog

All notable changes to this project are documented in this file.

## [1.3.0] — 2026-05-12 — "Atom-Grade"

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
