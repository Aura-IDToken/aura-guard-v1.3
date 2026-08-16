# D3_REAL_CHAIN_PROVENANCE

## Repository

| | |
|---|---|
| repository | `AuraIDToken/aura-guard-v1.3` |
| branch | `d3/real-chain-observability` |
| base_commit | `443f72e58483c3ea6112ea517647cc0dbf459960` (`main`) |
| base verified | Yes — `git fetch origin main` on execution day returned `443f72e`; PR #54 confirmed **not merged** (commit `6661982` present only on `origin/d3/real-chain-fixture-export`) |
| execution_commit (branch head) | `70b98818be3dddb0f753a7553bc7a40018d0b1b5` |
| `GITHUB_SHA` recorded by CI | `3ae36f84f905b1a1c80be08eaac525e59542f252` — the ephemeral `refs/pull/55/merge` commit GitHub creates for `pull_request` events, **not** the branch head. Recorded verbatim as observed; the code executed is the tree of `70b9881` merged onto `main@443f72e`, which are identical trees for `src/` since `main` is unchanged. |
| workflow_run_id | `31884628865` |
| CI conclusion | `d3-evidence` job **success**; artifact `d3-real-chain-rust-output` (id `9246932001`, 3226 bytes, zip SHA-256 `27cfd127cf35d6f5e0586df5836a8576d826359a2e440b4abe457d6fd5d82c74`) |

## Environment — local execution

| | |
|---|---|
| runner | ephemeral Linux container |
| OS | Linux 6.18.5-fc-v20 |
| architecture | x86_64 |
| rustc | rustc 1.94.1 (e408947bf 2026-03-25) |
| cargo | cargo 1.94.1 (29ea6fb6a 2026-03-24) |

## Environment — CI execution

| | |
|---|---|
| runner | `ubuntu-latest` (GitHub Actions), runner id 1000001388 |
| RUNNER_OS / RUNNER_ARCH | `Linux` / `X64` |
| rustc | `rustc 1.86.0 (05f9846f8 2025-03-31)` |
| cargo | `cargo 1.86.0 (adf9b6ad1 2025-02-28)` |
| toolchain pin | `dtolnay/rust-toolchain@1.86.0` — already used by every other job in `ci.yml` |

### CI-observed results

| | |
|---|---|
| regression control | `cargo test --test d3_chain_observability` — **5 passed, 0 failed** |
| `rust_canonical_bytes_length` | **315** |
| `rust_chain_hash` | `6eb514bf3ce334676d894e669e3d9598d594cc7e21c9bb694daad017f8c20222` |
| `instrumentation_control.identical` | **true** |
| `hash_independence_check.matches_chain_hash` | **true** |
| all four cross-checks | **true** |
| `D3_REAL_CHAIN_CANONICAL.bin` SHA-256 (CI) | `6eb514bf3ce334676d894e669e3d9598d594cc7e21c9bb694daad017f8c20222` |
| `D3_REAL_CHAIN_RUST_OUTPUT.json` SHA-256 (CI) | `42158c2660d690f8cb23d9e128ffd312b7a98035f43abcaab9412bc1128fdf9c` |

The CI copy of `D3_REAL_CHAIN_RUST_OUTPUT.json` hashes differently from the
committed local copy because its CI-metadata fields are populated rather than
`unavailable`. The evidence fields — canonical string, canonical bytes hex,
byte length and chain hash — are identical in both.

**Cross-environment observation:** the canonical bytes and digest are identical
between the local container (rustc 1.94.1, this session's arch) and the CI runner
(rustc 1.86.0, Linux X64). This is an observation about two environments and one
fixture; it is not a determinism claim.

## Fixture

| | |
|---|---|
| path | `D3_REAL_CHAIN_SEMANTIC_FIXTURE.json` |
| bytes | 2630 |
| SHA-256 | `185aa4a81ff571f0ae5e33aaf00f0fb7ea174b9d728b6dab789ab1a468afdae2` |
| determinism | All nine preimage fields are pinned literals. No `Utc::now()`, no live sequence state, no mutable log head participates. |

## Source files inspected

| File | Lines cited | Modified |
|---|---|---|
| `src/chain.rs` | 20, 25-49 (`SEP`, `compute_chain_hash`) | **YES — authorized instrumentation only** |
| `src/api/audit.rs` | 41, 103-129 (`handle_audit`, chain construction) | NO |
| `src/crypto.rs` | 8-12 (`sha256_hex`), 16-20 (`sha256_bytes_hex`), 27-29 (`genesis_hash`) | NO |
| `src/models.rs` | 50-97 (`AuditEntry`), 95 (docstring discrepancy) | NO |
| `src/engine.rs` | 14-67 (`evaluate`) | NO |
| `src/segment.rs` | 91-106 (`segment_chain_preimage` — instrumentation precedent) | NO |
| `src/policy.rs` | 184-188, 242 (`policy_hash` from raw YAML bytes) | NO |
| `src/normalizer.rs` | 49 (`shadow_normalize`) | NO |
| `src/log_writer.rs` | 74, 80, 88 (`next_seq`, `current_head`, `append`) | NO |

## Exact commands executed

```
# Baseline capture — BEFORE any edit to src/chain.rs
cargo build --locked --lib                          exit 0
cargo run --locked --example d3_probe_baseline      exit 0
  -> H_BEFORE = 6eb514bf3ce334676d894e669e3d9598d594cc7e21c9bb694daad017f8c20222
  (probe deleted immediately after capture; not part of the diff)

# Independent non-Rust oracle — BEFORE instrumentation
printf '%s' "<predicted 315-byte preimage>" | sha256sum
  -> 6eb514bf3ce334676d894e669e3d9598d594cc7e21c9bb694daad017f8c20222   exit 0

# After instrumentation
cargo fmt --all -- --check                                          exit 0
cargo clippy --locked --all-targets --all-features -- -D warnings   exit 0
cargo test  --locked --all-targets                                  exit 0
cargo test  --locked --test d3_chain_observability                  exit 0   (5/5)
cargo run   --locked --example d3_chain_export                      exit 0
```

### stdout / stderr

`cargo run --example d3_chain_export` wrote the full output JSON to stdout and to
`D3_REAL_CHAIN_RUST_OUTPUT.json`; that file **is** the captured stdout payload.
stderr carried only cargo's `Compiling` / `Finished` / `Running` progress lines.
No warnings, no errors. The exporter returns a non-zero exit if either the hash
independence check or the before/after control fails; it exited 0.

## Output artifacts

| Artifact | SHA-256 |
|---|---|
| `D3_REAL_CHAIN_SEMANTIC_FIXTURE.json` | `185aa4a81ff571f0ae5e33aaf00f0fb7ea174b9d728b6dab789ab1a468afdae2` |
| `D3_REAL_CHAIN_RUST_OUTPUT.json` (local run) | `6920601a59068207f36aa58a54f3fd20929ed76b3b1ed0bce545aef1b496afdc` |
| `D3_REAL_CHAIN_CANONICAL.bin` | `6eb514bf3ce334676d894e669e3d9598d594cc7e21c9bb694daad017f8c20222` |

`D3_REAL_CHAIN_CANONICAL.bin` is the raw 315-byte preimage. Its own SHA-256 is
therefore identical to `rust_chain_hash` by construction — an inherent
self-consistency property of this artifact, not an independent check.

## Production integrity

```
$ git diff --stat
 .github/workflows/ci.yml | 33 +++++++++++++++++++++++++++++++++
 src/chain.rs             | 44 ++++++++++++++++++++++++++++++++++++++++----

$ git diff -- src/models.rs src/engine.rs src/crypto.rs
(no output — unchanged)
```

Forbidden files `src/models.rs`, `src/engine.rs`, `src/crypto.rs`: **UNCHANGED.**
No specification, ADR, or policy file was touched. No existing test was modified.
