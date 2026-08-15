# D3_REAL_CHAIN_PROVENANCE

## Repository

| | |
|---|---|
| repository | `AuraIDToken/aura-guard-v1.3` |
| branch | `d3/real-chain-observability` |
| base_commit | `443f72e58483c3ea6112ea517647cc0dbf459960` (`main`) |
| base verified | Yes — `git fetch origin main` on execution day returned `443f72e`; PR #54 confirmed **not merged** (commit `6661982` present only on `origin/d3/real-chain-fixture-export`) |
| execution_commit | see `commit_sha` in the CI artifact `D3_REAL_CHAIN_RUST_OUTPUT.json` |
| workflow_run_id | see `workflow_run_id` in the CI artifact |

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
| runner | `ubuntu-latest` (GitHub Actions) |
| toolchain | `dtolnay/rust-toolchain@1.86.0` — the pin already used by every other job in `ci.yml` |
| recorded at runtime | `RUNNER_OS`, `RUNNER_ARCH`, `D3_RUST_VERSION`, `D3_CARGO_VERSION`, `GITHUB_SHA`, `GITHUB_RUN_ID` are captured into the output JSON by the `d3-evidence` job |

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
