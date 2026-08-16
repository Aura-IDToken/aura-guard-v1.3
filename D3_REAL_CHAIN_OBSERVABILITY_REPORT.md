# D3_REAL_CHAIN_OBSERVABILITY_REPORT

**Status: SUCCESS — real Rust execution achieved, hash semantics unchanged.**

- Repository: `AuraIDToken/aura-guard-v1.3`
- Base commit: `443f72e58483c3ea6112ea517647cc0dbf459960` (`main`, verified — PR #54 is **not** merged)
- Branch: `d3/real-chain-observability`
- Fixture SHA-256: `185aa4a81ff571f0ae5e33aaf00f0fb7ea174b9d728b6dab789ab1a468afdae2`

---

## 1. Source trace (section 6)

All citations are against `main@443f72e`, before instrumentation.

| # | Question | Answer | Source |
|---|---|---|---|
| A | What function receives the audit input? | `api::audit::handle_audit` | `src/api/audit.rs:41` |
| B | What fields reach `compute_chain_hash`? | `prev_hash`, `decision`, `policy.name`, `policy.policy_hash`, `req.context`, `input_hash`, `shadow_hash`, `seq`, `timestamp` — nine explicit arguments | `src/api/audit.rs:119-129` |
| C | What fields participate in the preimage? | All nine, and only those nine. `violations`, `schema`, `audit_id`, `request_id` do **not** | `src/chain.rs:36-47` |
| D | Concatenation order? | `prev_hash, decision, policy_set, policy_hash, context, input_hash, shadow_hash, seq, timestamp` | `src/chain.rs:37-45` |
| E | Separator? | `const SEP: &str = "|"` — a single U+007C, joined between adjacent fields, no leading or trailing separator | `src/chain.rs:20`, `src/chain.rs:47` |
| F | Values transformed before concatenation? | Only `seq`: `u64::to_string()` → decimal ASCII, no padding. The other eight are used verbatim as `&str` | `src/chain.rs:44` |
| G | Text or bytes? | Text. The preimage is a Rust `String` built by `[&str; 9]::join` | `src/chain.rs:36-47` |
| H | Encoding before SHA-256? | UTF-8, via `str::as_bytes()`. No BOM, no length prefix, no padding, no normalization | `src/crypto.rs:10` |
| I | Does `crypto.rs` hash the UTF-8 bytes directly? | Yes — `hasher.update(input.as_bytes())` on a single `Sha256` instance, then `hex::encode` | `src/crypto.rs:8-12` |
| J | Value returned to caller? | Lowercase hex SHA-256, 64 chars | `src/crypto.rs:11` |

### Determinism finding (resolves the section 20.4 stop condition)

`compute_chain_hash` takes all nine preimage fields as **explicit parameters**
and reads no ambient state — no clock, no log handle, no globals
(`src/chain.rs:25-49`). The live-state problem is confined to its *caller*
`handle_audit`, which sources `timestamp` from `Utc::now()`, `seq` from
`state.log.next_seq()` and `prev_hash` from `state.log.current_head()`
(`src/api/audit.rs:116-118`).

`chain::compute_chain_hash` is therefore **already a deterministic injection
boundary** in the existing public API. No production change was needed to make
the fixture deterministic, and none was made.

---

## 2. models.rs / chain.rs discrepancy (section 7) — INDEPENDENTLY VERIFIED, NOT RESOLVED

**Confirmed.**

| | Fields | Source |
|---|---|---|
| Documented in `models.rs` | **7** — `prev_hash, decision, policy_set, input_hash, shadow_hash, seq, timestamp` | `src/models.rs:95` |
| Documented in `chain.rs` | **9** — adds `policy_hash`, `context` | `src/chain.rs:6-8` |
| **Implemented** in `chain.rs` | **9** — matches the `chain.rs` docstring | `src/chain.rs:36-47` |

The `models.rs:95` docstring omits `policy_hash` (position 4) and `context`
(position 5). The executed implementation uses nine fields; this run
independently confirms it, since the exported preimage contains both
`5e9ab2b2…` (policy_hash) and `Finance Bot` (context).

Classification: **SOURCE / DOCUMENTATION DISCREPANCY.**

Not resolved. `models.rs` not edited. Referred to architectural authority.

**Consequence for D-3:** any independent implementation written against the
`models.rs` docstring would build a 7-field preimage and necessarily produce a
different digest. If a Python/Rust divergence is later observed, this docstring
is a candidate root cause and must be excluded before the divergence is
attributed to cross-language determinism.

---

## 3. Instrumentation (sections 3, 5, 14)

Single change to `src/chain.rs`: the inline preimage construction was extracted
verbatim into a public `chain_preimage()` accessor, and `compute_chain_hash`
now calls it. The array literal, its element order, `SEP`, the `.join()` and
the `sha256_hex()` call are byte-for-byte unchanged.

This mirrors the accessor that already exists one layer up,
`SegmentManifest::segment_chain_preimage` (`src/segment.rs:91-106`), making the
entry layer observable in the same way the segment layer already was.

Not done: no field added or removed, no reordering, no separator change, no
normalization, no encoding change, no hash change, no change to models,
engine, crypto or API semantics.

### Before / after control

| | `chain_hash` |
|---|---|
| Before instrumentation (`main@443f72e`, uninstrumented) | `6eb514bf3ce334676d894e669e3d9598d594cc7e21c9bb694daad017f8c20222` |
| After instrumentation | `6eb514bf3ce334676d894e669e3d9598d594cc7e21c9bb694daad017f8c20222` |
| Result | **IDENTICAL** |

The "before" value was captured by executing the unmodified baseline **prior to
editing `chain.rs`**, and is pinned as a constant in
`tests/d3_chain_observability.rs` so `cargo test` fails if the digest ever moves.

---

## 4. Rust output (section 10)

```
rust_canonical_string:
b93b4ade8c758fa0086b464ac445fe6109681da57a99760eeb7f7bce3623562d|DENY|finance-v1|5e9ab2b25e6a748aeff8610b341f1ec9ba4b281df9e22304b1066fadf082b35d|Finance Bot|c2e552214097f038caddfa8cd86daca6eb0197a1feeab0234dda34ba3dd1413a|534b346b8ffd5ce800097347fce1fcfe4d0d3dc6ad20c04b3213fec3455c12a6|0|2026-01-01T00:00:00+00:00

rust_canonical_bytes_length: 315

rust_chain_hash:
6eb514bf3ce334676d894e669e3d9598d594cc7e21c9bb694daad017f8c20222
```

Full `rust_canonical_bytes_hex` (630 hex chars) is in
`D3_REAL_CHAIN_RUST_OUTPUT.json`; the raw stream is in
`D3_REAL_CHAIN_CANONICAL.bin`.

---

## 5. Hash independence check (section 11)

Two independent confirmations that the exported bytes are the bytes actually hashed:

1. **In-process, different entry point.** The exported byte slice was re-hashed
   through `crypto::sha256_bytes_hex(&[u8])` — a different function from the
   `sha256_hex(&str)` used by `compute_chain_hash` — giving
   `6eb514bf3ce334676d894e669e3d9598d594cc7e21c9bb694daad017f8c20222`. **MATCH.**

2. **Out-of-process, non-Rust.** GNU coreutils `sha256sum` over the same 315
   bytes gives `6eb514bf3ce334676d894e669e3d9598d594cc7e21c9bb694daad017f8c20222`.
   **MATCH.**

The second check was performed *before* `chain.rs` was instrumented, against a
preimage predicted from the source trace — so the exported preimage was
confirmed against an independent oracle rather than against itself.

`crypto.rs` implementation documented, not replaced: `Sha256::new()` →
`update(input.as_bytes())` → `finalize()` → `hex::encode` (`src/crypto.rs:8-12`),
RustCrypto `sha2` 0.10.

---

## 6. Cross-checks against real production derivations

Each pinned fixture value was re-derived by calling the existing production
function and compared:

| Fixture field | Production function | Result |
|---|---|---|
| `prev_hash` | `crypto::genesis_hash()` | **MATCH** |
| `policy_hash` | `crypto::sha256_bytes_hex(fs::read("policies/finance-v1.yaml"))` | **MATCH** |
| `input_hash` | `crypto::sha256_hex(original)` | **MATCH** |
| `shadow_hash` | `crypto::sha256_hex(normalizer::shadow_normalize(original))` | **MATCH** |

Observed shadow normalization: `Finance Bot Card 4111-1111-1111-1111 please ok`
→ `finance bot card 4111-1111-1111-1111 please ok`.

---

## 7. Scope limitation (declared, not worked around)

The fixture declares `original` as a **literal string**. The construction of
`original` from `context` / `prompt` / `response` is inlined at
`src/api/audit.rs:104-107` (`format!("{} {} {}", …)`) and is **not exposed as a
callable function**. Reconstructing it in the exporter would have been a second
implementation of a production step, which section 13 forbids.

That single join is therefore **outside** this experiment's evidence chain. The
experiment covers the chain preimage and digest — the stated objective of
section 1 — and everything it reports is produced by existing production code.

Exposing that join is a further observability question for architectural
authority; it was not undertaken here.

---

## 8. Verification results

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | **PASS** |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | **PASS** |
| `cargo test --locked --all-targets` | **PASS** — 178 lib + 5 new D-3 + all existing integration tests, 0 failed |
| `cargo test --test d3_chain_observability` | **PASS** — 5/5 |
| Existing tests modified | **NONE** |

---

## 9. Classification

**C4 = EXECUTED AND OBSERVED**, for the tested controlled semantic fixture only.

Not claimed: proof of universal cross-language determinism; any Python
comparison (none was performed in this run); any canonical-format selection;
any normative semantics.

The defensible statement supported by this run is:

> For fixture `185aa4a8…`, the existing aura-guard chain implementation
> constructs a 315-byte UTF-8 canonical preimage and derives
> `6eb514bf3ce334676d894e669e3d9598d594cc7e21c9bb694daad017f8c20222`, and
> exposing that preimage did not change the digest.

A Python/Rust byte comparison remains **NOT EXECUTED**.

---

## 9a. CI execution (section 12)

Executed on the existing GitHub Actions infrastructure — a new `d3-evidence`
job appended to `ci.yml`; no existing job was modified.

| | |
|---|---|
| workflow run | [31884628865](https://github.com/AuraIDToken/aura-guard-v1.3/actions/runs/31884628865) |
| job | `D-3 chain evidence export` (id 95012019247) — **success** |
| runner | `ubuntu-latest`, `RUNNER_OS=Linux`, `RUNNER_ARCH=X64` |
| rustc / cargo | `1.86.0 (05f9846f8 2025-03-31)` / `1.86.0 (adf9b6ad1 2025-02-28)` |
| regression control | 5 passed, 0 failed |
| artifact | `d3-real-chain-rust-output` (id 9246932001, 3226 bytes) |

CI-observed values are identical to the local run:

```
rust_canonical_bytes_length          315
rust_chain_hash                      6eb514bf3ce334676d894e669e3d9598d594cc7e21c9bb694daad017f8c20222
instrumentation_control.identical    true
hash_independence_check              true
all four cross-checks                true
```

The canonical bytes and digest matched across two environments and two rustc
versions (local 1.94.1, CI 1.86.0). That is an observation about these two
environments and this one fixture — not a determinism claim.

Note on `commit_sha` in the artifact: it reads
`3ae36f84f905b1a1c80be08eaac525e59542f252`, the ephemeral `refs/pull/55/merge`
commit GitHub synthesises for `pull_request` events, not the branch head
`70b9881`. Recorded verbatim as observed.

---

## 10. Local artifact hashes

| Artifact | SHA-256 |
|---|---|
| `D3_REAL_CHAIN_SEMANTIC_FIXTURE.json` | `185aa4a81ff571f0ae5e33aaf00f0fb7ea174b9d728b6dab789ab1a468afdae2` |
| `D3_REAL_CHAIN_RUST_OUTPUT.json` (local run) | `6920601a59068207f36aa58a54f3fd20929ed76b3b1ed0bce545aef1b496afdc` |
| `D3_REAL_CHAIN_CANONICAL.bin` | `6eb514bf3ce334676d894e669e3d9598d594cc7e21c9bb694daad017f8c20222` |

The committed `D3_REAL_CHAIN_RUST_OUTPUT.json` is from the **local** execution
(CI metadata fields read `unavailable`). The authoritative reproducible copy is
the `d3-real-chain-rust-output` CI artifact, which carries `workflow_run_id`,
`runner_os`, `runner_arch` and the pinned toolchain.
