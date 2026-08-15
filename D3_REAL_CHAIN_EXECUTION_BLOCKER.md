# D3_REAL_CHAIN_EXECUTION_BLOCKER

**STOP report — section 17 of the D-3 execution order.**

- Repository: `AuraIDToken/aura-guard-v1.3`
- Branch: `d3/real-chain-fixture-export`
- Base commit: `443f72e58483c3ea6112ea517647cc0dbf459960`
- Status: **STOPPED before Phase 3 (export mechanism).**

Stop conditions triggered: **STOP-6**, **STOP-3**, **STOP-2**, **STOP-8**, and
partially **STOP-7**.

No exporter was written. No CI was modified. No production file was modified.
No evidence artifact was produced, because no execution occurred — section 7
forbids fabricating values, so `D3_REAL_CHAIN_RUST_OUTPUT.json`,
`D3_REAL_CHAIN_CANONICAL.bin`, `D3_REAL_CHAIN_RUST_PROVENANCE.md` and
`D3_REAL_CHAIN_EXECUTION_REPORT.md` are deliberately absent.

---

## 1. WHAT WAS OBSERVED

**The real execution path was traced to source** and is documented in
`D3_REAL_CHAIN_EXECUTION_PLAN.md`. It does not match the path presumed by the
order. The actual orchestrator is `src/api/audit.rs::handle_audit`, which the
order does not name; `models.rs` is a pure DTO module and not a processing
stage. (Partial **STOP-7**.)

**The chain preimage is a 9-field `|`-joined string** built at `src/chain.rs:36-47`
and assigned to a function-local binding named `canonical`. `compute_chain_hash`
returns only `sha256_hex(&canonical)`. The preimage is discarded when the
function returns and is exposed by no API in the crate.

**`policy_hash` derives from raw YAML file bytes**, pre-parse:
`sha256_bytes_hex(std::fs::read(<name>.yaml))` at `src/policy.rs:184-188`.

**Three of the nine hashed fields are runtime-generated** — `timestamp`, `seq`,
`prev_hash` — from `Utc::now()` and live log-writer state, not from any request
payload.

**`violations`, `schema`, `audit_id` and `request_id` do not participate** in the
digest.

**The segment layer already exposes its preimage publicly.**
`SegmentManifest::segment_chain_preimage` (`src/segment.rs:91-106`) returns the
segment-level canonical `String`. The entry layer has no equivalent accessor.

**A normative documentation divergence exists inside production source.**
`src/models.rs:95` documents a 7-field preimage omitting `policy_hash` and
`context`; `src/chain.rs` documents and implements the 9-field form. Left
uncorrected, per section 1.

**The fixture does not exist.** `D3_REAL_CHAIN_SEMANTIC_FIXTURE.json` was not
found in the working tree, in any of the 30+ remote branches, in the complete git
object history, in `aura-poc-a-core-v3.3`, in `aura-specification`, anywhere on
the container filesystem, or in GitHub global code search. No working materials
accompanied the order.

**The toolchain is present and functional** — `cargo 1.94.1`, `rustc 1.94.1`;
CI pins `1.86.0`. The blocker is semantic, not environmental.

---

## 2. WHAT REMAINS UNKNOWN

- The byte content and SHA-256 of the authoritative `D3_REAL_CHAIN_SEMANTIC_FIXTURE.json`.
- Which fields that fixture pins — decisively, whether it supplies `timestamp`,
  `seq` and `prev_hash`, which production generates at runtime.
- The Rust `rust_canonical_string` and `rust_canonical_bytes_hex` for the fixture.
  These cannot be observed through any existing interface.
- The Rust `rust_chain_hash` for the fixture.
- Whether Rust and Python agree — at byte level or digest level. **No comparison
  was performed and none is implied.**
- Whether any Python reference implementation was written against the `chain.rs`
  9-field form or the `models.rs` 7-field form.

---

## 3. WHY EXECUTION CANNOT CONTINUE

**Primary — STOP-6, raw canonical bytes are not exportable.**
Section 0 and section 8 make the raw canonical byte stream mandatory and state
that the digest alone is insufficient. The preimage is a discarded local
binding. The only three routes to it are each forbidden:

1. Modifying `chain.rs` to return it — barred by section 1, triggers **STOP-1**,
   and fails the section 10 integrity check.
2. Re-implementing the `join("|")` in the exporter — barred by section 6, which
   forbids a second implementation of canonicalization; triggers **STOP-3**.
3. Inverting SHA-256 — cryptographically infeasible.

A compliant exporter therefore cannot be constructed. This blocker is
independent of the fixture and would persist even if the fixture were supplied.

**Secondary — STOP-2, fixture identity is indeterminate.**
Section 5 requires the exact fixture, used verbatim, with its SHA-256 recorded as
immutable identity. Zero authoritative copies exist. Authoring one would mean
deciding which fields the experiment pins — a semantic decision barred by
section 1.

**Tertiary — STOP-8, competing architectural interpretations.**
Because `timestamp`, `seq` and `prev_hash` are runtime-generated, any
fixture-driven run must bypass `handle_audit` and call `compute_chain_hash`
directly. Whether that still counts as "the real chain implementation" is exactly
the kind of choice section 17 reserves to architectural authority.

---

## 4. WHAT REQUIRES ARCHITECTURAL AUTHORITY

Four decisions, none of which an executor may take:

**D-3.1 — Exposure of the entry-level canonical preimage.**
Should `chain.rs` gain a public accessor returning the preimage `String`,
mirroring the existing `SegmentManifest::segment_chain_preimage`, with
`compute_chain_hash` refactored to consume it? This is the single change that
unblocks forensic byte-level export. It touches `chain.rs` and so is barred to
the executor. Note it is preimage-preserving: it changes no digest.

**D-3.2 — Authoritative fixture.**
The Protocol Custodian must supply `D3_REAL_CHAIN_SEMANTIC_FIXTURE.json` as a
committed, hash-pinned artifact, and state which of `timestamp`, `seq` and
`prev_hash` it pins.

**D-3.3 — Definition of "real chain execution".**
Does D-3 mean the full HTTP `handle_audit` path, or direct invocation of
`chain::compute_chain_hash` with fixture-supplied values? These are different
experiments with different evidentiary weight. The former cannot be made
deterministic without injecting a clock and log state.

**D-3.4 — Resolution of the `models.rs` / `chain.rs` documentation divergence.**
Which is normative: the 7-field docstring at `models.rs:95` or the 9-field
implementation in `chain.rs`? This must be settled **before** any Rust/Python
comparison, since an independent implementation written against the `models.rs`
docstring would necessarily diverge — and that divergence would be
misattributed to a cross-language determinism problem rather than to its actual
cause.

---

## 5. EVIDENCE CLASSIFICATION

**NOT EXECUTED — EVIDENCE GAP REMAINS OPEN.**

This document is **not** evidence of chain behaviour. It is a reconnaissance
record and a blocker report.

Explicitly **not** claimed: PROOF, GUARANTEE, CANONICAL FORMAT ESTABLISHED,
SPECIFICATION VALIDATED, C4 CLOSED, EXECUTED AND OBSERVED, BYTE-LEVEL EQUALITY,
DIVERGENCE OBSERVED.

C4 status: **EVIDENCE GAP** (unchanged).
