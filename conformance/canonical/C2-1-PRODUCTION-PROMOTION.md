# C2-1 Production Promotion

## Status

**PASS / PROMOTED**

The capability proven by C1 (RFC 8785 canonicalization) and C2-1 (raw Event Payload input boundary) is now reachable from the production library surface. Nothing beyond that capability was promoted.

This is **not** full protocol conformance. It is one gate: input boundary + canonicalizer, production-reachable, handed off clean to C3.

---

## Evidence

| Item | Result |
|---|---|
| C1 — full-domain RFC 8785 | **PASS** — 9/9, exit 0, re-executed against the **promoted** function (§Promoted surface) |
| C2-1 — Event Payload input boundary | **PASS** — 17/17, exit 0, re-executed against the **promoted** validator |
| CANONICAL-001 | 5/5, exit 0 |
| Production unit tests (`src/event_payload.rs`) | 17/17, exit 0 — new |
| **Full suite** — `cargo test` | **346 passed, 0 failed, 0 ignored, exit 0** across 19 targets |
| `cargo clippy --lib --all-features --profile test -- -D warnings` | **PASS**, 0 issues |
| `cargo clippy --test {c1_full_domain_jcs, c2_1_event_payload_input, canonical_001} -- -D warnings` | **PASS** |
| `cargo fmt --check` | no new diffs; byte-parity with the pre-promotion baseline (see *Known pre-existing conditions*) |
| `Cargo.lock` | **unchanged** — same pinned version, section move only |

Commands, in order:

```
cargo test --test c1_full_domain_jcs        ->  9 passed;  0 failed; 0 ignored; exit 0
cargo test --test c2_1_event_payload_input  -> 17 passed;  0 failed; 0 ignored; exit 0
cargo test --test canonical_001             ->  5 passed;  0 failed; 0 ignored; exit 0
cargo test --lib event_payload              -> 17 passed;  0 failed; 0 ignored; exit 0
cargo test                                  -> 346 passed; 0 failed; 0 ignored; exit 0
```

Environment: `rustc 1.94.1 (e408947bf 2026-03-25)`, `cargo 1.94.1 (29ea6fb6a 2026-03-24)`.
Base commit: `a3e9bea81390e827c9b97d7989cb94599ada1487` (C2-1). Executed `2026-08-22T21:38:47Z`.

### Why C1's result still counts

`conformance/canonical/jcs.rs` was reduced to a re-export of the promoted `aura_guard::canonical`. C1 and CANONICAL-001 call `jcs::canonical_bytes`, so after promotion they execute against the **shipped** function rather than a conformance-only copy. C1 re-ran unmodified and returned 9/9.

That was deliberate. Copying the function into `src/` and leaving the original in place would have left C1 verifying code the runtime never calls — the precise failure mode this gate sequence exists to prevent. The re-export makes C1's 9/9 evidence about production.

The same reasoning applies to C2-1: its corpus now calls `aura_guard::event_payload::validate_event_payload`. The test cases, inputs, and expected outcomes are unchanged; only the symbol under test moved from a test-local copy to the shipped one.

---

## Promoted surface

| File | Symbol | Visibility | Provenance |
|---|---|---|---|
| `src/canonical.rs` | `pub fn canonical_bytes(&serde_json::Value) -> Result<Vec<u8>, serde_json::Error>` | `pub` via `aura_guard::canonical` | mechanical extraction of `conformance/canonical/jcs.rs`; body, signature, and engine call unchanged |
| `src/event_payload.rs` | `pub fn validate_event_payload(&[u8]) -> Result<serde_json::Value, EventPayloadError>` | `pub` via `aura_guard::event_payload` | promotion of the C2-1 reference validator |
| `src/event_payload.rs` | `pub enum EventPayloadError` — `InvalidUtf8`, `MalformedJson(String)`, `DuplicateMember(String)`, `NonObjectTopLevel` | `pub` | new; `thiserror`, matching the existing `src/error.rs` idiom |
| `src/event_payload.rs` | `struct StrictJson` | **private** | the streaming duplicate-rejecting reader |
| `src/lib.rs` | `pub mod canonical;`, `pub mod event_payload;` | — | module registration, 2 lines |
| `conformance/canonical/jcs.rs` | `pub use aura_guard::canonical::canonical_bytes;` | — | re-export; implementation moved, semantics identical |

Total production code added: two modules, no changes to any existing production module.

### Deliberately NOT wired into the request path

`src/api/audit.rs` is untouched. `validate_event_payload` has **no caller inside the crate**: it is a reachable, compiled, linted, tested part of the shipped library, but the `/v1/audit` handler still deserializes `AuditRequest` exactly as before.

That is correct for this gate. `AuditRequest` is not an Event Payload, and no Event Payload endpoint exists because ENT-007 does not exist. Wiring a caller would be composition — a C3 decision, not a promotion.

---

## Dependency

```toml
[dependencies]
# RFC 8785 (JCS) canonical serialization.
# Promoted from [dev-dependencies] to production by the C2-1 promotion gate:
# `src/canonical.rs` calls it directly. Version pin is unchanged (=0.3.2, MIT).
serde_json_canonicalizer = "=0.3.2"
```

- **Why required:** `src/canonical.rs::canonical_bytes` calls `serde_json_canonicalizer::to_vec` directly. With `canonical.rs` in `src/`, the crate does not build unless the dependency is a production one. The promotion is load-bearing, not cosmetic.
- **Version:** unchanged. Exact pin `=0.3.2` carried over verbatim; no upgrade, no range widening.
- **Removed from `[dev-dependencies]`** so it is declared once.
- **No second canonicalization library** was introduced, and no other dependency was added. The input validator needs only `serde`, `serde_json`, and `thiserror` — all already production dependencies.
- **`Cargo.lock` unchanged**, confirming the resolved graph is identical.

---

## Input boundary

```text
raw Event Payload bytes  (&[u8])
   │
   │  std::str::from_utf8                     -> EventPayloadError::InvalidUtf8
   ▼
&str
   │  serde_json::from_str::<StrictJson>      -> EventPayloadError::MalformedJson
   │    Visitor::visit_map rejects the second
   │    occurrence of a member name AS IT IS  -> EventPayloadError::DuplicateMember
   │    STREAMED, before the enclosing map
   │    is built
   │    Visitor::visit_seq recurses through
   │    StrictJson, so array elements are
   │    validated identically
   ▼
serde_json::Value   (duplicate-free at every depth, by construction)
   │  value.is_object()                       -> EventPayloadError::NonObjectTopLevel
   ▼
validated Event Payload object
   │  aura_guard::canonical::canonical_bytes
   ▼
RFC 8785 canonical bytes
```

The pipeline terminates at canonical bytes. It is not extended beyond JCS: no hash is computed, no domain separator is applied, no record is composed.

---

## Duplicate handling

**Guarantee:** for any input accepted by `validate_event_payload`, no JSON object anywhere in the document — top level, nested, or inside an array element, at any depth — contains a repeated member name. Detection occurs during parsing and aborts it.

**Mechanism:** `serde_json::Value` cannot represent a duplicate member name; parsing `{"a":1,"a":2}` yields a map of length 1. Inspecting a materialized `Value` therefore cannot detect duplicates — the evidence is already gone. `StrictJson` hooks `MapAccess` and rejects the second occurrence as names are streamed off the parser.

**Ordering is proven, not asserted.** `duplicate_is_reported_before_a_later_syntax_error` uses inputs carrying a duplicate early and a fatal syntax error late:

| Input | Plain `Value` path | Promoted boundary |
|---|---|---|
| `{"a":1,"a":2,` | `Err: EOF while parsing a value at line 1 column 13` | `Err: DuplicateMember("a")` |
| `{"a":1,"a":2,"b":@}` | `Err: expected value at line 1 column 18` | `Err: DuplicateMember("a")` |

A parse-then-inspect validator **cannot** report the duplicate for these inputs — it never obtains a `Value` to inspect. This discriminator was retained verbatim from C2-1 and was not weakened.

Second, independent argument (`detection_precedes_value_materialization`): the boundary names the offending member `"a"`, and that name is unrecoverable from the collapsed `Value` (length 1, keys `["a"]`, no collision record). Information the collapsed value does not contain cannot have been derived by inspecting it.

**Observed, both in production unit tests and the C2-1 conformance corpus:**

| Input | Result |
|---|---|
| `{"a":1,"a":2}` | `DuplicateMember("a")` |
| `{"outer":{"a":1,"a":2}}` | `DuplicateMember("a")` |
| `[{"a":1,"a":2}]` / `{"arr":[{"a":1,"a":2}]}` | `DuplicateMember("a")` |
| `{"a":1,"a":2,"a":3}` | `DuplicateMember("a")` |
| `{"a":1,"a":"x"}` / `{"a":{"deep":1},"a":"scalar"}` | `DuplicateMember("a")` |
| `{"w":{"x":{"y":{"z":1,"z":2}}}}` | `DuplicateMember("z")` |
| `{"arr":[0,{"n":{"d":1,"d":2}}]}` | `DuplicateMember("d")` |

---

## Top-level object handling

**Guarantee:** an accepted Event Payload is always a JSON object.

RFC 8785 canonicalizes any JSON value, so `canonical_bytes` accepts `[1,2]` and `42` and is correct to do so. The object requirement is an Aura constraint on the Event Payload, enforced in the input boundary, never in the serializer.

| Input | `canonical_bytes` alone | `validate_event_payload` |
|---|---|---|
| `{"a":1}` | `{"a":1}` | **ACCEPT** |
| `[1,2]` | `[1,2]` | **REJECT** — `NonObjectTopLevel` |
| `42` / `"text"` / `null` / `true` | canonicalized | **REJECT** — `NonObjectTopLevel` |

Ordering note: the shape check runs after the parse, so an input that is both a non-object and contains a duplicate (`[{"a":1,"a":2}]`) reports `DuplicateMember`. Both are rejections; only the category differs. Deterministic, and covered by test `f`.

---

## Error semantics

`EventPayloadError` variants are Rust-level categories for callers to branch on. They are **not** APS-200 normative error codes.

```
ERROR-CODE TAXONOMY: TBD — separate contract
```

No new protocol error taxonomy was invented or frozen. `src/error.rs` and `AuraError` are untouched; the new enum is local to the new module, using the `thiserror` idiom already established in the crate.

---

## Explicit non-goals

None of the following was implemented, created, modified, or claimed:

| Item | State |
|---|---|
| ENT-007 | **NOT IMPLEMENTED** |
| `struct AuditRecord` | **NOT CREATED** — verified absent from `src/` |
| `audit_record_hash` | **NOT IMPLEMENTED** — verified absent from `src/` |
| `integrity_hash` | **NOT IMPLEMENTED** — verified absent from `src/` |
| `previous_record_hash` | **NOT IMPLEMENTED** — verified absent from `src/` |
| `event_payload_hash` | **NOT IMPLEMENTED** — verified absent from `src/` |
| `chain_hash` / `chain_preimage` / `verify_chain` | **UNCHANGED** — `src/chain.rs` untouched |
| Genesis semantics | **UNCHANGED** — `src/crypto.rs` untouched |
| Merkle domains `0x00` / `0x01` | **UNCHANGED** — `src/merkle.rs` untouched |
| `0x02` audit-record domain | **NOT USED, NOT IMPLEMENTED** |
| RI-RS conformance adapter | **NOT CREATED** |
| RI-PY / `aura-poc-a-core-v3.3` | **UNTOUCHED** — 0 changes |
| APS-200 | **UNTOUCHED** |
| DQ-003 Golden Fixture | **UNTOUCHED** — byte-for-byte unchanged, no hash regenerated |
| DQ-003 verdict | **OPEN** |
| C3 | **NOT STARTED** |
| CROSS-LANGUAGE-002 | **NOT STARTED** |
| Unicode normalization / NFC-NFD equivalence | **NOT INTRODUCED** — see below |
| `src/api/`, `src/models.rs`, `src/engine.rs`, `src/segment.rs`, `src/log_writer.rs`, `tests/` | **UNTOUCHED** |

**Permitted architectural statement, and the only one made here:** C2-1 provides the validated input boundary that a future ENT-007 / Event Payload implementation may consume.

**Not claimed:** that RI-RS is conformant, that the Audit Chain is conformant, or that ENT-007 is implemented. None of those is true.

---

## Known pre-existing conditions (not introduced, not fixed)

Two conditions predate this promotion. Both were confirmed identical on the pre-promotion baseline `aebbbe0` (PR #60 head) using a clean worktree, and neither was touched, because fixing unrelated code is out of scope.

1. **`cargo clippy --all-targets --all-features -- -D warnings` fails**, with 3 errors, all in `tests/ck003_dq002_ri_rs_conformance.rs` (two `expect()` on `Result`, one missing crate documentation). Identical on the baseline. The production library and all three conformance targets are clippy-clean.
2. **`cargo fmt --check` reports diffs** in `conformance/canonical/c1_full_domain_jcs.rs` and `tests/ck003_dq002_ri_rs_conformance.rs`. Identical file set on the baseline. This promotion introduced **zero** new formatting diffs; `c1_full_domain_jcs.rs` was deliberately left unformatted rather than modify the C1 corpus.

---

## Unresolved, carried forward

`C2-1-TBD-UNICODE-NORMALIZATION` — duplicate detection compares member names by exact string equality. Whether two names differing only by Unicode normalization form (NFC vs NFD) must be treated as duplicates is not specified by RFC 8785 §3.1 or by any Aura artifact. No normalization is performed and the question is **not** resolved here. Recorded in the `src/event_payload.rs` module documentation so it travels with the code.

Also carried forward from C2: `AuditRequest` still lacks `#[serde(deny_unknown_fields)]`. Out of scope — unknown members are discarded and never enter a preimage.

---

## Remaining gates

```
C1 PASS
  → C2 PASS
  → C2-1 PASS
  → MINIMAL PRODUCTION PROMOTION   ← THIS GATE, complete
  → C3
  → ENT-007 composition
  → audit_record_hash
  → integrity_hash
  → DQ-003 replay
  → RI-RS adapter
  → RI-PY remediation
  → cross-language conformance
```

**C3 hand-off.** C3 inherits two production surfaces and no obligations from this gate:

- `aura_guard::event_payload::validate_event_payload` — raw bytes to a duplicate-free JSON object, no caller yet.
- `aura_guard::canonical::canonical_bytes` — validated value to RFC 8785 bytes, C1-verified.

What C3 must add, and this gate deliberately did not: an ENT-007 Audit Record type, the `R_AR` / `R_I` field-exclusion rules, the `0x02` domain-separator composition, and the three hash entry points. **DQ-003 remains OPEN** and is unaffected by this promotion.

---

## Git integrity

| Item | Value |
|---|---|
| Current branch | `claude/dq-003-conformance-audit-4ok63x` (session-mandated) |
| Intended branch | `c1/full-domain-jcs` (PR #60) |
| Base SHA | `aebbbe04287993ea303366cf8c453bf721d250cc` (PR #60 head) |
| HEAD before this gate | `a3e9bea81390e827c9b97d7989cb94599ada1487` |
| Ahead / behind `origin/c1/full-domain-jcs` | ahead, behind 0 |
| Fast-forward possible | **YES** — `git push origin claude/dq-003-conformance-audit-4ok63x:c1/full-domain-jcs` |

Reported, not force-resolved. No unrelated branch was merged.

Files changed by this gate, and only these:

```
 Cargo.toml                                          (dependency section move + comment)
 src/lib.rs                                          (2 module registrations)
 src/canonical.rs                                    (new)
 src/event_payload.rs                                (new)
 conformance/canonical/jcs.rs                        (implementation -> re-export)
 conformance/canonical/c2_1_event_payload_input.rs   (repointed at the production validator)
 conformance/canonical/C2-1-PRODUCTION-PROMOTION.md  (new, this document)
```
