# C2-1 Event Payload Input Boundary Contract

**Gate:** C2-1, following C1 = PASS and C2 = PROMOTION BLOCKED
**Repository:** `Aura-IDToken/aura-guard-v1.3`
**Verdict:** **C2-1 = PASS** — 17/17, exit code 0 (§J)
**Consequence:** input-boundary evidence is now sufficient for Custodian review of JCS production promotion.

> **SUPERSEDED IN PART — promotion has since been taken.** The Custodian authorized the minimal
> production promotion described in §K.2 and §L. The validator now lives in
> `aura_guard::event_payload`, the canonicalizer in `aura_guard::canonical`, and
> `serde_json_canonicalizer =0.3.2` has moved to `[dependencies]`. See
> **`C2-1-PRODUCTION-PROMOTION.md`** for the execution record. §K.1-K.2 below
> ("the validator is test-only") described the state *before* that promotion and are
> retained as the historical record. §K.3-K.6 remain open. DQ-003 remains OPEN.

| Gate | State |
|---|---|
| C1 — JCS capability | **VERIFIED** |
| C2 — input boundary | **CLOSED** in production by the promotion gate (`aura_guard::event_payload`) |
| Production JCS promotion | **DONE** — see `C2-1-PRODUCTION-PROMOTION.md` |
| ENT-007 | **NOT IMPLEMENTED** |
| DQ-003 | **OPEN** |

---

## A. Scope

C1 proved the canonicalizer is RFC 8785 conformant. C2 found the gap upstream of it: the untyped path materializes `serde_json::Value` before canonicalization, and duplicate member names are silently collapsed last-wins at every depth before `jcs.rs` is ever entered.

C2-1 formally defines the minimum input boundary required *before* canonicalization, and proves by execution that the boundary is satisfiable with the dependencies already present.

```text
RAW EVENT PAYLOAD (UTF-8 bytes)
        │
        ▼   EP-BOUNDARY-001  ← defined and proven here
   INPUT VALIDATION
        │
        ▼
  VALID JSON OBJECT
        │
        ▼   conformance/canonical/jcs.rs  ← unchanged, C1-verified
     RFC 8785 JCS
        │
        ▼
   canonical bytes
```

**C2-1 is explicitly not:** an ENT-007 implementation, a JCS rewrite, a dependency promotion, an RI-PY task, or DQ-003 closure. No hash domain is computed anywhere in this gate.

---

## B. Normative requirements — EP-BOUNDARY-001

**Input:** raw UTF-8 JSON bytes.

| # | Requirement | Normative status |
|---|---|---|
| 1 | Input MUST be valid UTF-8. | **Already normative** — RFC 8785 §3.2.4 / I-JSON (RFC 7493 §2.1) |
| 2 | Input MUST be valid JSON. | **Already normative** — RFC 8785 §3.1 |
| 3 | Duplicate object member names MUST be rejected. | **Already normative** — RFC 8785 §3.1 (I-JSON input stage); DQ-003 Golden Fixture, `verification_requirements`: *"Reject duplicate object member names."* |
| 4 | Duplicate detection MUST operate recursively: top-level object, nested objects, objects inside arrays, deeply nested objects. | **PROPOSED C2-1 requirement.** The recursion is implied by §3.1 applying to the whole document, but no existing Aura artifact states it explicitly. |
| 5 | The Event Payload top-level value MUST be a JSON object. | **Already normative** — DQ-003 Golden Fixture, `verification_requirements`: *"Require object as top-level Event Payload."* Note this is an *Aura* constraint, not an RFC 8785 one: RFC 8785 canonicalizes any JSON value. |
| 6 | Duplicate detection MUST occur BEFORE conversion into a representation that loses member multiplicity. | **PROPOSED C2-1 requirement.** This is the operative consequence of §3 and the specific defect C2 identified. |
| 7 | Only validated input may proceed to RFC 8785 JCS. | **PROPOSED C2-1 requirement** (pipeline ordering). |
| 8 | The canonicalizer remains responsible for canonicalization, not duplicate-key detection. | **Already normative** — RFC 8785 §3.1 places the constraint in the input-data stage. |
| 9 | No semantic normalization may silently convert invalid input into valid evidence. | **PROPOSED C2-1 requirement.** Directly motivated by the last-wins collapse, which is exactly such a silent conversion. |
| 10 | The boundary MUST be deterministic and testable. | **PROPOSED C2-1 requirement.** Discharged by §J. |

Nothing beyond these ten is asserted. No additional protocol requirement was invented, and no proposed requirement is presented as already normative.

---

## C. Input pipeline

### C.1 Actual ingestion mechanisms in the repository

Established by inspection, not from filenames.

| Stage | File / symbol | Type | Duplicate behavior |
|---|---|---|---|
| HTTP body → request | `src/api/audit.rs:44` `Json(req): Json<AuditRequest>` (axum 0.7 over `serde_json`) | `models::AuditRequest` (typed, `src/models.rs:8`) | **REJECTS** known-field duplicates at any depth |
| Log replay | `src/log_writer.rs:137`, `:162` | `models::AuditEntry` (typed) | **REJECTS** |
| Segment manifest | `src/segment.rs:275` | `segment::SegmentManifest` (typed) | **REJECTS** |
| Conformance path | `conformance/canonical/c1_full_domain_jcs.rs:22` | `serde_json::Value` (untyped) | **COLLAPSES** last-wins |
| Canonicalization | `conformance/canonical/jcs.rs:40` `canonical_bytes(&serde_json::Value)` → `serde_json_canonicalizer::to_vec` (`=0.3.2`, `[dev-dependencies]`) | — | cannot observe duplicates (correct per §3.1) |

`jcs.rs` appears in **no** production path. There is no `serde_json::Value` input deserialization anywhere in `src/`.

### C.2 The EP-BOUNDARY-001 pipeline

```text
&[u8]
  │  std::str::from_utf8                      → EpRejection::InvalidUtf8
  ▼
&str
  │  serde_json::from_str::<StrictJson>       → EpRejection::MalformedJson
  │    └─ Visitor::visit_map rejects the 2nd
  │       occurrence of a member name AS IT   → EpRejection::DuplicateMember(name)
  │       IS STREAMED, before the enclosing
  │       serde_json::Map is built
  │    └─ Visitor::visit_seq recurses through
  │       StrictJson, so array elements are
  │       validated identically
  ▼
serde_json::Value  (guaranteed duplicate-free at every depth)
  │  value.is_object()                        → EpRejection::NonObjectTopLevel
  ▼
validated Event Payload object
  │  jcs::canonical_bytes(&value)             ← UNCHANGED, C1-verified
  ▼
RFC 8785 canonical bytes
```

Reference implementation: `conformance/canonical/c2_1_event_payload_input.rs` — **test-only**, not reachable from `src/`.

---

## D. Duplicate-key semantics

### D.1 Why post-parse inspection is not a solution

`serde_json::Value` **cannot represent** a duplicate member name. Parsing `{"a":1,"a":2}` yields `{"a":2}` — a map of length 1, with no record that a collision occurred. Any validator that parses to `Value` and then inspects is inspecting evidence that has already been destroyed. C2 classified this **ABSENT**; C2-1 does not repeat the mistake.

### D.2 The mechanism

`StrictJson` implements `Deserialize` with a `Visitor` whose `visit_map` pulls member names off `MapAccess` in document order and returns an error the instant a name repeats. Values recurse through `StrictJson`, so nested objects and objects inside arrays get identical treatment. Detection therefore happens **during** the parse, not after it.

### D.3 Executable proof of ordering (not an assertion)

`c2_1_duplicate_is_reported_before_a_later_syntax_error` uses inputs carrying a duplicate **early** and a fatal syntax error **late**:

| Input | Plain `Value` path | EP-BOUNDARY-001 |
|---|---|---|
| `{"a":1,"a":2,` | `Err: EOF while parsing a value at line 1 column 13` | `Err: duplicate member name: a at line 1 column 10` |
| `{"a":1,"a":2,"b":@}` | `Err: expected value at line 1 column 18` | `Err: duplicate member name: a at line 1 column 10` |

A parse-then-inspect validator **cannot** report the duplicate for these inputs — it never obtains a `Value` to inspect. The boundary reports the duplicate at column 10, ahead of the syntax error at column 13/18. This is machine-checkable evidence of ordering.

`c2_1_detection_precedes_value_materialization` adds a second, independent argument: the boundary names the offending member (`"a"`), and that name is **not recoverable** from the collapsed `Value` (length 1, keys `["a"]`, no collision record). Information the collapsed value does not contain cannot have been derived by inspecting it.

### D.4 Observed behavior across the corpus

| Input | Plain `Value` | EP-BOUNDARY-001 |
|---|---|---|
| `{"a":1,"a":2}` | `{"a":2}` | `DuplicateMember("a")` |
| `{"outer":{"a":1,"a":2}}` | `{"outer":{"a":2}}` | `DuplicateMember("a")` |
| `[{"a":1,"a":2}]` | `[{"a":2}]` | `DuplicateMember("a")` |
| `{"arr":[{"a":1,"a":2}]}` | `{"arr":[{"a":2}]}` | `DuplicateMember("a")` |
| `{"a":1,"a":2,"a":3}` | `{"a":3}` | `DuplicateMember("a")` |
| `{"a":1,"a":"x"}` | `{"a":"x"}` | `DuplicateMember("a")` |
| `{"a":{"deep":1},"a":"scalar"}` | `{"a":"scalar"}` | `DuplicateMember("a")` |
| `{"w":{"x":{"y":{"z":1,"z":2}}}}` | `{"w":{"x":{"y":{"z":2}}}}` | `DuplicateMember("z")` |
| `{"arr":[0,{"n":{"d":1,"d":2}}]}` | `{"arr":[0,{"n":{"d":2}}]}` | `DuplicateMember("d")` |

### D.5 Why this matters for evidence

`event_payload_hash = SHA-256(JCS(event_payload))` binds the payload into `audit_record_hash` and thence into the chain. Under last-wins collapse, `{"action":"ALLOW","action":"DENY",…}` and `{"action":"DENY",…}` produce the **same** hash and the same audit record. A submitter could show one form to one verifier and the other to another, with identical valid-looking chain evidence. Rejecting duplicates is what makes the payload hash a faithful commitment to what was actually submitted.

---

## E. Top-level object requirement

RFC 8785 canonicalizes any JSON value, so `[1,2]` and `42` are legitimate JCS inputs — `canonical_bytes` accepts both today and is correct to do so. The object requirement is an **Aura** constraint from the DQ-003 Golden Fixture, and it lives in the input boundary, not in the serializer.

| Input | `canonical_bytes` alone | EP-BOUNDARY-001 |
|---|---|---|
| `{"a":1}` | `{"a":1}` | **ACCEPT** |
| `[1,2]` | `[1,2]` | **REJECT** — `NonObjectTopLevel` |
| `42` | `42` | **REJECT** — `NonObjectTopLevel` |
| `"text"` / `null` / `true` | canonicalized | **REJECT** — `NonObjectTopLevel` |

Ordering note: the check runs *after* the parse, so an input that is both a non-object and contains a duplicate (`[{"a":1,"a":2}]`) is reported as `DuplicateMember`. Both are rejections; only the reported category differs. This is deterministic and covered by `c2_1_f_duplicate_inside_array_element_is_rejected`.

---

## F. UTF-8 / malformed-input boundary

| Category | Trigger | Detection point |
|---|---|---|
| `InvalidUtf8` | raw bytes are not valid UTF-8 | `std::str::from_utf8` on the raw slice, before any JSON parsing |
| `MalformedJson` | valid UTF-8, not well-formed JSON | `serde_json` parser |
| `DuplicateMember(name)` | a member name repeats at any depth | streaming `visit_map`, before map construction |
| `NonObjectTopLevel` | top-level value is not an object | after parse, on the validated value |

Consistent with C1, the RFC 8785 invalid-value classes stay rejected at the input stage and **no canonical output is manufactured for them**: `NaN`, `Infinity`, `-Infinity`, lone low surrogate `\uDEAD`, lone high surrogate `\uD800`.

**Error codes are deliberately not frozen.** These four are C2-1 categories only. Machine-readable protocol error codes are recorded as **TBD — separate error-code contract** and are **not** written into APS-200 by this gate.

---

## G. Relationship to RFC 8785

```text
┌─────────── I-JSON / INPUT VALIDATION (RFC 8785 §3.1) ───────────┐
│ operates on RAW TEXT / BYTES                                     │
│ UTF-8 · well-formedness · DUPLICATE MEMBER REJECTION             │
│ + Aura: top-level-object requirement                             │
│ → EP-BOUNDARY-001                                                │
└───────────────────────────┬──────────────────────────────────────┘
                            │  duplicate-free JSON object
┌───────────────────────────▼──────────────────────────────────────┐
│ RFC 8785 CANONICALIZATION (§3.2)                                 │
│ property ordering (UTF-16 code units) · number serialization     │
│ string escaping · whitespace elimination · UTF-8 output          │
│ → conformance/canonical/jcs.rs  — UNCHANGED, C1-VERIFIED         │
└──────────────────────────────────────────────────────────────────┘
```

**`jcs.rs` was not modified and must not be.** Duplicate detection was deliberately kept out of `canonical_bytes`: RFC 8785 §3.1 assigns it to the input stage, and adding it to the serializer would be a silent redefinition of the RFC. C1's expected vectors are untouched and C1 remains green (§J).

---

## H. Relationship to ENT-007

*Documentation only. Nothing below is implemented.*

| ENT-007 element | Shape | Validation route | Status |
|---|---|---|---|
| `R_AR` (Audit Record preimage) | fixed 9-field | typed struct + `#[serde(deny_unknown_fields)]` — `serde_derive` already rejects duplicates (C2 §C.1) | route available, **not implemented** |
| `R_I` (Integrity preimage) | fixed 10-field | same | route available, **not implemented** |
| `event_payload` | **free-form** — cannot be typed | **requires EP-BOUNDARY-001** before `Value` materialization | boundary now proven, **not wired** |

Target architecture:

```text
RAW EVENT PAYLOAD → C2-1 INPUT VALIDATOR → JSON OBJECT → JCS → event_payload_hash → ENT-007 composition
```

No hash domain is implemented in this task. `event_payload_hash`, `audit_record_hash`, `integrity_hash`, and `previous_record_hash` remain **NOT IMPLEMENTED**, and no RI-RS adapter was created.

---

## I. Existing implementation capability

Classified before any code was written, to avoid adding a dependency that the repository does not need.

| Capability | Existing mechanism | Classification |
|---|---|---|
| Raw-byte / raw-text JSON parsing | `serde_json` (`[dependencies]`, 1.0.149) — streaming `Deserializer`, `Visitor`, `MapAccess` | **EXACT** |
| Duplicate-key detection, **typed** inputs | `serde_derive` → `Error::duplicate_field` | **PARTIAL** — only for declared fields of a typed struct; unusable for free-form payloads |
| Duplicate-key detection, **free-form** inputs | none | **ABSENT** |
| Recursive duplicate detection | none | **ABSENT** |
| Top-level object enforcement | none | **ABSENT** |
| RFC 8785 canonicalization | `conformance/canonical/jcs.rs` → `serde_json_canonicalizer =0.3.2` | **EXACT** (C1) |

**Consequence: no new dependency is required.** The ABSENT capabilities are compositions of `serde` + `serde_json` primitives the package already depends on. C2-1 adds **zero** dependencies; the only `Cargo.toml` change is registration of the new `[[test]]` target, following the C1 precedent. `serde_json_canonicalizer` remains in `[dev-dependencies]`.

---

## J. Executable evidence

### J.1 Execution metadata

| Item | Value |
|---|---|
| Command | `cargo test --test c2_1_event_payload_input` |
| Rust | `rustc 1.94.1 (e408947bf 2026-03-25)` |
| Cargo | `cargo 1.94.1 (29ea6fb6a 2026-03-24)` |
| Base commit | `0e71c7601ab04d205be685ec3d7dfba55eb5f468` (C2 review) |
| Timestamp (UTC) | `2026-08-22T21:24:55Z` |
| **Total / passed / failed / ignored** | **17 / 17 / 0 / 0** |
| **Exit code** | **0** |

```
running 17 tests
test c2_1_a_valid_object_is_accepted ... ok
test c2_1_b_top_level_array_is_rejected ... ok
test c2_1_c_top_level_scalar_is_rejected ... ok
test c2_1_d_duplicate_top_level_property_is_rejected ... ok
test c2_1_detection_precedes_value_materialization ... ok
test c2_1_duplicate_is_detected_at_arbitrary_depth ... ok
test c2_1_f_duplicate_inside_array_element_is_rejected ... ok
test c2_1_g_three_way_duplicate_is_rejected ... ok
test c2_1_duplicate_is_reported_before_a_later_syntax_error ... ok
test c2_1_e_duplicate_nested_property_is_rejected ... ok
test c2_1_h_type_changing_duplicate_is_rejected ... ok
test c2_1_i_valid_nested_object_is_accepted ... ok
test c2_1_invalid_utf8_is_rejected_as_its_own_category ... ok
test c2_1_j_valid_unicode_object_is_accepted ... ok
test c2_1_malformed_json_is_rejected ... ok
test c2_1_rfc8785_invalid_values_remain_rejected_at_the_input_stage ... ok
test c2_1_validated_payload_composes_with_unmodified_jcs ... ok

test result: ok. 17 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

### J.2 Mandatory pass criteria

| Criterion | Test | Result |
|---|---|---|
| A — valid object accepted | `c2_1_a_valid_object_is_accepted` | **PASS** |
| B — top-level array rejected | `c2_1_b_top_level_array_is_rejected` | **PASS** |
| C — top-level scalar rejected | `c2_1_c_top_level_scalar_is_rejected` | **PASS** |
| D — duplicate top-level rejected | `c2_1_d_duplicate_top_level_property_is_rejected` | **PASS** |
| E — duplicate nested rejected | `c2_1_e_duplicate_nested_property_is_rejected` | **PASS** |
| F — duplicate inside array rejected | `c2_1_f_duplicate_inside_array_element_is_rejected` | **PASS** |
| G — three-way duplicate rejected | `c2_1_g_three_way_duplicate_is_rejected` | **PASS** |
| H — type-changing duplicate rejected | `c2_1_h_type_changing_duplicate_is_rejected` | **PASS** |
| I — valid nested object accepted | `c2_1_i_valid_nested_object_is_accepted` | **PASS** |
| J — valid UTF-8 / Unicode object accepted | `c2_1_j_valid_unicode_object_is_accepted` | **PASS** |
| **Detection precedes information loss** | `c2_1_detection_precedes_value_materialization` + `c2_1_duplicate_is_reported_before_a_later_syntax_error` | **PASS** — proven by execution, not asserted in prose |

Beyond the mandatory set: arbitrary-depth recursion, the four error categories, the RFC 8785 invalid-value classes, and composition with the unmodified `jcs.rs`.

### J.3 Regression check — nothing else moved

| Suite | Result |
|---|---|
| `cargo test --test c1_full_domain_jcs` | 9 passed, 0 failed, 0 ignored, exit 0 — **C1 unweakened** |
| `cargo test --test canonical_001` | 5 passed, 0 failed, 0 ignored, exit 0 |
| `cargo clippy --test c2_1_event_payload_input` | clean, exit 0 (crate sets `clippy::all = deny`) |

---

## K. Remaining gaps

C2-1 proves the boundary is *specifiable and satisfiable*. It does **not** close it in production.

1. **The validator is test-only.** `conformance/canonical/c2_1_event_payload_input.rs` is not reachable from `src/`. **No production Event Payload ingest path exists**, because ENT-007 does not exist yet. Closing the boundary in production is a `src/` change and was not authorized by this gate (C2-1 §7: document, do not implement).
2. **Minimal production surface, when authorized:** one module exposing `fn validate_event_payload(&[u8]) -> Result<serde_json::Value, E>` with the semantics of §C.2, plus promotion of `jcs.rs` out of the conformance tree. Estimated surface: the ~90 lines of `StrictJson` + the validator, no new dependency.
3. **`R_AR` / `R_I` typed route is designed, not built.** §H names it; adding `#[serde(deny_unknown_fields)]` to those future structs is required and does not exist.
4. **Error codes are TBD.** The four categories in §F are deterministic but carry no machine-readable protocol code. Separate error-code contract; deliberately not frozen into APS-200.
5. **Production `AuditRequest` lacks `deny_unknown_fields`.** Out of C2-1 scope (unknown members are discarded and never enter a preimage), carried forward from C2 §D.
6. **Unicode member-name equivalence is not addressed.** Duplicate detection is exact byte/`String` equality on member names. Whether two names differing only by Unicode normalization form (e.g. NFC vs NFD) must be treated as duplicates is **not specified** by RFC 8785 §3.1 or by any Aura artifact, and C2-1 does not invent an answer. Flagged for the Custodian.

---

## L. Promotion consequence

```
C1 JCS capability          = VERIFIED
C2 input boundary          = NOT YET CLOSED  (evidence sufficient; production unimplemented)
Production JCS promotion   = BLOCKED until the Custodian acts on this document
```

**C2-1 = PASS. Input boundary evidence is sufficient for Custodian review of JCS production promotion.**

What C2-1 changed for the Custodian: C2 blocked promotion because the RFC 8785 §3.1 precondition was unenforceable through the promotion candidate's own API and no component anywhere satisfied it. That objection is now answered on the evidence axis — the boundary is specified (§B), its mechanism is proven to act before information loss (§D.3), and it needs **no new dependency** (§I). The remaining question is no longer *"can this be done?"* but *"is the Custodian authorizing the minimal `src/` surface in §K.2?"*

The next Custodian decision is a single authorization:

> Authorize the minimal production input-validation surface described in §K.2, promoting `serde_json_canonicalizer` to `[dependencies]` at the same time — or keep both in the conformance tree until C3.

Explicitly **not** done by C2-1 and **not** authorized by it:

- `serde_json_canonicalizer` — **NOT PROMOTED**, still `[dev-dependencies]`.
- `jcs.rs` — **unchanged**, still unreachable from `src/`.
- ENT-007, `audit_record_hash`, `integrity_hash`, `previous_record_hash` — **NOT IMPLEMENTED**.
- RI-RS adapter — **NOT CREATED**.
- `src/` — **untouched**.
- C1 corpus, expected vectors, Golden Fixture, APS-200, RI-PY, `main` — **untouched**.
- **DQ-003 = OPEN.** CROSS-LANGUAGE-002 **NOT STARTED**. C3 **NOT STARTED**.

---

## M. Final state check

| Invariant | Verified |
|---|---|
| `main` | UNTOUCHED |
| `src/` | UNTOUCHED (unchanged vs PR #60 head) |
| `conformance/canonical/jcs.rs` | UNTOUCHED (byte-identical to `main`) |
| C1 corpus `c1_full_domain_jcs.rs` | UNTOUCHED, still 9/9 green |
| DQ-003 Golden Fixture (`aura-specification`) | UNTOUCHED |
| APS-200 | UNTOUCHED |
| RI-PY (`aura-poc-a-core-v3.3`) | UNTOUCHED |
| Production dependency | NOT PROMOTED |
| ENT-007 | NOT IMPLEMENTED |
| DQ-003 | OPEN |

Files added/changed by C2-1: this document, `conformance/canonical/c2_1_event_payload_input.rs` (test-only), and a `[[test]]` registration in `Cargo.toml`. Nothing else.

### Branch discipline

| Item | Value |
|---|---|
| Requested target branch | `c1/full-domain-jcs` (PR #60) |
| Session-mandated branch | `claude/dq-003-conformance-audit-4ok63x` |
| Base SHA | `aebbbe04287993ea303366cf8c453bf721d250cc` (PR #60 head) |
| HEAD relationship | ahead of `origin/c1/full-domain-jcs`, behind by 0 |
| Fast-forward possible | **YES** — `git push origin claude/dq-003-conformance-audit-4ok63x:c1/full-domain-jcs` |

Reported, not force-resolved. No unrelated branch was merged.
