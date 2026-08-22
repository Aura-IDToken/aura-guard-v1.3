# C2 — Input / I-JSON Boundary Review

**Gate:** C2, immediately following C1 PASS
**Repository:** `Aura-IDToken/aura-guard-v1.3`
**Base commit under review:** `aebbbe04287993ea303366cf8c453bf721d250cc` (PR #60 head, branch `c1/full-domain-jcs`)
**Mode:** READ-ONLY / ANALYSIS-FIRST — documentation only, no production code, no test added or changed
**Verdict:** **PROMOTION BLOCKED** (see §G — the block is on the input boundary, not on the canonicalizer)

---

## A. Scope

C1 asked: *is the existing canonicalizer RFC 8785 capable?* It executed and answered **PASS** — 9/9, exit code 0, engine unmodified.

C2 asks a different question: *is the input boundary feeding that canonicalizer sufficiently defined and safe for the future normative surface?* C2 determines exactly where JSON input validation ends and RFC 8785 canonicalization begins.

C2 does **not**:

- implement ENT-007, `audit_record_hash`, `integrity_hash`, or `previous_record_hash`;
- create an Audit Record adapter;
- modify `jcs.rs`, the C1 corpus, or any C1 expected value;
- promote `serde_json_canonicalizer` to `[dependencies]`;
- close DQ-003 or start CROSS-LANGUAGE-002.

Everything below is derived from the actual repository and from read-only execution against it. No behavior was inferred from a name.

### A.1 Execution discipline

| Check | Result |
|---|---|
| `git status --porcelain` before work | empty (clean) |
| Branch | `claude/dq-003-conformance-audit-4ok63x` (session-mandated; see §I) |
| HEAD before work | `d10228d674613493d8bff4ab99665b57ad29637c` |
| Rust / Cargo | `rustc 1.94.1`, `cargo 1.94.1` |
| `main` | untouched |
| `src/` | untouched |
| `conformance/canonical/jcs.rs` | untouched |
| C1 corpus (`c1_full_domain_jcs.rs`) | untouched |
| DQ-003 Golden Fixture (`aura-specification`) | untouched |
| RI-PY (`aura-poc-a-core-v3.3`) | untouched |
| Files changed by C2 | this document only |

Read-only re-runs during C2:

```
cargo test --test c1_full_domain_jcs   -> 9 passed; 0 failed; 0 ignored;  exit 0
cargo test --test integration          -> 9 passed; 0 failed; 0 ignored;  exit 0
```

All probe code used in §C/§D ran from a scratchpad crate outside the repository, calling only existing public types and the existing `jcs.rs` file. Nothing was committed to `src/`, `tests/`, or `conformance/`.

---

## B. Actual RI-RS pipeline

There are **two distinct pipelines** in this repository, and they have **different** duplicate-key behavior. Conflating them is the central risk this gate exists to prevent.

### B.1 Pipeline 1 — the production path (typed; JCS is NOT in it)

```text
HTTP request body (bytes)
   │
   ▼  axum::extract::Json<AuditRequest>          src/api/audit.rs:44
      (axum 0.7 → serde_json over the body bytes)
   │
   ▼  serde_derive Deserialize for a TYPED struct
      models::AuditRequest { context: String,     src/models.rs:8
                             policy_set: Option<String>,
                             payload: Payload { prompt: String, response: String } }
   │
   ▼  engine::evaluate(...)                       src/engine.rs
      normalizer::shadow_normalize(...)           src/normalizer.rs
   │
   ▼  crypto::sha256_hex(...)                     src/crypto.rs:8
      chain::compute_chain_hash(...)              src/chain.rs:62
   │
   ▼  models::AuditEntry → JSONL log              src/log_writer.rs
```

**`conformance/canonical/jcs.rs` does not appear anywhere in this pipeline.** Confirmed: `grep -rn "serde_json::Value" src/` returns no untyped-`Value` deserialization in the request path (the only `Value` uses are in `src/bin/aura_seal.rs` and `src/bin/aura_sign_policy.rs`, both CLI output construction, not input parsing).

Other typed JSON entry points, same shape:

| Entry point | File | Target type |
|---|---|---|
| Log replay / recovery | `src/log_writer.rs:137`, `:162` | `models::AuditEntry` |
| Segment manifest load | `src/segment.rs:275` | `segment::SegmentManifest` |

### B.2 Pipeline 2 — the conformance path (untyped; this is the one JCS is in)

```text
raw JSON text (test literal)
   │
   ▼  serde_json::from_str::<serde_json::Value>   conformance/canonical/c1_full_domain_jcs.rs:22
   │
   ▼  serde_json::Value                           (Map = BTreeMap; no `preserve_order` feature)
   │
   ▼  jcs::canonical_bytes(&Value)                conformance/canonical/jcs.rs:40
      → serde_json_canonicalizer::to_vec(value)   (=0.3.2, [dev-dependencies])
   │
   ▼  Vec<u8> RFC 8785 canonical bytes
```

Exact signature of the surface under consideration for promotion:

```rust
pub fn canonical_bytes(value: &serde_json::Value) -> Result<Vec<u8>, serde_json::Error>
```

### B.3 The structural observation

The API accepts `&serde_json::Value`. A caller therefore **must** materialize a `Value` before calling it. Duplicate object member names do not survive that materialization. **The promotion candidate's own signature forecloses the RFC 8785 §3.1 precondition for any caller that starts from raw JSON text.**

Note for the record: the underlying engine `serde_json_canonicalizer::to_vec` is generic over `T: Serialize`; the narrowing to `&Value` is `jcs.rs`'s own choice, not the engine's. C2 records this and does not change it.

---

## C. Duplicate-key behavior — exact observed results

Probe input `{"a":1,"a":2}` and variants, executed against the repository's own types and `jcs.rs`.

### C.1 Typed path (Pipeline 1) — duplicates ARE rejected

`serde_derive`'s generated visitor calls `Error::duplicate_field` when a known field is seen twice. Observed:

| Input | Result |
|---|---|
| `{"context":"a","payload":{...}}` (baseline) | `Ok` |
| `{"context":"a","context":"b","payload":{...}}` | **`Err: duplicate field \`context\` at line 1 column 24`** |
| `{"context":"a","payload":{"prompt":"p1","prompt":"p2","response":"r"}}` (nested) | **`Err: duplicate field \`prompt\` at line 1 column 48`** |
| `{"context":"a","policy_set":"x","policy_set":"y","payload":{...}}` (optional field) | **`Err: duplicate field \`policy_set\` at line 1 column 44`** |
| `{"context":"a","zz":1,"zz":2,"payload":{...}}` (duplicate **unknown** field) | `Ok` — accepted, both values discarded |
| `AuditEntry` with `"seq":0,"seq":1` | **`Err: duplicate field \`seq\` at line 1 column 45`** |

**Finding C.1:** the production HTTP path and the log-replay path already satisfy the I-JSON duplicate precondition for every field they actually carry, at every nesting depth, without any additional component. `AuditRequest` does not declare `#[serde(deny_unknown_fields)]`, so duplicated *unknown* members are tolerated — but unknown members are discarded during deserialization and can never reach a hash or a canonicalizer, so this is a strictness gap, not an integrity gap.

### C.2 Untyped path (Pipeline 2) — duplicates are silently collapsed

| Input | `Value` after parse | `jcs::canonical_bytes` output |
|---|---|---|
| `{"a":1,"a":2}` | `{"a":2}` | `{"a":2}` |
| `{"o":{"x":1,"x":2}}` (nested) | `{"o":{"x":2}}` | `{"o":{"x":2}}` |
| `{"arr":[{"k":1,"k":2}]}` (inside an array element) | `{"arr":[{"k":2}]}` | `{"arr":[{"k":2}]}` |
| `{"a":1,"a":2,"a":3}` (three-way) | `{"a":3}` | `{"a":3}` |
| `{"a":{"deep":1},"a":"scalar"}` (type-changing) | `{"a":"scalar"}` | `{"a":"scalar"}` |

Last-wins, at every depth, silently, with no diagnostic.

### C.3 Answers to the seven required questions

**A. Can the current parser observe duplicate keys?**
Split answer. `serde_derive` (typed) — **YES**, and it rejects them. `serde_json::from_str::<Value>` (untyped) — **NO**; it applies last-wins.

**B. Does parsing produce `serde_json::Value`?**
Only on the conformance path. The production path produces typed structs and never materializes a `Value`.

**C. If duplicates exist, are they rejected?**
Typed path: yes, with `duplicate field \`x\``. Untyped path: no.

**D. If not rejected, does last-wins behavior occur?**
Yes — confirmed at top level, nested-object, in-array, three-way, and type-changing (§C.2).

**E. At what exact layer is the information lost?**
Inside `serde_json`'s `Value` deserializer, during map construction — `Map::insert` overwrites an existing key. Proof: parsing `{"a":1,"a":2}` yields a map of **length 1** with `keys = ["a"]`. The loss occurs strictly **before** `jcs.rs` is entered.

**F. Is that behavior compatible with the defined I-JSON input boundary?**
For the typed production paths — **yes**, the precondition is met by construction. For the untyped path that `jcs.rs` requires — **no**. RFC 8785 §3.1 places duplicate rejection in the I-JSON input-validation step, and **no component in this repository performs that step for untyped JSON.**

**G. Is the current JCS function itself capable of detecting duplicates?**
**No, and it cannot be made to without changing its signature.** `canonical_bytes` receives a `&Value` whose map keys are unique by construction; it never sees raw JSON text. Per RFC 8785 §3.1 this is *correct* — duplicate rejection is not the serializer's job. The absence is therefore **not** a canonicalization defect, and C1 PASS is not weakened by it.

---

## D. Invalid-input boundaries

Legend: **EXACT** = required behavior present and correct · **PARTIAL** = present but incomplete · **ABSENT** = required capability missing · **N/A** = not this layer's responsibility.

| Input | Parser (observed) | Validation | JCS | Status |
|---|---|---|---|---|
| `NaN` | `Err: expected value at line 1 column 6` | rejected at parse; not a JSON value | never reached | **EXACT** — no canonical output manufactured |
| `Infinity` | `Err: expected value at line 1 column 6` | rejected at parse | never reached | **EXACT** |
| `-Infinity` | `Err: invalid number at line 1 column 7` | rejected at parse | never reached | **EXACT** |
| Lone **low** surrogate `\uDEAD` | `Err: lone leading surrogate in hex escape` | rejected at parse | never reached | **EXACT** |
| Lone **high** surrogate `\uD800` | `Err: unexpected end of hex escape` | rejected at parse | never reached | **EXACT** (beyond C1 corpus; observed in C2) |
| Unpaired high + valid char `\uD800A` | `Err: unexpected end of hex escape` | rejected at parse | never reached | **EXACT** (beyond C1 corpus) |
| Valid surrogate **pair** `😀` | `Ok` | accepted, correctly | emits literal UTF-8 | **EXACT** — control case, proves the rejections above are not blanket |
| Invalid UTF-8 byte `0xFF` in a **known** field | `Err: invalid unicode code point at line 1 column 14` (both typed and `Value`) | rejected at parse | never reached | **EXACT** |
| Invalid UTF-8 byte `0xFF` in an **unknown** field | typed path: `Ok` — the member is skipped without UTF-8 validation and discarded | not validated | never reached | **PARTIAL** — undetected, but unreachable by any hash; see §D.1 |
| Malformed JSON (trailing comma) | `Err: trailing comma at line 1 column 8` | rejected at parse | never reached | **EXACT** |
| Missing required field | `Err: missing field \`payload\`` | rejected at parse | never reached | **EXACT** (typed path only) |
| **Duplicate properties — typed path** | `Err: duplicate field \`x\`` | rejected at parse | never reached | **EXACT** |
| **Duplicate properties — untyped path** | `Ok`, last-wins | **no validation exists** | canonicalizes the collapsed object | **ABSENT** |
| Duplicate **unknown** members (typed path) | `Ok`, discarded | not validated | never reached | **PARTIAL** — no `deny_unknown_fields` |
| Top-level **non-object** (`[1,2]`, `42`) | `Ok` | **not constrained** | `canonical_bytes` returns `[1,2]` / `42` | **ABSENT** for ENT-007; **N/A** for RFC 8785, which canonicalizes any JSON value |
| Duplicate detection inside `jcs.rs` | — | — | structurally impossible (`&Value`) | **N/A** — correctly not the serializer's responsibility (RFC 8785 §3.1) |

### D.1 Note on the invalid-UTF-8 asymmetry

Invalid UTF-8 inside a **known** field is rejected identically by both the typed and untyped parsers. Inside an **unknown** field on the typed path, `serde` skips the member without UTF-8-validating it and deserialization succeeds — observed as `Ok` with the surviving known fields intact. Because unknown members are discarded and never enter a preimage, this cannot corrupt evidence today. It is recorded as a strictness observation, not a defect, and it would become relevant only if a future surface ever forwarded unknown members.

---

## E. Responsibility boundary

```text
┌──────────────────────── I-JSON / INPUT VALIDATION ────────────────────────┐
│  Operates on RAW JSON TEXT / BYTES.                                        │
│  Owns:  well-formedness · UTF-8 validity · surrogate pairing               │
│         non-finite rejection · DUPLICATE MEMBER NAME REJECTION (§3.1)      │
│         structural preconditions (e.g. "top-level MUST be an object")      │
│                                                                            │
│  Present today:  serde_json parser        — well-formedness, UTF-8,        │
│                                             surrogates, non-finite  EXACT  │
│                  serde_derive typed impls — duplicate rejection     EXACT  │
│                                             (typed inputs only)            │
│  Missing today:  duplicate rejection for UNTYPED JSON              ABSENT  │
│                  top-level-object enforcement                      ABSENT  │
└────────────────────────────────────┬───────────────────────────────────────┘
                                     │  serde_json::Value
                                     │  (duplicates already gone — last-wins)
┌────────────────────────────────────▼───────────────────────────────────────┐
│                     RFC 8785 CANONICALIZATION                              │
│  Operates on an ALREADY-VALIDATED JSON VALUE.                              │
│  Owns:  property ordering (UTF-16 code units) · number serialization       │
│         string escaping · whitespace elimination · UTF-8 output            │
│                                                                            │
│  conformance/canonical/jcs.rs → serde_json_canonicalizer =0.3.2            │
│  Status:  VERIFIED BY C1 — 9/9, exit 0                                     │
│  Does NOT own duplicate rejection, and correctly so (RFC 8785 §3.1).       │
└────────────────────────────────────────────────────────────────────────────┘
```

The boundary is **well-defined**. The canonicalizer is on the correct side of it and is conformant. The defect is that on the untyped side of the boundary, the input-validation box is **empty** for two of the checks it owns.

---

## F. ENT-007 implications

*Implications only. Nothing below is implemented, and no gap below is solved here.*

**Can a future ENT-007 surface safely rely on the current upstream parser? — Split answer, and the split is the whole point of this gate.**

### F.1 The Audit Record and Integrity objects — YES, with a stated contract

`R_AR` and `R_I` are fixed-shape structures (`object_id`, `object_type`, `protocol_version`, `schema_version`, `created_at`, `event_type`, `sequence_number`, `previous_record_hash`, `event_payload_hash`, and for `R_I` also `audit_record_hash`). A future ENT-007 surface can deserialize them into a **typed Rust struct**, exactly as `AuditRequest` and `AuditEntry` already do. On that path, §C.1 shows the I-JSON duplicate precondition is satisfied by `serde_derive` at no cost.

**Contract boundary, if this path is taken:** *ENT-007 record ingestion MUST deserialize into a typed struct with `#[serde(deny_unknown_fields)]`, and MUST NOT route the record through `serde_json::Value`.* Adding `deny_unknown_fields` also closes the unknown-member strictness gaps in §D.

### F.2 The Event Payload — NO

The DQ-003 Golden Fixture defines `event_payload` as an arbitrary JSON object (`{"action":…,"resource":…,"subject":…}` in the fixture, but not schema-constrained). Arbitrary JSON cannot be represented by a typed struct, so this path must go through `serde_json::Value` — the exact path where §C.2 shows duplicates collapse silently.

This is not hypothetical. The Golden Fixture's own `verification_requirements` state:

> - *"Reject duplicate object member names."*
> - *"Require object as top-level Event Payload."*

**Neither capability exists anywhere in RI-RS.** §D classifies both **ABSENT**. `canonical_bytes` accepts a top-level array or scalar without complaint, and duplicate members are gone before it is called.

### F.3 The exact missing validation capability

> A JSON ingest step that operates on **raw text or bytes**, before `serde_json::Value` materialization, and that (a) errors on duplicate object member names at any depth, and (b) enforces a top-level-object requirement for the Event Payload.

Everything else the I-JSON boundary owns — well-formedness, UTF-8 validity, surrogate pairing, non-finite rejection — is already **EXACT** (§D). This is a narrow, single, well-identified gap. Per C2's mandate it is documented, not solved.

### F.4 Why this matters for evidence integrity

`event_payload_hash = SHA-256(JCS(event_payload))` binds the payload into `audit_record_hash` and thence into the chain. If two semantically different submissions — `{"action":"ALLOW","action":"DENY", …}` and `{"action":"DENY", …}` — collapse to the same `Value`, they produce the **same** `event_payload_hash` and the same audit record. A submitter could present the first form to one verifier and the second to another with identical, valid-looking chain evidence. Duplicate rejection is not pedantry at this boundary; it is what makes the payload hash a faithful commitment to what was submitted.

---

## G. Custodian recommendation

```
PROMOTION BLOCKED
```

**The unresolved issue, stated exactly:**

> Promotion would move `serde_json_canonicalizer` into `[dependencies]` and make `jcs.rs` reachable from `src/`. The promotion candidate's signature is `canonical_bytes(&serde_json::Value)`, which forces every caller to materialize a `Value` first. For the one input class ENT-007 requires and cannot type — the free-form Event Payload — that materialization silently destroys duplicate object member names (§C.2), and no component in the repository performs the RFC 8785 §3.1 rejection that the Golden Fixture explicitly requires (§F.2). Enforcement of a top-level-object Event Payload is likewise absent.

**What is explicitly NOT the reason for the block:**

- The canonicalizer is **not** deficient. C1 PASS stands, unweakened. RFC 8785 §3.2.1–§3.2.4 and Appendix B behavior is verified.
- Duplicate rejection is **not** the serializer's job. `jcs.rs` is on the correct side of the boundary.
- The production paths in use today (`AuditRequest`, `AuditEntry`, `SegmentManifest`) are **not** affected — they are typed and already reject duplicates (§C.1).

**Unblocking condition (single, and testable):**

> Land the raw-text I-JSON ingest step described in §F.3, with executable evidence that duplicate member names are rejected at any depth and that a non-object top-level Event Payload is refused. Promotion may then proceed without re-running C1.

Two statements the Custodian must keep separate, as the mission requires:

| Proven | Not proven |
|---|---|
| Canonicalization capability is RFC 8785 conformant for the C1 domain (C1 PASS, 9/9, exit 0) | The complete input pipeline is suitable for every normative ENT-007 input |

**Alternative considered and not recommended:** promote now and defer the input gate to C3 (ENT-007 composition). Rejected — promotion is what makes `jcs.rs` a production surface, and shipping a production canonicalizer whose documented §3.1 precondition is unenforceable through its own API is precisely the condition this gate exists to catch. The remedy in §F.3 is small; deferring it buys nothing and risks the gap being inherited silently by C3.

---

## H. DQ-003 status

```
DQ-003 = OPEN
```

Unchanged by C2 and not authorized to change. The Golden Fixture is frozen and was not read for values, modified, or regenerated in this gate. Also unchanged:

- `serde_json_canonicalizer` — **NOT PROMOTED**, remains in `[dev-dependencies]`.
- ENT-007, `audit_record_hash`, `integrity_hash`, `previous_record_hash` — **NOT IMPLEMENTED**.
- Audit Record adapter — **NOT CREATED**.
- RI-PY (`aura-poc-a-core-v3.3`) — **UNTOUCHED**; RI-PY remediation remains a separate workstream.
- CROSS-LANGUAGE-002 — **NOT STARTED**.
- C3 ENT-007 composition — **NOT STARTED**; it follows the promotion decision, not this document.

---

## I. Executable-evidence status

Per the C2 mandate, absence of a test is not converted into a pass.

| Evidence | Status |
|---|---|
| C1 canonicalization corpus | **EXECUTED** — `cargo test --test c1_full_domain_jcs`, 9/9, exit 0 (re-run during C2, unchanged) |
| HTTP/integration suite | **EXECUTED** — `cargo test --test integration`, 9/9, exit 0 |
| Typed-path duplicate rejection (§C.1) | **OBSERVED** via read-only probe against `models::AuditRequest` / `models::AuditEntry`; **no committed test asserts it** |
| Untyped-path last-wins collapse (§C.2) | **OBSERVED** via read-only probe; partially asserted by the existing C1 test `c1_i_json_duplicate_property_is_rejected_as_input_precondition` (top level only) |
| Lone **high** surrogate, unpaired-high, invalid UTF-8, top-level non-object | **OBSERVED** via read-only probe; **not in the committed C1 corpus** |
| Raw-text duplicate rejection (§F.3) | **NO IMPLEMENTATION AND NO TEST** — the gap itself |

No test was added by C2. Committing regression tests for the observations above is a legitimate follow-up, but it is a change to the test surface and therefore a separate authorization from this analysis gate.

---

## J. Branch discipline

| Item | Value |
|---|---|
| Requested target branch | `c1/full-domain-jcs` (PR #60) |
| Session-mandated branch | `claude/dq-003-conformance-audit-4ok63x` |
| Base commit | `aebbbe04287993ea303366cf8c453bf721d250cc` (PR #60 head) |
| HEAD relationship | ahead of `origin/c1/full-domain-jcs`, behind by 0 |
| Fast-forward possible | **YES** — `git push origin claude/dq-003-conformance-audit-4ok63x:c1/full-domain-jcs` |

The conflict is reported, not force-resolved. No unrelated branch was merged.
