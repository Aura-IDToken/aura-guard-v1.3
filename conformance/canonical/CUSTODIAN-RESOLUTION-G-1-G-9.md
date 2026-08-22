# Custodian Resolution — DQ-003 Findings G-1 … G-9

**Type:** READ-ONLY governance and specification audit. Audit artifact only.
**Inputs:** `C3-ENT-007-COMPOSITION-GATE.md`, `CUSTODIAN-CLOSURE-GATE-DQ-003.md`
**Scope of change:** one new report file. Nothing else in any repository was modified.

---

## 1. Executive decision

| Finding | Status |
|---|---|
| **G-1** — APS-200 §6–§10 regression | **BLOCKED** |
| **G-1b** — §8.1–§8.9 subsections referenced but never authored *(new, discovered by this audit)* | **CUSTODIAN INPUT REQUIRED** |
| **G-3** — `AUDIT_DECISION` / event-type registry | **CUSTODIAN INPUT REQUIRED** |
| **G-6** — `integrity_hash` dependency diagram | **OPEN** — proven non-byte-bearing and non-acceptance-bearing |
| **G-5** — undefined "session" | **CUSTODIAN INPUT REQUIRED** |
| **G-2** — `0x02` domain prefix | **CLOSED** |
| **G-9** — Unicode normalization | **CLOSED** |

```
C4 = NOT AUTHORIZED
DQ-003 = OPEN
```

### 1.1 What this audit changed against the previous gate

Three results moved, each on primary-source evidence the earlier gates had not read. All three moves are **stricter**, not looser.

**G-1 is far larger than "a branch deleted five sections."** The corpus contains **97 references to `APS-200 §8`**. `closures/DQ-006_CLOSURE_PACKAGE.md` names APS-200 §8 the **"NORMATIVE AUTHORITY"** for canonical serialization and records DQ-006 acceptance criteria as *"MET — APS-200 §8"* and *"MET — APS-200 §8.2"*. `aps/APS-300_EVIDENCE_MODEL.md:75` binds every evidence hash to it: *"APS-200 §8 is the sole normative authority for canonical serialization."* `invariants/INVARIANT_REGISTRY.md:54` and `specification/APS-001_PROTOCOL_SPECIFICATION.md:202–203` cite it. **Commit `bf33eb4` deleted the section on which an already-accepted DQ-006 closure rests.** The blast radius reaches APS-300, APS-001, the invariant registry and the DQ-006 closure package — far beyond DQ-003.

**G-1b is new.** Even restoring `origin/main`'s §8 verbatim would not repair the corpus: main's §8 has **no numbered subsections**, yet the corpus makes **31 references to §8.1 … §8.8**. This defect exists on `main` today and is independent of `bf33eb4`. A restoration executed without knowing this would appear to succeed and leave 31 references dangling.

**G-6 is reclassified CLOSED → OPEN, deliberately.** The previous gate closed it on the ground that normative prose outranks an illustrative figure — that reasoning still holds and is unchanged. But the defective text still stands in the highest-authority artifact, and this gate's vocabulary permits OPEN only with proof of non-impact. That proof is supplied in §6, so OPEN is the more honest resting state. **This is a tightening, not new doubt.**

### 1.2 What did not change

Hash-bearing semantics are untouched and re-confirmed: `event_payload_hash`, `audit_record_hash`, `integrity_hash`, `previous_record_hash`, `0x02 ‖ JCS(R_AR)`, `R_AR`, `R_I`, genesis bytes, digest encoding. **Hash-bearing ambiguities remain 0.** No finding below was downgraded to let C4 proceed.

---

## 2. Authority hierarchy used

As mandated by this gate, cross-checked against `CLAUDE.md` Authority Precedence:

| Rank | Class | Instances |
|---:|---|---|
| 1 | Current normative specification / APS-200 | `aps/APS-200_CANONICAL_DATA_MODEL.md` |
| 2 | Other rank-2 normative artifacts | `aps/APS-000`, `aps/APS-100`, `aps/APS-300`, `aps/EVENT_TYPE_REGISTRY.md`, `specification/APS-001` |
| 3 | Approved protocol contracts | `conformance/P0-2_AUDIT_RECORD_FIELD_BY_FIELD_MATRIX.md` (FROZEN), `closures/DQ-006_CLOSURE_PACKAGE.md` |
| 4 | Golden Fixtures | `conformance/DQ-003-AUDIT-CHAIN-001.json` |
| 5 | Conformance documents | C1 / C2 / C2-1 / C3 gates, `ck003/**` |
| 6 | Implementation | RI-RS, RI-PY |
| 7 | Tests / experimental documents | `conformance/DQ-003_AUDIT_RECORD_HASH_DOMAIN.md`, `conformance/dq-003/**` |

No artifact was modified because a lower-rank artifact disagreed with it. No implementation behavior was read as normative. Every conflict below is identified, ranked, dated, and left for the Custodian.

---

## 3. G-1 — APS-200 §6–§10 regression → **BLOCKED**

### 3.1 The commit

```
commit bf33eb40411d02ba30c68708f980b31747e6ac99
Author: Aura-IDToken
Date:   Sat Aug 22 21:44:56 2026 +0200

    spec(dq-003): define EP-001 event payload contract

 aps/APS-200_CANONICAL_DATA_MODEL.md | 178 +++++++++-----------------
 1 file changed, 71 insertions(+), 107 deletions(-)
```

Section-heading changes in that single commit:

```
+ ### 5.5 EP-001 — Event Payload Contract
- ### ENT-008 — Implementation Metadata      (removed here …)
- ## 6. Relationships
- ## 7. Validation Rules
- ## 8. Serialization Requirements
- ###   CANONICAL-001 reference vector
- ## 9. JSON Schema
+ ### ENT-008 — Implementation Metadata      (… re-added here)
- ## 10. Traceability
```

### 3.2 Verification of the deletions

`origin/main` vs branch, top-level headings:

| Section | `origin/main` | branch `dq/dq-003-audit-record-hash-domain` |
|---|---|---|
| §6 Relationships | line 180 | **DELETED** |
| §7 Validation Rules | line 202 | **DELETED** |
| §8 Serialization Requirements | line 213 | **DELETED** |
| §8 CANONICAL-001 reference vector | present | **DELETED** |
| §9 JSON Schema | line 272 | **DELETED** |
| §10 Traceability | line 280 | **DELETED** |

Confirmed by `git log -S'## 8. Serialization Requirements' -- aps/APS-200_CANONICAL_DATA_MODEL.md`, which returns `bf33eb4` as the removal and `b68181e` as the original import.

### 3.3 Original content on `origin/main` (what was lost)

- **§6 Relationships** — the entity flow ENT-002 → ENT-003 → ENT-005 → ENT-006 → **ENT-007**, closing with *"Every relationship MUST be traceable via object_id references."*
- **§7 Validation Rules** — five mandatory checks for every object: structure, type, required-field, **integrity validation (`integrity_hash` matches computed hash)**, and APS-100 invariant validation.
- **§8 Serialization Requirements** — *"implementations MUST use **RFC 8785 JSON Canonicalization Scheme (JCS)**"*; the canonical boundary as *"the UTF-8 byte sequence emitted by the JCS profile"*; the prohibition on semantic-equivalence / insertion-order / hex substitutes; the `SHA-256(B)` / `SHA-256(0x00 ‖ B)` / `0x01` domain block; version-binding of the profile; the named conformance engines (`rfc8785==0.1.4`, `serde_json_canonicalizer==0.3.2`) with the explicit note that they are *"not a production dependency requirement"*.
- **§8 CANONICAL-001 reference vector** — input object, canonical byte length `100`, canonical bytes hex, `SHA-256 = b6c3660c…a4e6`, RFC 6962 leaf `ce6b3673…c039`.
- **§9 JSON Schema** — schema location, and: *"The event-type vocabulary and validation contract are governed by `aps/EVENT_TYPE_REGISTRY.md`. That registry **MUST be incorporated into the approved APS-200 profile before DQ-004 can be closed**."*
- **§10 Traceability** — the entity → invariant → evidence → CONF matrix, including **`ENT-007 | INV-003, INV-012 | EVID-AUDIT | CONF-003, CONF-012`**.

### 3.4 Every remaining reference to §8

**Intra-document** (`aps/APS-200_CANONICAL_DATA_MODEL.md`, branch) — two, both dangling:

| Line | Text |
|---:|---|
| 58 | `integrity_hash` … *"`SHA-256(canonical_bytes(object))` of this object, excluding `integrity_hash` itself. **Canonical bytes are defined by §8.**"* |
| 189 | *"The canonical bytes MUST be produced using the **RFC 8785 JCS profile defined in §8**."* |

**Cross-document — 97 corpus references to `APS-200 §8`.** The load-bearing ones:

| Artifact | Rank | Reference |
|---|---:|---|
| `aps/APS-300_EVIDENCE_MODEL.md:75` | 2 | *"Every hash field … computed over **canonical bytes as defined by APS-200 §8**. APS-200 §8 is the **sole normative authority** for canonical serialization."* |
| `aps/APS-300_EVIDENCE_MODEL.md:84, 94, 96, 97, 103, 105` | 2 | binds `evidence_hash` representation, `canonical_bytes`, Merkle leaf/interior domains, migration, traceability — to §8.2/§8.4/§8.5/§8.8 |
| `specification/APS-001_PROTOCOL_SPECIFICATION.md:202–203` | 2 | *"the canonical serialization profile itself is closed: APS-200 §8 binds RFC 8785 JCS…"* |
| `invariants/INVARIANT_REGISTRY.md:54` | 2 | `Related APS \| APS-200 §8` |
| `closures/DQ-006_CLOSURE_PACKAGE.md:230` | 3 | *"APS-200 §8 … §8.1–8.9 **NORMATIVE AUTHORITY**"* |
| `closures/DQ-006_CLOSURE_PACKAGE.md:271` | 3 | acceptance criterion 1 — *"**MET** — APS-200 §8"* |
| `closures/DQ-006_CLOSURE_PACKAGE.md:282` | 3 | acceptance criterion 12, *"Single normative authority; no competing definition"* — *"**MET** — APS-200 §8.2"* |
| `CHANGELOG.md:26` | — | *"**APS-200 §8** … **Declared the single normative authority for canonical serialization (DQ-006)**"* |

**Consequence: deleting §8 retroactively invalidates the evidence for an already-accepted DQ-006 closure**, and leaves APS-300's entire hash chapter bound to a section that no longer exists.

### 3.5 CANONICAL-001 reference material

**Removed.** The reference vector — input object, byte length, canonical hex, SHA-256, RFC 6962 leaf — lived only inside §8 and was deleted with it. `conformance/canonical/CANONICAL-001.json` in RI-RS still carries the input object, but the **normative expected values** existed only in APS-200 §8.

### 3.6 Do P0-2 / ENT-007 changes depend on the deleted sections?

| Dependency | Verdict |
|---|---|
| §8 canonical-bytes profile | **Yes, indirectly.** §5.1 and §5.5 name RFC 8785 inline and P0-2 §7 restates UTF-8, so ENT-007's **bytes** are determined without §8 (§7.2). But line 58's definition of canonical bytes for **every** entity's `integrity_hash` — ENT-001…ENT-008 — now points at nothing. |
| §7 Validation Rules | **Yes.** Check 4, *"Integrity validation (`integrity_hash` matches computed hash)"*, is the general obligation ENT-007 §5.2 specialises. P0-2 §9's 17-step order presumes it. |
| §9 registry-incorporation clause | **Yes, and it is exactly G-3.** The requirement that the registry *"MUST be incorporated into the approved APS-200 profile before DQ-004 can be closed"* was deleted along with §9. |
| §10 Traceability | **Yes.** The `ENT-007 → INV-003, INV-012 / EVID-AUDIT / CONF-003, CONF-012` row was the only mapping from ENT-007 to its invariants; INV-010 Conformance Completeness depends on that mapping existing. |
| §6 Relationships | Contextual only. |

### 3.7 Regression or intentional change?

**SPECIFICATION REGRESSION.** Five independent indicators, none of which relies on interpretation:

1. **The commit message declares only an addition** — *"define EP-001 event payload contract"* — and says nothing about removing five sections.
2. **Nothing was relocated.** The only heading that moved is ENT-008 (deleted at one position, re-added at another). §6–§10 content appears nowhere else on the branch.
3. **Both §8 references were left live.** An intentional deletion would have retargeted lines 58 and 189 in the same commit.
4. **No deprecation record.** `CHANGELOG.md` still advertises §8 as the single normative authority (line 26); no entry records its removal.
5. **The shape is a truncation.** `+71 / −107` on a commit whose message describes an addition, with ENT-008 relocated and everything after it lost, is the signature of a regenerated file whose tail was dropped — not a considered edit.

### 3.8 Restoration plan — **PLAN ONLY, NOT APPLIED**

| Item | Value |
|---|---|
| **File** | `aps/APS-200_CANONICAL_DATA_MODEL.md` (repository `Aura-IDToken/aura-specification`) |
| **Sections** | `## 6. Relationships`, `## 7. Validation Rules`, `## 8. Serialization Requirements` (incl. `### CANONICAL-001 reference vector`), `## 9. JSON Schema`, `## 10. Traceability` |
| **Source commit** | `origin/main` @ `9682cf53956f27c18821ac29531a356c5ed4afa5`, lines 180–291 |
| **Authoritative source** | `origin/main` — rank 1. The branch never superseded this content; it deleted it |
| **Reason** | Undeclared regression (§3.7) removing the sole normative authority for canonical serialization, on which APS-300, APS-001, the invariant registry and the accepted DQ-006 closure all depend |
| **Merge strategy** | Append the five sections verbatim from `origin/main` **after** the branch's new `### 5.7` / `### ENT-008` block, preserving the branch's §4.1 and §5.1–§5.7 additions unchanged. This is an append, not a merge of overlapping text |
| **Renumbering** | **None required.** The branch added only §4.1 and §5.1–§5.7 — all sub-sections of existing §4 and §5. Top-level numbering §1–§5 is unchanged, so restored §6–§10 keep their numbers and all 97 corpus references resolve |
| **Conflicts with current P0-2 work** | **One, and it is benign.** Restored §8 states the `SHA-256(0x00 ‖ B)` RFC 6962 leaf domain; branch §5.1 states the `0x02` Audit Record domain. These are **complementary, not competing** — P0-2 §8's domain table already assigns `0x00`/`0x01` to Merkle and `0x02` to the Audit Record. No wording change is needed in either section. **No other overlap exists**: the branch touched only §4/§5, the restoration touches only §6–§10 |
| **Byte impact** | **None.** Restored §8 mandates plain RFC 8785 with no deviation, matching branch §5.1/§5.5 and P0-2 §7. Verified by direct comparison (§7.2) |

**Alternative, if the Custodian intends the five-section structure to be final:** the deletion must be re-executed *deliberately* — retarget lines 58 and 189, relocate the §7 integrity-validation rule, the §9 registry-incorporation clause and the §10 ENT-007 traceability row into surviving sections, update all 97 cross-references, amend `CHANGELOG.md`, and re-open DQ-006 for re-closure against a new authority. **Silent deletion is not an acceptable outcome under either path.**

### 3.9 Status

**G-1 = BLOCKED.** ENT-007 byte determination is unaffected, but the branch cannot merge without removing rank-1 normative content and invalidating an accepted closure.

---

## 4. G-1b — §8.1 … §8.9 subsections referenced but never authored → **CUSTODIAN INPUT REQUIRED**

*New finding. Discovered while validating the G-1 restoration plan; reported because the plan cannot be executed correctly without it.*

The corpus makes **31 references to numbered subsections of APS-200 §8**:

| Reference | Count | Cited for |
|---|---:|---|
| `APS-200 §8.5` | 8 | Merkle leaf / interior domains |
| `APS-200 §8.7` | 7 | canonicalization vs event semantics boundary |
| `APS-200 §8.8` | 4 | version binding / migration |
| `APS-200 §8.4` | 4 | prohibited digest inputs |
| `APS-200 §8.3` | 4 | — |
| `APS-200 §8.2` | 3 | single normative authority |
| `APS-200 §8.1` | 1 | — |

`origin/main`'s §8 contains **no numbered subsections** — its only sub-heading is `### CANONICAL-001 reference vector`. The referenced content exists as unnumbered prose within §8; the numbering does not.

This is **pre-existing on `main` and independent of `bf33eb4`.** Restoring §8 verbatim per §3.8 restores the *content* and repairs the 66 plain `§8` references, but leaves these 31 sub-references unresolvable.

**Custodian input required:** either author the §8.1–§8.9 subdivision so the existing citations resolve, or amend the 31 citations to reference §8 without subdivision. **This gate does not choose, and does not invent a subdivision** — deciding which prose becomes §8.4 versus §8.5 is a normative structuring decision.

---

## 5. G-3 — `AUDIT_DECISION` / event registry → **CUSTODIAN INPUT REQUIRED**

### 5.1 The seven determinations

**1. Is `AUDIT_DECISION` a normative `event_type`?**
**CUSTODIAN INPUT REQUIRED.** `grep -rn AUDIT_DECISION` across the specification corpus returns **no hit outside the DQ-003 Golden Fixture**. No artifact registers, describes, reserves or deprecates it. The corpus is silent, and silence is not an answer this audit may supply.

**2. Is `AUDIT_DECISION` currently registered?** **No.**

**3. Does the registry contain zero valid tokens?**
**Yes.** `aps/EVENT_TYPE_REGISTRY.md` §5: *"**No individual event token is promoted to final normative status by this document yet.**"* §9: *"DQ-004: `SEMANTIC CONTRACT DEFINED / VOCABULARY REGISTRY PENDING NORMATIVE ENTRIES`."*

**4. Does strict verification therefore reject the Golden Fixture?**
**Yes.** Registry §3: `unknown token → REJECT in strict conformance mode`. §5: *"Until entries are registered, strict conformance implementations MUST reject an `event_type` value that is not present in an approved versioned registry."* APS-200 §5 ENT-007 delegates the vocabulary to that registry by name, so the rule reaches ENT-007 at rank 1–2. Both fixture records must be rejected.

**5. Does the same contradiction affect CANONICAL-001?**
**Yes — in three places, one of them inside the specification itself:**

| Artifact | Token | Registered? |
|---|---|---|
| `origin/main` APS-200 §8 CANONICAL-001 reference vector | `AUDIT_RECORD` | **No** |
| `conformance/canonical/CANONICAL-001.json` (RI-RS) | `AUDIT_RECORD` | **No** |
| `conformance/DQ-003-AUDIT-CHAIN-001.json` (Golden Fixture) | `AUDIT_DECISION` | **No** |

**The registry currently rejects the specification's own normative reference vector.**

**6. DQ-003-specific or corpus-wide?**
**Corpus-wide, and already registered as such.** `closures/DQ-006_CLOSURE_PACKAGE.md:310`, verbatim:

> **CFL-005** — CANONICAL-001 carries `event_type: "AUDIT_RECORD"`, which the Event-Type Registry does not register, while requiring strict-mode rejection of unregistered tokens. Under the registry's own rule, strict conformance would reject the object this gate rests on. Canonicalization determines representation, never event semantics (APS-200 §8.7), so DQ-006 does not repair this. **DQ-004 governs.**

Also logged as CONFLICT in `ck003/handover-assessment/04_CONFLICT_REGISTER.md` §CFL-005. DQ-003 inherited a known open conflict; it did not create one.

**7. Which artifact must change?**
`aps/EVENT_TYPE_REGISTRY.md` §5 (register the tokens), and APS-200 §5.7 (add an error code). **Not the Golden Fixture** — amending a fixture to satisfy a registry would invert ranks 1–2 above rank 4 and is forbidden by this gate's governance rule.

Note the compounding effect with G-1: the clause requiring the registry to be *"incorporated into the approved APS-200 profile before DQ-004 can be closed"* lived in **§9, which `bf33eb4` deleted**. G-1 removed the text that gates G-3's resolution.

### 5.2 Cryptographic validity vs normative acceptance

| Dimension | Golden Fixture | Evidence |
|---|---|---|
| **CRYPTOGRAPHIC VALIDITY** | **VALID** — all six digests and both canonical preimages derive uniquely; independently reproduced byte-for-byte | `DQ-003-ENTRY-POINT-EXECUTION.md` §A.4, `FIXTURE SELF-VERIFICATION: PASS`, exit 0 |
| **NORMATIVE ACCEPTANCE** | **REJECTED** in strict mode — unregistered `event_type` | `EVENT_TYPE_REGISTRY.md` §3, §5 |

These are independent axes. The fixture is simultaneously correct and unacceptable. **No computation resolves this**; only a Custodian decision does.

### 5.3 Missing protocol content — not supplied here

| Required | Status |
|---|---|
| Is `AUDIT_DECISION` normative? | **CUSTODIAN INPUT REQUIRED** |
| `description` (normative semantic meaning) | **CUSTODIAN INPUT REQUIRED** |
| `producer` (component/profile permitted to emit) | **CUSTODIAN INPUT REQUIRED** |
| `payload_schema` (canonical payload contract) | **CUSTODIAN INPUT REQUIRED** |
| `introduced_protocol_version` | derivable as `1.0`, but requires ratification |
| Error code for unregistered `event_type` | **CUSTODIAN INPUT REQUIRED** — none of APS-200 §5.7's fourteen codes covers it |
| Same decision for `AUDIT_RECORD` (CFL-005) | **CUSTODIAN INPUT REQUIRED** |

No token, description, producer, payload schema or error code was invented.

### 5.4 Status

**G-3 = CUSTODIAN INPUT REQUIRED.** The missing element is protocol content, not analysis.

---

## 6. G-6 — `integrity_hash` dependency diagram → **OPEN** (proven non-impacting)

### 6.1 Exact diagram, APS-200 §5.2

Introduced by the sentence *"The dependency is intentionally one-directional:"*:

```text
ENT-007 source fields
        │
        ├───────────────┐
        ▼               ▼
 event_payload_hash  audit_record_hash
                         │
                         ▼
                  integrity_hash
                         │
                         ▼
          next.previous_record_hash
```

### 6.2 Exact normative rules

**§5.2 rule 4:** *"`previous_record_hash` MUST refer to the preceding record's `audit_record_hash`, **not its `integrity_hash`**."*

**§5.3:**
```text
R[n].previous_record_hash = R[n-1].audit_record_hash
```

**§5.4:** *"`previous_record_hash` — from the predecessor's `audit_record_hash`, except for genesis."*

### 6.3 Determinations

| Question | Determination |
|---|---|
| Does the contradiction change hash bytes? | **No.** No preimage member set, member order or encoding is affected. `R_AR` remains 9 members, `R_I` 10 |
| Could an implementer derive the wrong chain? | **Yes, prospectively.** Reading the figure before the rules would wire `previous_record_hash` to `integrity_hash`, producing a chain that fails the fixture at record-001 (`cbbc5104…689e79` expected; `70526acd…be57a` would be produced) |
| Which statement has normative authority? | **The prose and the equation.** Three normative statements — §5.2 rule 4, the §5.3 equation, §5.4 — against one arrow in a figure introduced as an illustration, carrying no MUST and making no linkage claim |
| Does it affect normative acceptance semantics? | **No.** Acceptance is decided by §5.3 and P0-2 §9 step 14, both of which name `audit_record_hash` |
| Is the fixture consistent with the rule? | **Yes**, verified byte-for-byte: `record-001.previous_record_hash` = `cbbc5104…689e79` = `record-000.audit_record_hash` |
| Does any implementation rely on the diagram? | **No.** RI-RS links `prev_hash → chain_hash` in its own unrelated domain; RI-PY has no chain |

### 6.4 Authoritative statement

The authoritative contract supports, and this audit therefore records:

```text
previous_record_hash[n+1] = audit_record_hash[n]
```

`integrity_hash` is **not** equated with `audit_record_hash`. `chain_hash` is **not** renamed.

### 6.5 Status

**G-6 = OPEN.** Permitted to remain open because §6.3 proves it changes **no hash preimage** and **no normative acceptance semantics**. It stays open rather than closed because the erroneous figure still stands in the rank-1 artifact. Correction proposed in §9 (A-4), **not applied**.

---

## 7. G-5 — "session" definition → **CUSTODIAN INPUT REQUIRED**

### 7.1 Corpus search

Searched `session`, `session_id`, `session boundary`, `first record in a session`, `sequence_number = 0` across `aps/`, `glossary/`, `invariants/`, `specification/`, `conformance/`.

`session` occurs **exactly three times**, all in APS-200, all as usage:

| Line | Text |
|---:|---|
| 175 | *"Monotonically increasing sequence number **within a session**"* |
| 253 | *"The first Audit Record **in a session** MUST have `sequence_number = 0`. Subsequent records MUST increase monotonically by one within that session."* |
| 384 | `E_SEQUENCE_INVALID` — *"Sequence number violates **session** ordering"* |

`session_id` — **zero hits corpus-wide.** No definition in `aps/APS-000_FOUNDATION_AND_TERMINOLOGY.md` or `glossary/GLOSSARY.md`.

### 7.2 Determinations, and re-confirmation of the byte finding

| Question | Determination |
|---|---|
| Used normatively? | **Yes** — three MUST-bearing usages |
| Formally defined? | **No**, nowhere in the corpus |
| Does `sequence_number = 0` depend on it? | **Partially.** The *value* does not; the *rule that it must be 0* is scoped "in a session" and that scope is undefined |
| Does genesis behavior depend on it? | **No.** §5.3 identifies genesis by two self-contained per-record properties: `previous_record_hash == 0`×64 and `sequence_number == 0`. Neither requires a session model |
| Does the Golden Fixture require it? | **No.** A single frozen two-record chain, `sequence_number` 0 then 1, verified in supplied order; the chain is its own scope |
| Byte-bearing or verification-only? | **Verification-only.** `sequence_number` is serialized from the record's supplied value as an RFC 8785 number; the session concept never enters a preimage |

**Re-confirmation.** Cross-checking `origin/main`'s §8 against branch §5.1/§5.5 and P0-2 §7 found no divergence in canonical-byte semantics: main's §8 mandates *"RFC 8785 JSON Canonicalization Scheme (JCS)"* with the boundary as *"the UTF-8 byte sequence emitted by the JCS profile"* — no deviation. **C3's "hash-bearing ambiguities = 0" stands, now verified against the fuller specification text this branch had removed.**

### 7.3 Minimum semantic statement required — **not filled in**

The Custodian must supply a definition that fixes at least these four points. **This audit deliberately proposes no wording; the session model is a protocol design decision.**

1. **What delimits a session** — the scope within which `sequence_number` is monotonic.
2. **When a session begins** — the condition under which a record legitimately carries `sequence_number = 0` and the genesis sentinel.
3. **Whether a session is identified in-record** — and if so, by which field. *Note: adding a session field to ENT-007 would change `R_AR` and `R_I` and therefore every digest. **That would be byte-bearing and would require re-freezing P0-2 and regenerating the Golden Fixture.** If the Custodian intends session identity to remain out-of-band, saying so explicitly preserves the current frozen hash contract.*
4. **What `E_SEQUENCE_INVALID` tests** — the precise predicate, so it becomes testable.

### 7.4 Status

**G-5 = CUSTODIAN INPUT REQUIRED.** Non-byte-bearing **as the contract currently stands**, and therefore not a C4 blocker — with the caveat in point 3 that one possible resolution *would* become byte-bearing.

---

## 8. G-2 and G-9 — reconfirmation

### 8.1 G-2 — `0x02` domain prefix → **CLOSED**

**Normative source.** APS-200 §5.1:

```text
AuditRecordHashPreimage(R) = 0x02 || JCS(R_AR)
audit_record_hash(R)       = SHA-256(AuditRecordHashPreimage(R))
```

> `` `0x02` `` is one raw octet. It MUST NOT be represented as the ASCII characters `0x02`, a hexadecimal string, or another textual wrapper.

Corroborated by P0-2 §4 and the §8 domain table (`0x00` Merkle leaf · `0x01` Merkle interior · `0x02` Audit Record).

**Authority.** APS-200 is rank 1. The two dissenting documents are rank 7 (tests / experimental) and self-designate *"EXPERIMENTAL — not normative"* and *"EXPERIMENTAL / NOT NORMATIVE"*.

**Chronology** — decisive. Branch order, oldest first:

| Order | Commit | Effect |
|---:|---|---|
| 1 | `9b5c262` | `conformance/dq-003/…` added — *"`0x02` … has no normative status until DQ-003 is accepted"*; *"The specification does not presently provide the exact hash equation for that field"* |
| 4 | `7bc722f` | `conformance/DQ-003_AUDIT_RECORD_HASH_DOMAIN.md` added — *"experimental and MUST NOT be treated as normative until DQ-003 closes"* |
| 11 | **`8d3f1fe`** | **`spec(aps-200): define ENT-007 audit record hash dependency`** — introduces `0x02 ‖ JCS(R_AR)` into APS-200. `git log -S'0x02 \|\| JCS(R_AR)'` returns this commit and only this commit |

Both dissents were written **before** APS-200 acquired the construction. The second document's premise — *"the specification does not presently provide the exact hash equation"* — was true at `9b5c262` and became **false** at `8d3f1fe`.

**Self-limiting scope.** `conformance/DQ-003_AUDIT_RECORD_HASH_DOMAIN.md` states in its own Purpose: *"This document does **not** amend APS-200… Any rule that **differs from or extends APS-200** remains provisional."* Once APS-200 carries the rule, it no longer differs from or extends it, and the clause no longer reaches it.

**Genuine authority conflict remaining?** **None.** Both dissenting artifacts are rank 7, disclaim normative force, disclaim amending APS-200, and predate the amendment.

**G-2 = CLOSED.** The two documents are classified **STALE DOCUMENTATION** and were **not modified**.

### 8.2 G-9 — Unicode normalization → **CLOSED**

**Governing text.** APS-200 §5.5 line 296:

> The Event Payload MUST be valid Unicode JSON and its canonical JCS representation MUST be encoded as UTF-8. Invalid UTF-8 byte sequences are not a valid payload representation. **Implementations MUST NOT perform locale-dependent transcoding or normalization outside the JCS processing defined by RFC 8785.**

**Does RFC 8785 normalize?** **No.** It sorts member names by UTF-16 code units (§3.2.3) and escapes per ECMAScript (§3.2.2.2). It defines no NFC/NFD/NFKC/NFKD step.

**Does any Aura artifact require a normalization form?** **No.** `grep -rn -i "NFC\|NFD\|NFKC\|NFKD\|unicode normal"` over `aps/` and `conformance/` returns **zero** hits.

**May `NFC(name) == NFC(other_name)` be used for duplicate detection?**

> **NO.** Applying NFC before comparison is *"normalization outside the JCS processing defined by RFC 8785"* and is therefore prohibited by APS-200 §5.5. **Duplicate detection MUST compare member names exactly**, and RFC 8785 behavior is authoritative.

**Does C2-1 normalize?** No — `validate_event_payload` compares by exact `String` equality. **This is confirmed correct against APS-200 §5.5**, not merely tolerated. The engine (`serde_json_canonicalizer =0.3.2`, C1-verified 9/9) performs no normalization either.

**Could normalization alter hash-participating bytes?** Yes — which is precisely why §5.5 forbids it. NFC-folding a payload member name would change `JCS(P)` and therefore `event_payload_hash`. The prohibition is what keeps the bytes stable.

**G-9 = CLOSED.** The `C2-1-TBD-UNICODE-NORMALIZATION` marker in `src/event_payload.rs` and `C2-1-EVENT-PAYLOAD-INPUT-CONTRACT.md` §K.6 is classified **STALE DOCUMENTATION** — it states the question is unspecified when APS-200 §5.5 specifies it. As instructed, **it was not removed.**

---

## 9. Required amendments — **NOT APPLIED**

None applied. No normative artifact, fixture, source file or manifest was modified by this audit.

| ID | Amendment | Closes | Blocking |
|---|---|---|:---:|
| **A-1** | Restore APS-200 §6–§10 verbatim from `origin/main` @ `9682cf5` lines 180–291, appended after the branch's `### ENT-008` block. No renumbering; no conflict with §4.1/§5.1–§5.7 (§3.8) | G-1 | **YES** |
| **A-1-alt** | If the five-section structure is intended as final: retarget lines 58 and 189, relocate the §7 integrity-validation rule, the §9 registry-incorporation clause and the §10 ENT-007 traceability row, update all 97 cross-references, amend `CHANGELOG.md`, and re-open DQ-006 for re-closure | G-1 | **YES** |
| **A-2** | Author the §8.1–§8.9 subdivision so the 31 existing sub-references resolve, **or** amend those 31 citations to plain §8. *Structuring decision — no candidate subdivision proposed here* | G-1b | **YES** (rides with A-1) |
| **A-3** | Register `AUDIT_DECISION` in `EVENT_TYPE_REGISTRY.md` §5 using the §4 record. `event_type` = `AUDIT_DECISION`; `introduced_protocol_version` = `1.0`; `deprecated` = `false`. **`description`, `producer` and `payload_schema` are CUSTODIAN INPUT REQUIRED and are deliberately left blank.** Resolve `AUDIT_RECORD` (CFL-005) in the same change | G-3 | **YES** |
| **A-4** | Add an APS-200 §5.7 / P0-2 §11 error code for an unregistered `event_type`. **Code name is CUSTODIAN INPUT REQUIRED** — none is proposed | G-3 | **YES** |
| **A-5** | Correct the APS-200 §5.2 figure so its final arrow leaves `audit_record_hash`, matching §5.2 rule 4 and §5.3, and mark `integrity_hash` terminal | G-6 | no |
| **A-6** | Add supersession banners to `conformance/DQ-003_AUDIT_RECORD_HASH_DOMAIN.md` and `conformance/dq-003/DQ-003_AUDIT_RECORD_HASH_DOMAIN.md` recording that `0x02` was promoted to normative by APS-200 §5.1 in `8d3f1fe`, after those documents were written | G-2 | no |
| **A-7** | Define "session" per the four points in §7.3. **No wording proposed** | G-5 | no |
| **A-8** | Replace the `C2-1-TBD-UNICODE-NORMALIZATION` marker with a citation to APS-200 §5.5 confirming exact comparison and no normalization | G-9 | no |

---

## 10. C4 readiness decision

```
C4 = NOT AUTHORIZED
```

Mandated by this gate's rule: C4 must remain unauthorized while **either** G-1 **or** G-3 is unresolved. Both are unresolved.

| Blocker | Why it blocks C4 |
|---|---|
| **G-1** (+ G-1b) | C4 would implement ENT-007 against an APS-200 revision that has silently deleted the sole normative authority for canonical serialization, while APS-300, APS-001, the invariant registry and an accepted DQ-006 closure still cite it, and two internal references dangle. The specification must be whole before it is implemented against |
| **G-3** | C4 necessarily includes §5.7 error reporting and `event_type` validation. Neither can be built correctly today: the registry rejects the Golden Fixture *and* the specification's own reference vector, and no error code exists for that rejection. Proceeding would force the implementer to invent a vocabulary or an error code — exactly what the governance rule forbids |

Permitted to remain unresolved without blocking C4, with proof: **G-6** (§6.3 — no preimage, no acceptance impact) and **G-5** (§7.2 — verification-only, subject to the §7.3 point-3 caveat).

**No blocker was downgraded to allow C4 to proceed.** G-1 was escalated and a new blocker (G-1b) was added.

**When G-1 and G-3 close, the hash contract needs nothing further.** C3 established 0 hash-bearing ambiguities and complete Golden Fixture derivation; this audit re-confirmed both against the fuller `main` text. The C4 hand-off requirements in `C3-ENT-007-COMPOSITION-GATE.md` §17 remain valid and unmodified.

---

## 11. Decision table

| Finding | Status | Byte-bearing? | Normative? | Required Custodian Action | C4 Impact |
|---|---|:---:|:---:|---|---|
| **G-1** APS-200 §6–§10 regression | **BLOCKED** | **NO** | **YES** — rank 1 | Restore §6–§10 from `origin/main` (A-1), or re-execute the deletion deliberately (A-1-alt) | **BLOCKS** |
| **G-1b** §8.1–§8.9 never authored | **CUSTODIAN INPUT REQUIRED** | **NO** | **YES** — rank 1 | Author the subdivision or amend 31 citations (A-2) | **BLOCKS** (with A-1) |
| **G-3** `AUDIT_DECISION` unregistered | **CUSTODIAN INPUT REQUIRED** | **NO** — registry validates, never rewrites the token | **YES** — rank 2 | Register the token with Custodian-supplied semantics; add an error code (A-3, A-4); resolve CFL-005 corpus-wide | **BLOCKS** |
| **G-6** §5.2 diagram | **OPEN** | **NO** — proven §6.3 | **NO** — figure is illustrative | Correct the figure (A-5) | none |
| **G-5** "session" undefined | **CUSTODIAN INPUT REQUIRED** | **NO** as the contract stands — see §7.3 point 3 | **YES** — rank 1 usage without definition | Define per the four points in §7.3 (A-7) | none |
| **G-2** `0x02` normative status | **CLOSED** | **NO** — identical octet in all artifacts | resolved — APS-200 §5.1 governs | Optional: supersession banners (A-6). Two documents = **STALE DOCUMENTATION** | none |
| **G-9** Unicode normalization | **CLOSED** | **NO** — the prohibition is what keeps bytes stable | resolved — APS-200 §5.5 governs | Optional: retire the stale marker (A-8) = **STALE DOCUMENTATION** | none |

```
C4:      NOT AUTHORIZED
DQ-003:  OPEN
```

---

## 12. Explicit non-actions

Not done, in any repository:

- APS-200, APS-000, APS-300, APS-001, `EVENT_TYPE_REGISTRY.md`, the invariant registry, the DQ-006 closure package, `CHANGELOG.md` — **not modified**
- DQ-003 Golden Fixture — **not modified**; no byte, no expected value, no `event_type`
- CANONICAL-001 reference vector and `CANONICAL-001.json` — **not modified**
- RI-PY (`aura-poc-a-core-v3.3`) — **not modified**
- RI-RS production code, conformance test code, `Cargo.toml`, `Cargo.lock` — **not modified**
- The two stale DQ-003 experimental documents — **not modified** (classified, per instruction)
- `C2-1-TBD-UNICODE-NORMALIZATION` marker — **not removed** (classified, per instruction)
- ENT-007, adapters, hash formulas, `0x02`, JCS behavior, C4 — **not created, not changed, not authorized**
- DQ-003 — **not closed**
- No event token, description, producer, payload schema, error code, session model or §8 subdivision — **invented**
- No normative meaning inferred from RI-RS or RI-PY
- No §6–§10 content restored — **plan only**

---

## 13. Evidence and commit references

| Ref | Evidence |
|---|---|
| `bf33eb4` | `spec(dq-003): define EP-001 event payload contract` — +71/−107 on APS-200; deleted §6–§10 and the CANONICAL-001 vector; relocated ENT-008 |
| `8d3f1fe` | `spec(aps-200): define ENT-007 audit record hash dependency` — introduced `0x02 ‖ JCS(R_AR)` into APS-200 |
| `9b5c262`, `7bc722f` | added the two "experimental" DQ-003 documents, both **before** `8d3f1fe` |
| `9682cf5` | `origin/main` — authoritative source for §6–§10 restoration, lines 180–291 |
| `b68181e` | original import of §8 |
| `git log -S'0x02 \|\| JCS(R_AR)'` | returns `8d3f1fe` only |
| `git log -S'## 8. Serialization Requirements'` | returns `bf33eb4` (removal) and `b68181e` (import) |
| `grep -rn "APS-200 §8" --include=*.md` | **97** references corpus-wide |
| `grep -rhoE "APS-200 §8\.[0-9]"` | **31** sub-section references: §8.5×8, §8.7×7, §8.8×4, §8.4×4, §8.3×4, §8.2×3, §8.1×1 |
| `aps/APS-300_EVIDENCE_MODEL.md:75` | *"APS-200 §8 is the sole normative authority for canonical serialization"* |
| `closures/DQ-006_CLOSURE_PACKAGE.md:230, 271, 282, 310` | §8 as NORMATIVE AUTHORITY; criteria MET; CFL-005 verbatim |
| `CHANGELOG.md:26–27` | §8 declared single normative authority (DQ-006); APS-300 §5 bound to it |
| `aps/EVENT_TYPE_REGISTRY.md` §3, §5, §9 | strict-mode rejection; zero registered tokens; DQ-004 pending |
| `aps/APS-200_CANONICAL_DATA_MODEL.md` §4 L58, §5.1 L189 | the two dangling §8 references |
| `aps/APS-200_CANONICAL_DATA_MODEL.md` §5.2, §5.3, §5.4 | diagram vs rule 4 vs equation (G-6) |
| `aps/APS-200_CANONICAL_DATA_MODEL.md` §5.5 L296 | normalization prohibition (G-9) |
| `aps/APS-200_CANONICAL_DATA_MODEL.md` L175, L253, L384 | the three undefined "session" usages (G-5) |
| `DQ-003-ENTRY-POINT-EXECUTION.md` §A.4 | `FIXTURE SELF-VERIFICATION: PASS`, exit 0 — cryptographic validity |
| `C1-FULL-DOMAIN-JCS.md` | RFC 8785 conformance, 9/9, exit 0 |
| `C2-1-PRODUCTION-PROMOTION.md` | 346/346, exit 0 |

### Git state

| Item | Value |
|---|---|
| Repository | `Aura-IDToken/aura-guard-v1.3` |
| Branch | `claude/dq-003-conformance-audit-4ok63x` (session-mandated) |
| Intended branch | `c1/full-domain-jcs` (PR #60) — conflict reported, not auto-resolved; fast-forward possible |
| HEAD before | `f9245a32b953344ccfe198643dc41b7e396a45dc` |
| `git status` before | clean |
| Files changed | **exactly one — this report (new)** |
| `aura-specification` | clean, `ecdb52f`, untouched |
| `aura-poc-a-core-v3.3` | clean, `64bf959`, untouched |
