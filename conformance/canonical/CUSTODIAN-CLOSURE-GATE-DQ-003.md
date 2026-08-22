# Custodian Closure Gate — DQ-003 / C3 Conditional Pass

**Input:** `C3-ENT-007-COMPOSITION-GATE.md` — CONDITIONAL PASS, 0 hash-bearing ambiguities, Golden Fixture derivation PASS, 9 normative-consistency defects.
**Purpose:** formally close, block, or escalate each finding. Normative consistency only — **not** redesign, **not** implementation.
**Scope of change:** one new report file. No `src/`, no fixture, no APS-200, no Cargo, no RI-PY, no RI-RS.

---

## 1. Executive summary

| Finding | Status |
|---|---|
| **G-2** — `0x02` normative status | **CLOSED** |
| **G-3** — event-type registry vs Golden Fixture | **BLOCKED** — Custodian decision required |
| **G-6** — §5.2 dependency-diagram contradiction | **CLOSED** |
| **G-1** — dangling §8 reference | **BLOCKED** — merge-blocking specification regression |
| **G-5** — undefined "session" | **OPEN NON-BLOCKING** |
| **G-9** — Unicode normalization | **CLOSED** |

Three findings closed on the evidence, two blocked pending Custodian action, one open and non-blocking.

**Two results changed materially against C3's provisional classification, both after reading primary sources this gate had not yet examined:**

- **G-1 is worse than C3 recorded.** It is not a typo. Branch commit `bf33eb4` **deleted APS-200 §6 Relationships, §7 Validation Rules, §8 Serialization Requirements (including the CANONICAL-001 reference vector), §9 JSON Schema and §10 Traceability**, all of which exist on `origin/main`, while leaving two live references to §8. Merging this branch as-is would remove the normative Serialization Requirements from the specification. Escalated Medium → **BLOCKED**.
- **G-9 is already answered by the specification.** APS-200 §5.5 line 296 states: *"Implementations MUST NOT perform locale-dependent transcoding or normalization outside the JCS processing defined by RFC 8785."* RFC 8785 performs no Unicode normalization, so exact comparison is mandated. C3 recorded this as unresolved because that sentence had not been located. Resolved → **CLOSED**.

**Hash-bearing semantics are unchanged.** Nothing in this gate touched `event_payload_hash`, `audit_record_hash`, `integrity_hash`, `previous_record_hash`, the genesis bytes, or `0x02 ‖ JCS(R_AR)`. C3's finding of **0 hash-bearing ambiguities** is re-confirmed, including against APS-200 §8 as it exists on `main` (§7.3).

**C4 is NOT AUTHORIZED.** G-1 and G-3 must be closed by the Custodian first.

---

## 2. Authority hierarchy used

Taken from `CLAUDE.md` (Authority Precedence, highest → lowest), unmodified:

| Rank | Artifact class | Instances in this gate |
|---:|---|---|
| 1 | Constitutional Decree | — |
| 2 | **Aura Protocol Specification** | `aps/APS-200_CANONICAL_DATA_MODEL.md`, `aps/EVENT_TYPE_REGISTRY.md` (delegated by APS-200 §5 ENT-007) |
| 3 | Protocol Invariants | `aps/APS-100_PROTOCOL_INVARIANTS.md` |
| 4 | Repository constitutional directives | — |
| 5 | **Conformance Test Matrix / approved Conformance Requirements** | `conformance/P0-2_AUDIT_RECORD_FIELD_BY_FIELD_MATRIX.md` (FROZEN), `C2-1-EVENT-PAYLOAD-INPUT-CONTRACT.md` |
| 6 | AGENTS.md / CLAUDE.md workflow | — |
| 7 | Path-specific agent instructions | — |
| 8 | Prompt / task instructions | this gate |
| 9 | **Existing implementation** | RI-RS, RI-PY — **evidence only, never authority** |
| 10 | Agent assumptions | excluded |

Governing rule, applied throughout: *"Lower-level instructions MUST NOT override higher-level authority."*

Documents self-designated **"EXPERIMENTAL — not normative"** (`conformance/DQ-003_AUDIT_RECORD_HASH_DOMAIN.md`, `conformance/dq-003/DQ-003_AUDIT_RECORD_HASH_DOMAIN.md`) sit at rank 5 or below **and disclaim normative force in their own text**. They cannot bind APS-200.

No contradiction below was resolved by consulting RI-RS or RI-PY behavior.

---

## 3. G-2 — `0x02` normative status → **CLOSED**

### 3.1 The three texts, verbatim

**APS-200 §5.1** (rank 2):

> ```text
> AuditRecordHashPreimage(R) =
>     0x02 || JCS(R_AR)
> ```
> `` `0x02` `` is one raw octet. It MUST NOT be represented as the ASCII characters `0x02`, a hexadecimal string, or another textual wrapper.

**`conformance/DQ-003_AUDIT_RECORD_HASH_DOMAIN.md`** — header *"**Status:** EXPERIMENTAL — not normative"*, line 74:

> The `0x02` domain byte is experimental and MUST NOT be treated as normative until DQ-003 closes.

and, in its own Purpose section:

> This document does **not** amend APS-200. It is an isolated DQ-003 experiment. **Any rule that differs from or extends APS-200** remains provisional until DQ-003 closes and the corresponding normative specification change is approved.

**`conformance/dq-003/DQ-003_AUDIT_RECORD_HASH_DOMAIN.md`** — header *"**Status:** EXPERIMENTAL / NOT NORMATIVE"*:

> `0x02` is an **experimental domain-separation octet only**. It has no normative status until DQ-003 is accepted.

and:

> The specification does not presently provide the exact hash equation for that field.

### 3.2 The five determinations

**1. Which artifact has higher normative authority?**
APS-200 — rank 2 — outranks both DQ-003 documents, which are rank 5 or below and are self-labelled non-normative. Under the precedence rule they cannot override it.

**2. Is the DQ-003 wording a transitional governance clause or an actual prohibition?**
**Transitional, and self-limiting by its own terms.** The first document scopes its provisionality precisely: *"Any rule that **differs from or extends APS-200** remains provisional."* Once APS-200 itself carries `0x02 ‖ JCS(R_AR)`, the rule no longer differs from or extends APS-200, and the clause no longer reaches it. The second document's premise — *"The specification does not presently provide the exact hash equation"* — is a **factual statement about the specification at the time of writing**, not a prohibition.

**3. Does APS-200 already establish `0x02` normatively?**
**Yes**, three times over: §5.1 gives the preimage equation and the one-raw-octet constraint with MUST NOT language; §5.1 states the exclusion rationale; and the P0-2 FROZEN matrix §8 records the domain table `0x00 → Merkle leaf · 0x01 → Merkle interior · 0x02 → Audit Record hash`.

**4. Chronology — the decisive evidence.** Branch commit order, oldest first (`git log --reverse origin/main..HEAD`):

| Order | Commit | Effect |
|---:|---|---|
| 1 | `9b5c262` | adds `conformance/dq-003/…` — *"EXPERIMENTAL / NOT NORMATIVE"*, *"the specification does not presently provide the exact hash equation"* |
| 4 | `7bc722f` | adds `conformance/DQ-003_AUDIT_RECORD_HASH_DOMAIN.md` — *"EXPERIMENTAL — not normative"* |
| 11 | **`8d3f1fe`** | **`spec(aps-200): define ENT-007 audit record hash dependency`** — introduces `0x02 ‖ JCS(R_AR)` into APS-200 (`git log -S'0x02 \|\| JCS(R_AR)'` returns this commit and only this commit) |

Both "experimental" statements were written **before** APS-200 acquired the construction. They describe a superseded state of the corpus. The second document's premise became false at `8d3f1fe`.

**5. Can DQ-003 remain OPEN while the Golden Fixture uses `0x02`?**
**Yes.** DQ-003's open status tracks *conformance of the implementations*, not the normative status of the hash domain. APS-200 §5.1 is in force independently. The fixture applies the APS-200 construction and derives correctly (`DQ-003-ENTRY-POINT-EXECUTION.md` §A.4, self-verification PASS). Nothing about an open DQ-003 suspends a rank-2 specification clause.

### 3.3 Closure

**G-2 = CLOSED.** Authority, self-limiting scope, and chronology all point the same way: APS-200 §5.1 governs and `0x02` is normative. No hash semantics changed; the octet, its position, and its encoding are identical in every artifact — only the governance label differed.

A residual **editorial** contradiction remains in two stale documents. It does not require a Custodian *decision*, only a correction, supplied in §10 as **PROPOSED — NOT APPLIED**.

---

## 4. G-3 — Event-type registry vs Golden Fixture → **BLOCKED**

### 4.1 The conflict

`aps/APS-200_CANONICAL_DATA_MODEL.md:174` (rank 2) delegates the vocabulary:

> `` `event_type` `` | string | MUST | Canonical event type; **normative vocabulary is governed by `aps/EVENT_TYPE_REGISTRY.md`**

`aps/EVENT_TYPE_REGISTRY.md` §5:

> **No individual event token is promoted to final normative status by this document yet.**
> … Until entries are registered, strict conformance implementations MUST reject an `event_type` value that is not present in an approved versioned registry.

§3: `unknown token → REJECT in strict conformance mode`.

`conformance/DQ-003-AUDIT-CHAIN-001.json` uses `"event_type": "AUDIT_DECISION"` in both records. `grep -rn AUDIT_DECISION` across the specification corpus returns **no hit outside the fixture**. The token is unregistered.

### 4.2 The nine determinations

| # | Question | Determination |
|---:|---|---|
| 1 | Is `AUDIT_DECISION` intended to be a valid normative event type? | **Cannot be determined from the corpus.** No artifact registers, describes, or reserves it. Answering requires a Custodian decision, not analysis. |
| 2 | If yes, where must it be registered? | `aps/EVENT_TYPE_REGISTRY.md` §5, as a §4 event-definition record (all seven properties required). |
| 3 | Is the registry authoritative for ENT-007? | **Yes** — APS-200 §5 ENT-007 delegates the vocabulary to it by name, so it inherits rank-2 authority for this field. |
| 4 | Does registration affect hash bytes? | **No.** `event_type` enters `R_AR` and `R_I` as its literal UTF-8 string. Registry §7 confirms: *"The token's canonical byte representation is therefore the UTF-8 encoding of the exact registered token after validation; no case folding, whitespace normalization or alias expansion is permitted."* Registration validates a token; it never rewrites it. |
| 5 | Does registration affect only verification acceptance? | **Yes** — exactly and only acceptance. |
| 6 | Is the fixture supposed to be accepted in strict mode? | **Unresolvable from the corpus.** The fixture declares `status: GOLDEN-FIXTURE` and `self_verification: PASS`, which asserts derivational correctness; nothing states it must also pass registry validation. |
| 7 | Does APS-200 require registry validation? | **Yes, by delegation** (§5 ENT-007). Note APS-200 itself never uses the phrase "strict conformance mode" — that mode is defined only in the registry. |
| 8 | Is an error code required for an unregistered event type? | **Yes, and none exists.** APS-200 §5.7's fourteen codes contain no `event_type` vocabulary code. `E_PAYLOAD_SCHEMA` covers payload-schema violations, not envelope vocabulary; using it would misreport the condition. |
| 9 | Does the missing code make verification semantics incomplete? | **Yes.** §5.7 requires a stable machine-readable code for the first applicable failure. A strict verifier can detect this failure but cannot report it conformantly. |

### 4.3 Cryptographic validity vs normative acceptance

| Dimension | Result | Evidence |
|---|---|---|
| **Cryptographic validity** | **VALID** — all six digests and both canonical preimages derive uniquely and were independently reproduced byte-for-byte | `DQ-003-ENTRY-POINT-EXECUTION.md` §A.4, exit 0 |
| **Normative acceptance (strict mode)** | **REJECTED** — `AUDIT_DECISION` is not in an approved versioned registry | `EVENT_TYPE_REGISTRY.md` §3, §5 |

The Golden Fixture is cryptographically sound and normatively unacceptable **at the same time**. That is the conflict, and it is not resolvable by computation.

### 4.4 This is a pre-existing, already-registered conflict

It is not new to DQ-003. `ck003/handover-assessment/04_CONFLICT_REGISTER.md` §CFL-005 — *"The event-type registry rejects the object in the closed fixture"*, **Verdict: CONFLICT** — logs the same defect, and `ck003/dq-006-closure/DQ-006_SPECIFICATION_CONSISTENCY_SCAN.md` row 28 records it as *"Reported, not repaired — CFL-005. DQ-004 governs."*

It also reaches `main`: the CANONICAL-001 reference vector in `origin/main` APS-200 §8 uses `"event_type":"AUDIT_RECORD"` — likewise unregistered. **The registry currently rejects the specification's own reference vector.**

### 4.5 Blocking

**G-3 = BLOCKED — explicit Custodian amendment required.**

Closure requires modifying a **rank-2 normative artifact** (`aps/EVENT_TYPE_REGISTRY.md`, and possibly APS-200 §5.7). This branch mandate permits documentation and conformance reporting only, not normative-artifact modification. The proposed registry entry and error code are supplied in §10 as **PROPOSED — NOT APPLIED**.

The fixture was **not** modified. Modifying a Golden Fixture to satisfy a registry would invert the authority relationship and is explicitly forbidden.

---

## 5. G-6 — §5.2 dependency-diagram contradiction → **CLOSED**

### 5.1 The three texts, verbatim

**The diagram** (APS-200 §5.2, introduced by *"The dependency is intentionally one-directional:"*):

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

**Rule 4** (APS-200 §5.2, immediately below the diagram):

> 4. `previous_record_hash` MUST refer to the preceding record's `audit_record_hash`, **not its `integrity_hash`**.

**§5.3** (APS-200):

> For a non-genesis record `R[n]`:
> ```text
> R[n].previous_record_hash = R[n-1].audit_record_hash
> ```

A fourth statement agrees — §5.4: *"`previous_record_hash` — from the predecessor's `audit_record_hash`, except for genesis."*

### 5.2 The eight determinations

| # | Question | Determination |
|---:|---|---|
| 1 | Exact conflicting diagram wording | the final arrow `integrity_hash → next.previous_record_hash`, quoted above |
| 2 | Exact rule 4 wording | quoted above — explicitly excludes `integrity_hash` |
| 3 | Exact §5.3 wording | quoted above — an equation naming `audit_record_hash` |
| 4 | Which representation is authoritative? | **The prose and the equation.** Three normative statements (§5.2 rule 4, §5.3 equation, §5.4 derived-field rule) against one arrow in an illustrative figure |
| 5 | Is the diagram stale / non-normative? | **Non-normative.** It is introduced as an illustration of one-directionality, carries no MUST, and its caption makes no linkage claim. Its final arrow is simply drawn wrong |
| 6 | Does any implementation rely on it? | **No.** RI-RS links `prev_hash → chain_hash` in its own unrelated domain; RI-PY has no chain at all; the Golden Fixture follows `audit_record_hash` (`record-001.previous_record_hash` = `cbbc5104…689e79` = `record-000.audit_record_hash`) |
| 7 | Can the contradiction affect implementation? | **Yes, prospectively.** An implementer reading the figure before the rules could wire `previous_record_hash` to `integrity_hash`, producing a chain that fails the fixture at record-001. This is why the correction is required even though the semantics are settled |
| 8 | Is the fixture consistent with the intended rule? | **Yes**, verified byte-for-byte |

### 5.3 Normative conclusion

The authoritative contract supports, and this gate therefore states:

```text
previous_record_hash[n+1] = audit_record_hash[n]
```

`integrity_hash` and `audit_record_hash` are **not** equated. `chain_hash` is **not** renamed and remains RI-RS implementation terminology with no normative standing.

### 5.4 Closure

**G-6 = CLOSED.** The contradiction is intra-document and resolves under the artifact's own hierarchy — normative prose and an explicit equation outrank an illustrative figure — so no Custodian *decision* is needed. The figure must still be corrected; the correction is in §10 as **PROPOSED — NOT APPLIED**.

---

## 6. G-1 — dangling §8 reference → **BLOCKED** (escalated)

### 6.1 Every occurrence

`grep -n "§8" aps/APS-200_CANONICAL_DATA_MODEL.md` returns exactly two:

| Line | Text |
|---:|---|
| 58 | `integrity_hash` … *"`SHA-256(canonical_bytes(object))` of this object, excluding `integrity_hash` itself. **Canonical bytes are defined by §8.**"* |
| 189 | *"The canonical bytes MUST be produced using the **RFC 8785 JCS profile defined in §8**."* |

`grep "^## "` on the branch returns §1–§5 only. **There is no §8.**

### 6.2 Root cause — a deletion, not a typo

This is the finding that changed most against C3's provisional read.

| Section | `origin/main` | branch |
|---|---|---|
| §6 Relationships | present (line 180) | **DELETED** |
| §7 Validation Rules | present (line 202) | **DELETED** |
| **§8 Serialization Requirements** | present (line 213) | **DELETED** |
| §8 CANONICAL-001 reference vector | present | **DELETED** |
| §9 JSON Schema | present (line 272) | **DELETED** |
| §10 Traceability | present (line 280) | **DELETED** |
| §4.1, §5.1–§5.7 | absent | added |

`git log -S'## 8. Serialization Requirements' -- aps/APS-200_CANONICAL_DATA_MODEL.md` identifies branch commit **`bf33eb4` — `spec(dq-003): define EP-001 event payload contract`** as the removal. That commit added the EP-001 and ENT-007 hash contracts and, in the same edit, dropped five sections it did not replace, while leaving both references to §8 live.

### 6.3 The four determinations

**1. Every occurrence** — two, listed above.

**2. Is RFC 8785 independently named at the same normative site?**
**Line 189: yes** — *"the RFC 8785 JCS profile"* names the algorithm inline, so the pointer is redundant for byte determination. **Line 58: no** — it says only *"Canonical bytes are defined by §8"*, with no inline algorithm. On this branch, line 58's definition of canonical bytes for **every entity's `integrity_hash`** points at nothing.

**3. Does the missing §8 create semantic ambiguity?**
**For ENT-007 — no.** Three independent sources determine the same bytes: §5.1 names RFC 8785 inline; §5.5 mandates *"RFC 8785 JSON Canonicalization Scheme (JCS), encoded as UTF-8"*; the FROZEN P0-2 matrix §7 restates it. Cross-checked against `main`'s §8, which mandates *"implementations MUST use RFC 8785 JSON Canonicalization Scheme (JCS)"* with *"the canonical serialization boundary is the UTF-8 byte sequence emitted by the JCS profile"* — **no deviation from plain RFC 8785.** C3's conclusion holds unchanged.
**For the corpus as a whole — yes.** Line 58 governs `integrity_hash` for **all** entities ENT-001 … ENT-008, not just ENT-007. For every entity without an ENT-007-style §5.x contract, canonical bytes are now undefined on this branch.

**4. Is it a broken normative cross-reference?**
**It is worse: a normative content regression.** Merging this branch would delete the Serialization Requirements, the CANONICAL-001 reference vector, the Validation Rules, the JSON Schema section, and Traceability from the protocol specification.

### 6.4 Blocking

**G-1 = BLOCKED.** Not because ENT-007's bytes are ambiguous — they are not — but because the branch cannot merge without silently removing rank-2 normative content. Correction is in §10 as **PROPOSED — NOT APPLIED**.

---

## 7. G-5 — undefined "session" → **OPEN NON-BLOCKING**

### 7.1 The seven determinations

**1. Where does "session" appear?** Exactly three times, all in APS-200, all as usage rather than definition:

| Line | Text |
|---:|---|
| 175 | `sequence_number` … *"Monotonically increasing sequence number **within a session**"* |
| 253 | *"The first Audit Record **in a session** MUST have `sequence_number = 0`. Subsequent records MUST increase monotonically by one within that session."* |
| 384 | `E_SEQUENCE_INVALID` — *"Sequence number violates **session** ordering"* |

**2. Does APS-200 define session semantics?** **No.** No definition in APS-200, APS-000 (Foundation & Terminology), APS-100, or `glossary/GLOSSARY.md` — `grep -rn -i session aps/ glossary/ invariants/` returns only the three usages above.

**3. Do genesis semantics depend on session identity?** **No.** §5.3 identifies genesis by two **self-contained per-record properties**: `previous_record_hash == 0`×64 and `sequence_number == 0`. Neither requires knowing where a session begins.

**4. Is `sequence_number = 0` sufficient to establish genesis?** In combination with the zero sentinel, **yes** for a supplied chain. What a session definition would add is the ability to reject a *legitimately formed* genesis record appearing where a session boundary does not exist — a scope question, not an identification question.

**5. Does session affect any hash preimage?** **No.** `sequence_number`'s value is supplied by the record and serialized into `R_AR` and `R_I` as an RFC 8785 number. The session concept never enters a preimage.

**6. Does the Golden Fixture need additional session semantics?** **No.** It is a single frozen two-record chain, `sequence_number` 0 then 1, verified in supplied order; the chain is its own scope.

**7. Hash-bearing or verification/governance gap?** **Verification/governance, explicitly non-hash-bearing.**

### 7.2 Classification

**G-5 = OPEN NON-BLOCKING.** A real normative gap that will matter for multi-session or concurrent-chain verification and for making `E_SEQUENCE_INVALID` precisely testable. It affects **no** current hash byte and does **not** block DQ-003 replay. **No session model was invented here.**

### 7.3 Re-confirmation of C3's hash finding

Cross-checking `main`'s §8 against the branch's §5.1/§5.5 and P0-2 §7 (§6.3 above) found no divergence in canonical-byte semantics. **C3's "hash-bearing ambiguities = 0" stands, now verified against the fuller specification text that this branch had removed.** No closed hash semantics were reopened.

---

## 8. G-9 — Unicode normalization → **CLOSED**

### 8.1 The seven determinations

| # | Question | Determination |
|---:|---|---|
| 1 | Does RFC 8785 require Unicode normalization? | **No.** RFC 8785 sorts member names by UTF-16 code units (§3.2.3) and escapes strings per ECMAScript (§3.2.2.2). It defines no NFC/NFD/NFKC/NFKD step. |
| 2 | Does Aura impose additional normalization? | **No — it prohibits it.** APS-200 §5.5, line 296: *"Implementations MUST NOT perform locale-dependent transcoding or **normalization outside the JCS processing defined by RFC 8785**."* |
| 3 | Does C2-1 normalize member names or values? | **No.** `validate_event_payload` compares member names by exact `String` equality and performs no transformation. |
| 4 | Does the current JCS implementation normalize? | **No.** `serde_json_canonicalizer =0.3.2`, C1-verified 9/9 against RFC vectors including the discriminating UTF-16 ordering case; no normalization step exists in `src/canonical.rs`. |
| 5 | Does any Aura artifact require NFC/NFD/NFKC/NFKD? | **No.** `grep -rn -i "NFC\|NFD\|NFKC\|NFKD\|unicode normal" aps/ conformance/` returns **zero** hits. |
| 6 | Could normalization alter hash-participating bytes? | **Yes — which is precisely why §5.5 forbids it.** Applying NFC to a member name would change `JCS(P)` and therefore `event_payload_hash`. The prohibition is what keeps the bytes stable. |
| 7 | Inside or outside the frozen ENT-007 domain? | **Fully covered.** ENT-007 envelope member names are eleven fixed ASCII literals, where normalization is a no-op. The only free-form names are Event Payload members, and §5.5 governs exactly those. |

### 8.2 Closure

**G-9 = CLOSED.** The specification already answers it. The correct and only conformant reading:

> **No normalization beyond RFC 8785 is permitted. Member-name comparison is exact. RFC 8785 behavior is authoritative.**

No NFC was invented, no NFD was invented, and C2-1 was not modified. C2-1's exact-string-equality duplicate detection is **confirmed correct against APS-200 §5.5**, not merely tolerated.

**Correction to C3.** C3 classified this "AMBIGUOUS / potentially hash-bearing." That was wrong: APS-200 §5.5 line 296 settles it, and this gate located the sentence. The `C2-1-TBD-UNICODE-NORMALIZATION` marker in `src/event_payload.rs` is now **stale** — its removal is proposed in §10, not applied.

---

## 9. Closure matrix

| Finding | Authority | Contradiction | Hash-bearing? | Verification-bearing? | Fixture impact | Required action | Custodian decision | Status |
|---|---|---|---|---|---|---|---|---|
| **G-2** `0x02` status | APS-200 §5.1 (r2) vs two EXPERIMENTAL docs (r5-) | governance label only; identical octet, position, encoding | **NO** | NO | none — fixture derives correctly | editorial supersession banners | **NOT required** — resolved by precedence + chronology | **CLOSED** |
| **G-3** event-type registry | APS-200 §5 ENT-007 (r2) delegating to EVENT_TYPE_REGISTRY (r2) vs fixture | vocabulary empty; `AUDIT_DECISION` unregistered | **NO** — registry validates, never rewrites the token | **YES** — strict mode must reject; no error code exists | **cryptographically VALID, normatively REJECTED** | register the token (or exempt the profile) **and** add an error code | **REQUIRED** — rank-2 artifact change | **BLOCKED** |
| **G-6** §5.2 diagram | APS-200 §5.2 figure vs §5.2 rule 4, §5.3, §5.4 (all r2) | intra-document; figure contradicts three normative statements | **NO** | prospectively — could misdirect an implementer | none — fixture follows the correct rule | correct the final arrow | **NOT required** — prose outranks illustration | **CLOSED** |
| **G-1** dangling §8 | APS-200 §4 line 58, §5.1 line 189 (r2) | §6–§10 deleted by `bf33eb4`; two live references to a deleted section | **NO** for ENT-007 (three independent sources agree; `main` §8 confirms plain RFC 8785) | **YES** — line 58 leaves canonical bytes undefined for all non-ENT-007 entities | none | restore §6–§10 before merge, or renumber and retarget both references | **REQUIRED** — rank-2 content restoration | **BLOCKED** |
| **G-5** "session" | APS-200 lines 175, 253, 384 (r2); undefined in APS-000 and glossary | usage without definition | **NO** | YES for multi-session scope; `E_SEQUENCE_INVALID` untestable | none — 2-record chain is its own scope | define "session" in APS-000 | deferred — not blocking | **OPEN NON-BLOCKING** |
| **G-9** normalization | APS-200 §5.5 line 296 (r2) | none — C3 had not located the governing sentence | **NO** — the prohibition is what keeps bytes stable | NO | none | remove the stale TBD marker | **NOT required** | **CLOSED** |

---

## 10. Proposed amendments — **PROPOSED — NOT APPLIED**

None of the following has been applied. No normative artifact was modified by this gate.

### A-1 — restore APS-200 §6–§10 *(closes G-1; MERGE-BLOCKING)*

> **PROPOSED — NOT APPLIED.** Before `dq/dq-003-audit-record-hash-domain` merges to `main`, restore `## 6. Relationships`, `## 7. Validation Rules`, `## 8. Serialization Requirements` (including the CANONICAL-001 reference vector), `## 9. JSON Schema`, and `## 10. Traceability` from `origin/main`, placed after the new §5.7. The two references at lines 58 and 189 then resolve correctly and no further edit is needed.
>
> If instead the Custodian intends the branch's five-section structure to be final, both references MUST be retargeted in the same change — line 58 to a section that actually defines canonical bytes, and line 189 likewise — and the deletion of §7, §9 and §10 MUST be recorded as a deliberate normative removal with impact analysis. **Silent deletion is not an acceptable outcome either way.**

### A-2 — register `AUDIT_DECISION` *(closes G-3; requires a Custodian decision first)*

> **PROPOSED — NOT APPLIED.** Only if the Custodian determines `AUDIT_DECISION` is intended to be normative. Add to `aps/EVENT_TYPE_REGISTRY.md` §5, using the §4 event-definition record:
>
> | Property | Value |
> |---|---|
> | `event_type` | `AUDIT_DECISION` |
> | `description` | *Custodian to supply — the normative semantic meaning* |
> | `producer` | *Custodian to supply* |
> | `payload_schema` | *Custodian to supply — currently undeclared, so §5.5 step 5 is a no-op* |
> | `introduced_protocol_version` | `1.0` |
> | `deprecated` | `false` |
> | `replacement` | n/a |
>
> The token already satisfies §2's syntax contract (`^[A-Z][A-Z0-9_]*$`, ASCII, no whitespace, no alias). **The three italicised properties are Custodian content and are deliberately left blank — this gate does not invent event semantics.**
>
> `AUDIT_RECORD`, used by the CANONICAL-001 reference vector in `main`'s §8, is unregistered on the same grounds and should be resolved in the same change (CFL-005).

### A-3 — add an error code for unregistered `event_type` *(closes the §5.7 gap in G-3)*

> **PROPOSED — NOT APPLIED.** Add one row to APS-200 §5.7 and to P0-2 §11:
>
> | Code | Condition |
> |---|---|
> | `E_EVENT_TYPE_UNREGISTERED` | `event_type` is not present in the approved versioned event-type registry |
>
> Name is a placeholder for Custodian approval. Without it a strict verifier can detect the condition but cannot report it conformantly.

### A-4 — correct the §5.2 dependency diagram *(closes the G-6 editorial defect)*

> **PROPOSED — NOT APPLIED.** Replace the figure in APS-200 §5.2 with one whose linkage arrow matches rule 4 and §5.3:
>
> ```text
> ENT-007 source fields
>         │
>         ├───────────────┐
>         ▼               ▼
>  event_payload_hash  audit_record_hash
>                          │
>                          ├──────────────► next.previous_record_hash
>                          ▼
>                   integrity_hash
>                     (terminal)
> ```
>
> This keeps the section's point — one-directionality, no cycle — while showing the chain link leaving `audit_record_hash`, and marks `integrity_hash` terminal as §5.2 rule 4 requires.

### A-5 — supersede the stale DQ-003 experimental documents *(closes the G-2 editorial residue)*

> **PROPOSED — NOT APPLIED.** Add to the top of both `conformance/DQ-003_AUDIT_RECORD_HASH_DOMAIN.md` and `conformance/dq-003/DQ-003_AUDIT_RECORD_HASH_DOMAIN.md`:
>
> > **SUPERSEDED IN PART.** The `0x02` Audit Record domain separator was promoted to normative status by APS-200 §5.1 in commit `8d3f1fe`, after this document was written. The "experimental / not normative" language above applies to the state of the corpus before that commit and no longer governs `0x02`. APS-200 §5.1 is authoritative. This document's remaining experimental content is retained as the historical record.
>
> Additionally, the sentence *"The specification does not presently provide the exact hash equation for that field"* in `conformance/dq-003/…` is now factually false and should be struck or dated.

### A-6 — define "session" *(closes G-5; not blocking)*

> **PROPOSED — NOT APPLIED.** Add a definition to `aps/APS-000_FOUNDATION_AND_TERMINOLOGY.md` and `glossary/GLOSSARY.md` establishing the scope within which `sequence_number` is monotonic and within which exactly one genesis record exists. **This gate deliberately supplies no candidate wording** — the session model is a protocol design decision, not an editorial fix.

### A-7 — remove the stale TBD marker *(closes the G-9 residue)*

> **PROPOSED — NOT APPLIED.** The `C2-1-TBD-UNICODE-NORMALIZATION` note in `src/event_payload.rs` and in `C2-1-EVENT-PAYLOAD-INPUT-CONTRACT.md` §K.6 states the question is unspecified. APS-200 §5.5 line 296 specifies it. Replace the note with a citation to §5.5 confirming that exact comparison is mandated and no normalization is permitted. **`src/` was not modified by this gate.**

---

## 11. Hash-contract preservation statement

Nothing in this gate changed, reinterpreted, or reopened any hash-bearing semantics. Explicitly preserved, byte for byte:

| Construct | Value | Unchanged |
|---|---|---|
| `event_payload_hash` | `SHA-256(JCS(P))`, no domain separator | ✓ |
| `audit_record_hash` | `SHA-256(0x02 ‖ JCS(R_AR))`, one raw octet | ✓ |
| `integrity_hash` | `SHA-256(JCS(R_I))` | ✓ |
| `previous_record_hash` | `= R[n-1].audit_record_hash`; genesis `0`×64 = 32 zero bytes, 64 lowercase hex | ✓ |
| `R_AR` | ENT-007 less `audit_record_hash`, `integrity_hash` — 9 members | ✓ |
| `R_I` | ENT-007 less `integrity_hash` — 10 members | ✓ |
| Canonicalization | RFC 8785 JCS, UTF-8, no additional normalization | ✓ |
| Digest representation | 64 lowercase hexadecimal ASCII | ✓ |
| Domain separation | `0x00` Merkle leaf · `0x01` Merkle interior · `0x02` Audit Record | ✓ |

- The Golden Fixture was **not** modified, regenerated, or reinterpreted.
- `0x02` was **not** changed.
- `chain_hash` was **not** renamed and is **not** equated with `audit_record_hash`.
- `integrity_hash` is **not** equated with `audit_record_hash`.
- No normative meaning was inferred from RI-RS or RI-PY.
- C3's finding of **0 hash-bearing ambiguities** is re-confirmed, and additionally cross-checked against `origin/main` APS-200 §8, which mandates plain RFC 8785 with no deviation.

---

## 12. C4 readiness determination

```
C4 = NOT AUTHORIZED
```

Two blocking findings stand:

| Blocker | Why it blocks C4 |
|---|---|
| **G-1** | ENT-007 implementation would be written against an APS-200 revision that has silently dropped its own Serialization Requirements, Validation Rules, JSON Schema and Traceability sections, while two normative references point at the deleted §8. The specification must be whole before it is implemented against. |
| **G-3** | A C4 implementation would necessarily include §5.7 error reporting and event-type validation. Today those cannot be built correctly: the registry rejects the Golden Fixture, and no error code exists for that rejection. Building anyway would force the implementer to invent either a vocabulary or an error code — exactly what the governance principle forbids. |

Not blocking, and safe to carry into C4: **G-5** (non-hash-bearing scope gap), plus the closed findings **G-2**, **G-6**, **G-9**.

**Readiness once G-1 and G-3 close:** the hash contract itself needs nothing further. C3 established 0 hash-bearing ambiguities and complete Golden Fixture derivation; this gate re-confirmed both. The C4 hand-off requirements in `C3-ENT-007-COMPOSITION-GATE.md` §17 remain valid and unmodified.

---

## 13. Remaining Custodian decisions

In priority order. Each is a decision this gate is not authorized to make.

| # | Decision | Finding | Blocking C4? |
|---:|---|---|:---:|
| 1 | Restore APS-200 §6–§10, or ratify the five-section structure and retarget both §8 references with a recorded impact analysis | G-1 / A-1 | **YES** |
| 2 | Is `AUDIT_DECISION` a normative event type? If yes, supply `description`, `producer`, `payload_schema` and register it; if no, state how the Golden Fixture is to be verified | G-3 / A-2 | **YES** |
| 3 | Approve an error code for unregistered `event_type` (`E_EVENT_TYPE_UNREGISTERED` proposed) | G-3 / A-3 | **YES** |
| 4 | Resolve CFL-005 corpus-wide, including `AUDIT_RECORD` in `main`'s CANONICAL-001 reference vector | G-3 | **YES** (same decision) |
| 5 | Reconcile the error-code selection rule: APS-200 §5.7 *"most specific applicable"* vs P0-2 §9/§11 *"first applicable"* (C3 G-7) | G-7 | no |
| 6 | Apply the diagram correction A-4 | G-6 | no |
| 7 | Apply the supersession banners A-5 | G-2 | no |
| 8 | Define "session" in APS-000 and the glossary | G-5 / A-6 | no |
| 9 | Retire or rename the two non-authoritative `DQ-003-AUDIT-CHAIN-001.json` files (C3 G-4) | G-4 | no |
| 10 | Align genesis indexing notation in the DQ-003 working documents (C3 G-8) | G-8 | no |
| 11 | Remove the stale `C2-1-TBD-UNICODE-NORMALIZATION` marker | G-9 / A-7 | no |

**DQ-003 remains OPEN.** This gate closes no defect in an implementation and authorizes no implementation work.

---

## 14. Git discipline

| Item | Value |
|---|---|
| Branch | `claude/dq-003-conformance-audit-4ok63x` (session-mandated) |
| Intended branch | `c1/full-domain-jcs` (PR #60) |
| Base SHA | `aebbbe04287993ea303366cf8c453bf721d250cc` |
| HEAD before this gate | `f51fa68ad157be35891a373ffb1033bee84f9112` |
| Files changed | **exactly one — this file (new)** |
| `src/`, `Cargo.toml`, `Cargo.lock`, C1/C2-1 corpora, `tests/` | unmodified |
| APS-200, Golden Fixture, EVENT_TYPE_REGISTRY, P0-2 matrix, RI-PY | unmodified |
| Merge / rebase / force-push | none |
| Fast-forward to intended branch | possible — `git push origin claude/dq-003-conformance-audit-4ok63x:c1/full-domain-jcs` |

Branch conflict reported, not auto-resolved.
