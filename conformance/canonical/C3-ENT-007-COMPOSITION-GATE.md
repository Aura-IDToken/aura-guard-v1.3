# C3 — ENT-007 Composition Contract Gate

**Mode:** READ-ONLY / SPECIFICATION-FIRST. No implementation, no `src/` change, no ENT-007 type, no hash function, no adapter.
**Question:** is the frozen P0-2 / DQ-003 contract precise enough to define the ENT-007 composition surface without ambiguity?

---

## 1. Executive verdict

```
C3 = CONDITIONAL PASS
```

**Every byte** participating in `event_payload_hash`, `audit_record_hash`, `integrity_hash`, and `previous_record_hash` is uniquely determined by the frozen contract. **Hash-bearing byte ambiguities: 0.** The Golden Fixture's six digests and six canonical preimages are derivable from APS-200 alone, and were independently reproduced byte-for-byte (`DQ-003-ENTRY-POINT-EXECUTION.md` §A.4).

It is **not** a full PASS. Nine defects remain in the corpus. None of them changes a preimage byte; all of them are normative-status, vocabulary, cross-reference, or verification-acceptance gaps. Two are severe enough that an implementer will hit them immediately:

- **G-2** — `0x02` is normative in APS-200 §5.1 but labelled *"EXPERIMENTAL / NOT NORMATIVE until DQ-003 closes"* in two DQ-003 documents. Same octet either way; the conflict is about whether the contract is in force.
- **G-3** — the event-type registry contains **zero** registered tokens, and the Golden Fixture's `AUDIT_DECISION` is unregistered. A strict-conformance verifier **must reject both fixture records**, even though their hashes derive correctly.

Derivation is complete. Strict-mode *acceptance* of the fixture is not, and that is a Custodian decision, not an implementation one.

Per repository governance, these conflicts are **reported, not reconciled**. No ambiguity was resolved by preferring the implementation that happens to exist.

---

## 2. Source inventory

| Source | Authority rank | Status | Used for |
|---|---|---|---|
| `aps/APS-200_CANONICAL_DATA_MODEL.md` §4, §4.1, §5 ENT-007, §5.1–§5.7 | 2 — Protocol Specification | normative | primary contract for all four hashes |
| `aps/APS-100_PROTOCOL_INVARIANTS.md` | 3 — Protocol Invariants | normative | INV-003 canonical serialization, INV-011 cryptographic integrity, INV-015 canonical identity |
| `aps/EVENT_TYPE_REGISTRY.md` | delegated by APS-200 §5 ENT-007 | **DRAFT — 0 tokens registered** | `event_type` vocabulary — **G-3** |
| `conformance/P0-2_AUDIT_RECORD_FIELD_BY_FIELD_MATRIX.md` | 5 — Conformance Requirements | **FROZEN** | field-by-field inclusion/exclusion, verification order, error codes |
| `conformance/DQ-003-AUDIT-CHAIN-001.json` | Golden Fixture | **GOLDEN-FIXTURE**, self-verification PASS | derivation target |
| `conformance/DQ-003-ENTRY-POINT-EXECUTION.md` | evidence | — | independent fixture re-derivation; RI-PY / RI-RS execution results |
| `conformance/DQ-003-ENTRY-POINT-BASELINE.md` | evidence | — | pre-execution entry-point baseline |
| `conformance/DQ-003_AUDIT_RECORD_HASH_DOMAIN.md` | working doc | says `0x02` **experimental** | **G-2** |
| `conformance/dq-003/DQ-003_AUDIT_RECORD_HASH_DOMAIN.md` | working doc | **EXPERIMENTAL / NOT NORMATIVE** | **G-2** |
| `conformance/canonical/C1-FULL-DOMAIN-JCS.md` | evidence | **PASS** 9/9 | RFC 8785 capability, now production |
| `conformance/canonical/C2-INPUT-IJSON-BOUNDARY.md` | evidence | PROMOTION BLOCKED → resolved | input-boundary gap analysis |
| `conformance/canonical/C2-1-EVENT-PAYLOAD-INPUT-CONTRACT.md` | 5 — Conformance Requirements | **PASS** 17/17 | EP-BOUNDARY-001 |
| `conformance/canonical/C2-1-PRODUCTION-PROMOTION.md` | evidence | PROMOTED | production reachability of the input boundary and JCS |
| `src/chain.rs`, `src/crypto.rs`, `src/merkle.rs`, `src/models.rs` (RI-RS) | 9 — existing implementation | read-only | comparison only |
| `compliance/certificate.py`, `audit/`, `core/` (RI-PY) | 9 — existing implementation | read-only | comparison only |

Nothing was inferred from implementation. Where the specification is silent, this report records a gap rather than adopting RI-RS or RI-PY behavior.

---

## 3. ENT-007 field matrix

ENT-007 = Common Object Contract (§4) + five ENT-007 fields (§5 ENT-007). **All eleven fields are MUST. There are no optional fields**, so no "absent optional field" representation question arises.

`R_AR` *is* the `audit_record_hash` preimage object and `R_I` *is* the `integrity_hash` preimage object, so the "IN R_AR? / IN audit_record_hash?" and "IN R_I? / IN integrity_hash?" column pairs are definitionally identical; both are shown as required.

| FIELD | TYPE | REQ | SOURCE | CANONICAL REPRESENTATION | IN R_AR? | IN R_I? | IN event_payload_hash? | IN audit_record_hash? | IN integrity_hash? | DERIVED? | GENESIS BEHAVIOR | VERIFICATION RULE | STATUS |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `object_id` | string | MUST | APS-200 §4 | JCS string; UUID v4 or canonical format | YES | YES | NO — outside payload | YES | YES | NO | ordinary | exact canonical value | **EXACT** |
| `object_type` | string | MUST | APS-200 §4 | JCS string; APS-000 canonical type name | YES | YES | NO — outside payload | YES | YES | NO | ordinary | exact canonical value | **EXACT** |
| `protocol_version` | string | MUST | APS-200 §4 | JCS string | YES | YES | NO — outside payload | YES | YES | NO | ordinary | exact canonical value | **EXACT** |
| `schema_version` | string | MUST | APS-200 §4 | JCS string | YES | YES | NO — outside payload | YES | YES | NO | ordinary | exact canonical value | **EXACT** |
| `created_at` | string | MUST | APS-200 §4 | JCS string, ISO 8601 UTC | YES | YES | NO — outside payload | YES | YES | NO | ordinary | exact canonical value | **EXACT** |
| `event_type` | string | MUST | APS-200 §5 ENT-007 | JCS string; UTF-8, ASCII token `^[A-Z][A-Z0-9_]*$` | YES | YES | NO — excluded by EP-001 | YES | YES | NO | ordinary | registry membership **+** exact canonical value | **AMBIGUOUS** — bytes exact, vocabulary empty (**G-3**) |
| `sequence_number` | integer | MUST | APS-200 §5 ENT-007 | JCS number (RFC 8785 §3.2.2.3) | YES | YES | NO | YES | YES | NO | MUST be `0` for first record | monotonic `+1` within a session | **AMBIGUOUS** — bytes exact, "session" undefined (**G-5**) |
| `previous_record_hash` | string | MUST | APS-200 §5.3 | JCS string; 64 lowercase hex (§4.1) | YES | YES | NO | YES | YES | YES — verifier-linked | `0`×64 sentinel = 32 zero bytes | `== R[n-1].audit_record_hash`, except genesis | **EXACT** |
| `event_payload_hash` | string | MUST | APS-200 §5.5 | JCS string; 64 lowercase hex (§4.1) | YES | YES | NO — it *is* the commitment | YES | YES | YES | ordinary; payload hash still required | recompute `SHA-256(JCS(P))` | **EXACT** |
| `audit_record_hash` | string | MUST | APS-200 §5.1 | JCS string; 64 lowercase hex (§4.1) | **NO — self-excluded** | YES | NO | **NO — self** | YES | YES | derived from `R_AR` | recompute `SHA-256(0x02 ‖ JCS(R_AR))` | **EXACT** |
| `integrity_hash` | string | MUST | APS-200 §4, §5.2 | JCS string; 64 lowercase hex (§4.1) | **NO — excluded** | **NO — self-excluded** | NO | **NO** | **NO — self** | YES | derived after record hash | recompute `SHA-256(JCS(R_I))` | **EXACT** |
| *(`event_payload`)* | JSON object | MUST | APS-200 §5.5 EP-001 | JCS object, UTF-8 | NO — not an ENT-007 field | NO | **IS the input** | NO | NO | NO | ordinary | EP-BOUNDARY-001 then `SHA-256(JCS(P))` | **EXACT** |

**Field-order question, resolved:** object member order in the source representation is irrelevant. RFC 8785 §3.2.3 sorts members by UTF-16 code unit before serialization, and C1 proved the promoted engine implements that ordering with a discriminating test (U+1F600 before U+FB33). No pre-JCS ordering rule is needed and none is specified. **Not a gap.**

**Null-vs-omit question, resolved:** every field is MUST and the surface is closed (§5.6), so no field may be absent and none may be `null` unless its declared type permits it. None does. **Not a gap.**

---

## 4. `R_AR` definition

**Source:** APS-200 §5.1, corroborated by P0-2 matrix §4.

```text
R_AR = complete canonical ENT-007 object
       EXCLUDING exactly:
         audit_record_hash     (self)
         integrity_hash        (circularity break)
```

**The exclusion list is complete and closed**, not assumed. Three independent statements pin it:

1. §5.1 enumerates exactly two exclusions with the word "except".
2. §5.1: *"The `audit_record_hash` MUST NOT depend on `integrity_hash`. This exclusion prevents a circular dependency."*
3. §5.6 closes the field surface, so no undeclared field can exist to be silently included or excluded.

`R_AR` therefore contains exactly nine members:

```
created_at, event_payload_hash, event_type, object_id, object_type,
previous_record_hash, protocol_version, schema_version, sequence_number
```

(shown in JCS order; source order is irrelevant per §3 above)

| Question posed by the gate | Answer | Authority |
|---|---|---|
| Does object field order matter before JCS? | **No** — RFC 8785 §3.2.3 sorts | APS-200 §5.1 + RFC 8785 |
| Are fields omitted or represented as `null`? | **Neither arises** — all fields MUST be present | §4, §5 ENT-007 |
| Are absent optional fields included? | **No optional fields exist** | §4, §5 ENT-007 |
| Are unknown/extension fields permitted? | **No** — closed surface | §5.6 |
| Do extension fields participate in `R_AR`? | **N/A** — none may exist | §5.6 |
| Can extension fields alter `audit_record_hash`? | **N/A** — none may exist; this is §5.6's stated purpose | §5.6 |
| Are any derived fields excluded? | **Yes** — `audit_record_hash` (self) and `integrity_hash`. `event_payload_hash` and `previous_record_hash` are derived but **included** | §5.1, P0-2 §2 |
| Is `previous_record_hash` included? | **YES** | §5.1, P0-2 §2 |
| Is `event_payload_hash` included? | **YES** | §5.1, P0-2 §2, §4 |

**`JCS(R_AR)` is uniquely determined.** Member set is closed and enumerable; member order is fixed by RFC 8785; every member's canonical representation is pinned (§4.1 for digests, RFC 8785 §3.2.2.3 for the integer, JCS string escaping for the rest); output encoding is UTF-8.

---

## 5. `audit_record_hash` definition

**Source:** APS-200 §5.1.

```text
AuditRecordHashPreimage(R) = 0x02 ‖ JCS(R_AR)
audit_record_hash(R)       = SHA-256(AuditRecordHashPreimage(R))
```

| Property | Normative value | Authority |
|---|---|---|
| Prefix byte | `0x02` | §5.1, §8 domain table in P0-2 |
| Prefix length | **exactly one raw octet** | §5.1 |
| Prefix encoding | raw octet. **MUST NOT** be ASCII `"0x02"`, a hex string, or any textual wrapper | §5.1, P0-2 §4, §7 |
| Concatenation | byte concatenation, prefix first, no separator, no length prefix | §5.1 `‖` |
| JCS output encoding | UTF-8 bytes | §5.5, P0-2 §7 |
| Hash algorithm | SHA-256 | §5.1 |
| Digest representation **inside ENT-007** | exactly 64 lowercase hexadecimal ASCII characters encoding 32 bytes | **§4.1** |
| Comparison | performed over the 32 raw digest bytes | §4.1 |
| Non-conformant representations | uppercase hex, `0x` prefix, base64, whitespace | §4.1, P0-2 §7 |

### 5.1 `audit_record_hash ≠ chain_hash` — proven, not assumed

The contract never equates them. It separates them three ways, and execution confirms the separation numerically.

1. **Explicit textual exclusion.** §5.1: *"It is distinct from `integrity_hash`, certificate fingerprints, and RFC 6962-style Merkle hashes."* §5.2 rule 5: *"Certificate and Merkle digests MUST NOT be substituted for `audit_record_hash`."* P0-2 §8: *"Certificate, Merkle, and legacy chain digests MUST NOT be substituted."*
2. **Different domain.** `0x02` is reserved for the Audit Record; `0x00`/`0x01` are RFC 6962 Merkle. RI-RS's `chain_hash` uses **no** domain octet at all.
3. **Different preimage, measured.** From `DQ-003-ENTRY-POINT-EXECUTION.md` §C.5–C.7, record-000:

| Construction | Preimage | Digest |
|---|---|---|
| APS-200 `audit_record_hash` | `0x02 ‖ JCS(R_AR)` | `cbbc5104a848650d4b6cea175462b50779b40077c815cf3622875e8fc5689e79` |
| RI-RS `compute_chain_hash` | `prev\|decision\|policy_set\|policy_hash\|context\|input_hash\|shadow_hash\|seq\|timestamp` | `d6cc2e73b5f052660163cf882a36632152e2b8c633c58e780dff48cd8bad4c80` |
| control: same JCS, **no** `0x02` | `JCS(R_AR)` | `0da60d9b13bb95245470935e123aa5b86d26b652dda44ad9957a9342acce4480` |
| control: RFC 6962 leaf domain | `0x00 ‖ JCS(R_AR)` | `26574f39b270b3968c9192947790a59c594e2fca8f4f230df2025acc34e9d00c` |

The no-domain control proves the `0x02` octet is load-bearing: omitting it changes the digest completely. SHA-256 alone does **not** establish the domain.

**RI-RS's pipe-joined nine-field preimage is recorded here as implementation behavior only.** It has no normative standing and does not reinterpret the contract.

---

## 6. `R_I` definition

**Source:** APS-200 §5.2, corroborated by §4 and P0-2 §5.

```text
R_I = complete canonical ENT-007 object
      EXCLUDING ONLY:
        integrity_hash        (self)
```

§5.2 is emphatic: *"`R_I` is the complete canonical ENT-007 object **excluding only `integrity_hash` itself**"* and *"Therefore `R_I` includes the derived `audit_record_hash`."*

`R_I` therefore contains exactly ten members — the nine of `R_AR` **plus** `audit_record_hash`.

| Does `R_I` include… | Answer | Authority |
|---|---|---|
| `audit_record_hash` | **YES** — stated explicitly twice | §5.2, §4 note, P0-2 §5 |
| `previous_record_hash` | **YES** | §5.2 "complete … excluding only" |
| `event_payload_hash` | **YES** | §5.2 |
| `sequence_number` | **YES** | §5.2 |
| all identity/schema/version fields | **YES** | §5.2 + §4 |
| extension fields | **N/A** — none may exist | §5.6 |
| `integrity_hash` | **NO** — self-excluded | §4 self-reference note, §5.2 |

---

## 7. `integrity_hash` definition

```text
IntegrityPreimage(R) = JCS(R_I)          # no domain separator
integrity_hash(R)    = SHA-256(IntegrityPreimage(R))
```

No normative alternative exists in the corpus. Representation: 64 lowercase hex ASCII (§4.1).

### 7.1 Does `integrity_hash` depend on `audit_record_hash`?

**YES — and the exact dependency is by value inclusion in the preimage.** `audit_record_hash` is a member of `R_I`, so its 64-hex string is serialized into `JCS(R_I)` and hashed. Changing `audit_record_hash` by one nibble changes `integrity_hash` completely.

Measured on fixture record-000: `integrity_jcs` opens with
`{"audit_record_hash":"cbbc5104…689e79","created_at":…}` — `audit_record_hash` sorts first under JCS and is literally the first member of the integrity preimage.

### 7.2 Is there a circular dependency?

**No.** The dependency graph is a strict DAG, closed by two complementary exclusions:

```text
Event Payload
     │
     ▼
event_payload_hash  ──┐
                      ├──►  R_AR  ──► 0x02 ‖ JCS  ──►  audit_record_hash
other source fields ──┘                                        │
                                                               ▼
                                                    R_I (= R_AR ∪ {audit_record_hash})
                                                               │
                                                          JCS  ▼
                                                        integrity_hash
                                                               │
                                                    (terminal — nothing consumes it)
```

- `audit_record_hash → integrity_hash`: **YES**, via `R_I` membership.
- `integrity_hash → audit_record_hash`: **NO.** §5.1 excludes `integrity_hash` from `R_AR` precisely to prevent this, and says so.
- Self-reference: neither digest includes its own field (§4 self-reference note, §5.2 rule 3).
- `integrity_hash` is **terminal**: `previous_record_hash` links to the predecessor's `audit_record_hash`, never its `integrity_hash` (§5.2 rule 4, §5.3).

Both exclusions are explicit and computable. **No circular definition exists.**

> **G-6 (documentation defect).** The dependency diagram in APS-200 §5.2 draws an arrow `integrity_hash → next.previous_record_hash`. That contradicts §5.2 rule 4 and §5.3 in the same document, both of which bind `previous_record_hash` to `audit_record_hash`. The prose rules and the Golden Fixture agree, so the byte semantics are unambiguous — but the diagram is wrong and will mislead an implementer reading it first.

---

## 8. `event_payload_hash` definition

**Source:** APS-200 §5.5 (EP-001), operationalized by `C2-1-EVENT-PAYLOAD-INPUT-CONTRACT.md`.

```text
raw event_payload bytes
      │  EP-BOUNDARY-001  (aura_guard::event_payload::validate_event_payload)
      ▼
validated duplicate-free JSON object
      │  RFC 8785 JCS + UTF-8  (aura_guard::canonical::canonical_bytes)
      ▼
JCS(P)
      │  SHA-256
      ▼
event_payload_hash  → 64 lowercase hex (§4.1)
```

**No domain separator** is applied (§5.5, P0-2 §8) — deliberately, since domain separation for the record identity is supplied independently by `0x02`.

### 8.1 Boundary between the four concepts

| Concept | What it is | Where it lives |
|---|---|---|
| `event_payload` | application/event data for one Audit Record | **outside** ENT-007; MAY be persisted or transported separately (§5.5) |
| `event_payload_hash` | the commitment binding payload to record | an ENT-007 field; input to `R_AR` and `R_I` |
| ENT-007 metadata | the immutable audit envelope — the other ten fields | ENT-007 |
| audit evidence | `audit_record_hash`, `integrity_hash`, `previous_record_hash` chain | ENT-007, derived |

§5.5 states the exclusion explicitly: the payload MUST exclude all Common Object Contract fields, `event_type`, `sequence_number`, `previous_record_hash`, `event_payload_hash`, `audit_record_hash`, and `integrity_hash`. **The raw payload is never duplicated inside an ENT-007 hash preimage** (P0-2 §3).

### 8.2 Determinations

| Question | Answer | Authority | Status |
|---|---|---|---|
| Top-level type | MUST be a JSON **object**; array/string/number/boolean/null MUST NOT be used | §5.5 | **EXACT** |
| Duplicate keys | invalid; MUST be rejected **before** hashing; first-wins / last-wins / merge explicitly forbidden | §5.5 | **EXACT** |
| UTF-8 | payload MUST be valid Unicode JSON; canonical form MUST be UTF-8; invalid sequences are not a valid representation | §5.5 | **EXACT** |
| JCS | RFC 8785, no deviation | §5.5 | **EXACT** |
| Numeric semantics | RFC 8785 §3.2.2.3 / ECMAScript; verified by C1's 24-case Appendix B corpus | §5.5 + RFC 8785 | **EXACT** |
| Unknown fields **in the payload** | permitted — payload members are governed by the event-specific schema, not by §5.6 | §5.5 | **EXACT** |
| Extension fields **in ENT-007** | forbidden | §5.6 | **EXACT** |
| Empty object `{}` | permitted — an object with zero members satisfies the top-level rule; no minimum-member rule exists | §5.5 (by absence of constraint) | **EXACT** |
| `null` as a member value | permitted | §5.5 | **EXACT** |
| Arrays as member values | permitted | §5.5 | **EXACT** |
| Scalars as member values | permitted | §5.5 | **EXACT** |
| Event-specific schema validation | required *"if one is declared by the event contract"* | §5.5 step 5 | **ABSENT for `AUDIT_DECISION`** — see **G-3** |
| Unicode normalization of member names | not specified anywhere | — | **AMBIGUOUS** — **G-9**, carried from C2-1 |

The C2-1 contract is unmodified by this gate. EP-BOUNDARY-001 implements exactly §5.5 steps 1–4 and 6–7; no requirement was added or relaxed.

---

## 9. `previous_record_hash` and genesis

### 9.1 Non-genesis linkage — explicitly normative

APS-200 §5.3, verbatim:

```text
R[n].previous_record_hash = R[n-1].audit_record_hash
```

Reinforced by §5.2 rule 4 (*"not its `integrity_hash`"*), §5.4 (derived and independently recomputable), and P0-2 §6. The "if and only if explicitly normative" test posed by this gate is **satisfied** — it is stated as an equation in the specification body, not inferred.

### 9.2 Genesis — every requested property is pinned

| Property | Normative value | Authority |
|---|---|---|
| Digest length | 32 bytes | §4.1 |
| Number of zero bytes | **32** | §4.1 *"textual encoding of 32 zero bytes"*; P0-2 §6 |
| Encoding | 64 lowercase hexadecimal ASCII characters | §4.1 |
| Literal representation | `0000000000000000000000000000000000000000000000000000000000000000` | §4.1, quoted verbatim in the specification |
| Genesis `sequence_number` | `0` | §5.3, P0-2 §6 |
| Sentinel nature | an **encoded all-zero digest** | §4.1: *"This is the textual encoding of 32 zero bytes, **not a special keyword**"* |

**Genesis is NOT:** a literal raw byte sequence in the preimage (it is the hex *string*, JCS-serialized like any other string member); an omitted field (`previous_record_hash` is MUST, always present); or a special sentinel token such as `"GENESIS"`.

Nothing was assumed. §4.1 states the byte count, the encoding, and the anti-keyword clause explicitly, and P0-2 §6 repeats all three.

> **G-8.** `conformance/dq-003/DQ-003_AUDIT_RECORD_HASH_DOMAIN.md` and `conformance/DQ-003_AUDIT_RECORD_HASH_DOMAIN.md` use 1-indexed notation (`R[1].previous_record_hash == GENESIS`), while APS-200 §5.3 and the Golden Fixture are 0-indexed (`sequence_number = 0`, `record-000`). A notational inconsistency in non-normative documents; it changes no byte, but it invites off-by-one implementation.

> **G-4.** The DQ-003 fixture-selection collision recorded in `DQ-003-ENTRY-POINT-EXECUTION.md` §A.5 persists: three files are named `DQ-003-AUDIT-CHAIN-001.json`, and the two EXPERIMENTAL ones use `"previous_record_hash": "GENESIS"` and `"EXPECTED_FROM_R1"` — placeholder sentinels that directly contradict §4.1's anti-keyword clause. Only `conformance/DQ-003-AUDIT-CHAIN-001.json` (`status: GOLDEN-FIXTURE`) is authoritative.

---

## 10. Extension-field policy

**ENT-007 permits no extension fields in the P0-2 conformance profile.** This is stated, not inferred.

APS-200 §5.6: *"ENT-007 is a **closed canonical hash surface**. An implementation MUST NOT add undeclared fields… Unknown or undeclared fields MUST be rejected in the P0-2 conformance profile. This rule prevents two implementations from accepting the same semantic record while hashing different field sets."*

| Question | Answer | Authority |
|---|---|---|
| Are extension fields allowed? | **NO** for P0-2 | §5.6 |
| Where would they live? | **N/A** — no extension container is defined | §5.6 |
| Do they enter `R_AR`? | **N/A** — none may exist | §5.6 |
| Do they enter `R_I`? | **N/A** | §5.6 |
| Can they affect `audit_record_hash`? | **N/A**; preventing exactly this is §5.6's stated rationale | §5.6 |
| Can they affect `integrity_hash`? | **N/A** | §5.6 |
| Are unknown fields rejected? | **YES, MUST** — error code `E_UNEXPECTED_FIELD` | §5.6, §5.7 |
| Does an extension namespace/versioning mechanism exist? | **Yes, at the version level only**: a field may be added solely by a later `schema_version` that declares the field, declares its hash-domain treatment, updates the inclusion/exclusion matrix, and provides new golden fixtures | §5.6, P0-2 §10 |

**Explicit statement, fully supported by the specification: unknown fields MUST be rejected.** No new extension policy was introduced by this gate.

Note for the payload boundary: §5.6 governs the **ENT-007 envelope only**. Unknown members *inside* `event_payload` are governed by the event-specific schema (§5.5), not by §5.6 — these are different surfaces and must not be conflated.

---

## 11. Verification semantics

**The specification defines the order.** It was not invented here. APS-200 §5.5 gives a 9-step payload sequence; P0-2 §9 gives the full 17-step record sequence "in dependency order". They are consistent; P0-2 is the superset.

| # | Check | Failure code (§5.7) |
|---|---|---|
| 1 | Parse Event Payload | `E_PAYLOAD_INVALID_JSON` |
| 2 | Reject malformed JSON | `E_PAYLOAD_INVALID_JSON` |
| 3 | Reject duplicate object member names | `E_PAYLOAD_DUPLICATE_KEY` |
| 4 | Reject non-object top-level payload | `E_PAYLOAD_TOP_LEVEL_TYPE` |
| 5 | Validate event-specific payload schema, when declared | `E_PAYLOAD_SCHEMA` |
| 6 | JCS-canonicalize the payload | `E_CANONICALIZATION_INVALID` |
| 7 | UTF-8 encode | `E_CANONICALIZATION_INVALID` |
| 8 | Compute `event_payload_hash` | — |
| 9 | Compare `event_payload_hash` | `E_PAYLOAD_HASH_MISMATCH` |
| 10 | Construct `R_AR`, compute `audit_record_hash` using `0x02` | — |
| 11 | Compare `audit_record_hash` | `E_AUDIT_RECORD_HASH_MISMATCH` |
| 12 | Construct `R_I`, compute `integrity_hash` | — |
| 13 | Compare `integrity_hash` | `E_INTEGRITY_HASH_MISMATCH` |
| 14 | Verify `previous_record_hash` against predecessor, except genesis | `E_PREVIOUS_RECORD_HASH_MISMATCH` |
| 15 | Verify genesis sentinel and `sequence_number` rules | `E_GENESIS_INVALID`, `E_SEQUENCE_INVALID` |
| 16 | Verify canonical serialization and required-field presence | `E_CANONICALIZATION_INVALID`, `E_REQUIRED_FIELD_MISSING` |
| 17 | Reject undeclared ENT-007 fields | `E_UNEXPECTED_FIELD` |

**Does failure of one check prevent later checks?** Yes, and this is specified: P0-2 §9 requires checks "in dependency order" and §5.5 requires rejection "if any required step fails". Steps 8–13 are strictly dependency-ordered — `R_AR` cannot be built before `event_payload_hash` is known, and `R_I` cannot be built before `audit_record_hash` is known — so the ordering is also mathematically forced, not merely stylistic. Fail-fast is therefore normative for the hash chain.

> **G-7 (conflict).** The two authorities disagree on *which* code to surface when several apply. APS-200 §5.7: *"The verifier MUST report the **most specific** applicable code."* P0-2 §9 and §11: *"The verifier MUST report the **first** applicable normative code."* Specificity-ranked and order-ranked selection are different rules and can yield different codes for the same record. APS-200 outranks P0-2, but the frozen conformance matrix is what a test harness will implement. Non-hash-bearing; still a real interoperability defect between two conformant verifiers.

> **G-3 (gap).** No error code exists for *"`event_type` is not present in the approved registry."* `E_PAYLOAD_SCHEMA` covers payload-schema violations, not envelope vocabulary. A strict verifier rejecting `AUDIT_DECISION` has no normative code to report.

---

## 12. Golden Fixture derivation analysis

**Fixture:** `conformance/DQ-003-AUDIT-CHAIN-001.json`, `status: GOLDEN-FIXTURE`, unmodified. Not regenerated, not reinterpreted.

### 12.1 Mechanical field mapping

| Fixture field | record-000 | record-001 | `JCS(P)` | `R_AR` | `R_I` |
|---|---|---|---|---|---|
| `object_id` | `00000000-0000-4000-8000-000000000000` | `…0001` | — | ✓ | ✓ |
| `object_type` | `AuditRecord` | `AuditRecord` | — | ✓ | ✓ |
| `protocol_version` | `1.0` | `1.0` | — | ✓ | ✓ |
| `schema_version` | `1.0` | `1.0` | — | ✓ | ✓ |
| `created_at` | `2026-01-01T00:00:00Z` | `2026-01-01T00:00:01Z` | — | ✓ | ✓ |
| `event_type` | `AUDIT_DECISION` | `AUDIT_DECISION` | — | ✓ | ✓ |
| `sequence_number` | `0` | `1` | — | ✓ | ✓ |
| `previous_record_hash` | `0`×64 (genesis) | `cbbc5104…689e79` | — | ✓ | ✓ |
| `event_payload_hash` | `a303ba4e…45ebde` | `fabc602b…2224a1` | *output* | ✓ | ✓ |
| `audit_record_hash` | `cbbc5104…689e79` | `08704c4e…268902` | — | ✗ self | ✓ |
| `integrity_hash` | `70526acd…be57a` | `748de582…9c6591` | — | ✗ | ✗ self |
| `event_payload` | `{action:ALLOW, resource, subject}` | `{action:DENY, …}` | **input** | — | — |

Chain dependency: `record-001.previous_record_hash` (`cbbc5104…689e79`) `==` `record-000.audit_record_hash` (`cbbc5104…689e79`). ✓

### 12.2 Derivation result

```
FIXTURE DERIVATION = COMPLETE
```

Every expected value derives uniquely from the frozen contract, with nothing supplied by the fixture beyond its declared inputs. Independently confirmed in `DQ-003-ENTRY-POINT-EXECUTION.md` §A.4: all six digests and all six canonical preimages reproduced, and the chain linkage verified — `FIXTURE SELF-VERIFICATION: PASS`, exit 0.

The fixture also carries its own `generation_rules`, which match APS-200 §5.1/§5.2/§5.5 term-for-term, and records `"generation_method": "Independent fixture computation… no RI-PY or RI-RS implementation was used to derive expected values."`

### 12.3 One qualification — derivation is not acceptance

A strict-conformance verifier executing P0-2 §9 step 5 together with `EVENT_TYPE_REGISTRY.md` §3 (*"unknown token → REJECT in strict conformance mode"*) **must reject both fixture records**, because `AUDIT_DECISION` is not registered and the registry currently registers nothing.

This does not make derivation incomplete — the digests are correct and reproducible. It means the Golden Fixture **cannot currently pass strict-mode verification of its own contract**. That is a Custodian decision (**G-3**), not an implementation defect, and it must be resolved before any conformance run can return a meaningful PASS.

---

## 13. RI-RS comparison — `aura-guard-v1.3` @ `9328484`

Read-only. RI-RS behavior does **not** redefine the contract anywhere below.

| APS-200 / P0-2 requirement | RI-RS current behavior | Class |
|---|---|---|
| RFC 8785 JCS canonicalization | `aura_guard::canonical::canonical_bytes` — **production** since C2-1; C1-verified 9/9 against RFC vectors | **EXACT** |
| EP-001 payload validation (§5.5 steps 1–4, 6–7) | `aura_guard::event_payload::validate_event_payload` — **production**; 17/17 conformance + 17/17 unit | **EXACT** |
| UTF-8 canonical encoding | RFC 8785 output, C1 §3.2.4 vector | **EXACT** |
| SHA-256 primitive | `crypto::sha256_hex`, `crypto::sha256_bytes_hex` — the latter accepts arbitrary bytes, so a `0x02` prefix is expressible | **EXACT** |
| Digest representation, 64 lowercase hex | `hex::encode` throughout | **EXACT** |
| `0x02` Audit Record domain | **not used as a hash domain anywhere.** `grep 0x02 src/` matches only DER/ASN.1 literals in `rfc3161.rs` | **ABSENT** |
| Merkle `0x00` / `0x01` separation | `merkle::leaf_hash` / `node_hash` — RFC 6962, correctly distinct | **EXACT** (adjacent, not ENT-007) |
| ENT-007 record type | `models::AuditEntry` field set is disjoint; deserializing a fixture record fails `missing field 'schema'` | **ABSENT** |
| `R_AR` / `R_I` field-exclusion rules | none | **ABSENT** |
| `event_payload_hash` entry point | none — primitives exist, composition does not | **ABSENT** |
| `audit_record_hash` entry point | `chain::compute_chain_hash` produces a *different* digest from a *different* preimage | **ANALOGOUS** |
| `chain_preimage()` | `prev\|decision\|policy_set\|policy_hash\|context\|input_hash\|shadow_hash\|seq\|timestamp`, `\|`-joined UTF-8, no JSON, no domain octet | **ANALOGOUS** — recorded as implementation behavior only |
| `recompute_for_entry()` | recomputes `chain_hash`, not `audit_record_hash` | **ANALOGOUS** |
| `verify_chain()` | correct chain *shape* (genesis → linkage → recompute); wrong domain and wrong anchor. Rejected the fixture at entry #0 | **ANALOGOUS** |
| `integrity_hash` entry point | none | **ABSENT** |
| `previous_record_hash` | `AuditEntry.prev_hash` links predecessor `chain_hash`, not `audit_record_hash` | **ANALOGOUS** |
| Genesis anchor | `crypto::genesis_hash()` = `SHA-256("AURA-GUARD-GENESIS-v1.3")` = `b93b4ade…3562d` ≠ required `0`×64 | **ANALOGOUS** |
| Closed-surface rejection (§5.6) | `AuditRequest` lacks `deny_unknown_fields`; no ENT-007 surface to close | **ABSENT** |
| §5.7 error codes | no `E_*` code exists in `src/` | **ABSENT** |
| Event-type registry validation | none | **ABSENT** |

**Terminology discipline:** `chain_hash` is **not** renamed and **not** equated with `audit_record_hash`. RI-RS's in-tree disclaimers (`tests/hash_domains.rs:697`, `tests/regression.rs:35`) already state that no relationship is claimed with APS-200 `integrity_hash` / `event_payload_hash` / `previous_record_hash`. Nothing in this gate contradicts them.

**Net change since the DQ-003 execution gate:** two rows moved from ABSENT/PARTIAL to **EXACT** (JCS canonicalization, EP-001 validation) as a direct result of the C2-1 promotion. Everything ENT-007-specific remains ABSENT or ANALOGOUS.

---

## 14. RI-PY comparison — `aura-poc-a-core-v3.3` @ `64bf959`

Read-only, unchanged, and untouched by every gate in this sequence. No remediation designed here.

| APS-200 / P0-2 requirement | RI-PY current behavior | Class |
|---|---|---|
| RFC 8785 JCS canonicalization | **no implementation and no dependency.** `grep` for `8785` / `canonicalize` / `def canonical` → 0 hits | **ABSENT** |
| Deterministic serialization | `compliance/certificate.py:69` `json.dumps(sort_keys=True)`; `core/merkle.py:8` same — Python default separators `", "` / `": "`, not JCS | **ANALOGOUS** |
| Compact-separator idiom | present **inline only**, hard-wired to three fields (`audit/merkle.py:85` `_signing_payload`), never a general canonicalizer | **PARTIAL** |
| SHA-256 primitive | `audit/merkle.py:14` `sha256(str)` — correct; reproduced `event_payload_hash` and `integrity_hash` exactly when handed the fixture's own JCS bytes | **EXACT** |
| EP-001 payload validation | no duplicate rejection, no top-level-object enforcement | **ABSENT** |
| ENT-007 record type | `AuraEventCertificate(**record)` → `TypeError: unexpected keyword argument 'object_id'` | **ABSENT** |
| Certificate fingerprint | `AuraEventCertificate.fingerprint()` — certificate domain, disjoint field set | **ANALOGOUS** |
| Merkle leaf / root | `audit/merkle.py` `MerkleTree`, `sha256(left+right)` — **no** `0x00`/`0x01` domain octets; hex-string concatenation | **ANALOGOUS** |
| Evidence representation | Event Trust Certificate + Merkle proof — an inclusion-proof model, not a sequential record chain | **ANALOGOUS** |
| `0x02` Audit Record domain | no domain-separation octet of any kind | **ABSENT** |
| `event_payload_hash` / `audit_record_hash` / `integrity_hash` | 0 grep hits each | **ABSENT** |
| `previous_record_hash`, `sequence_number`, genesis, chain verification | 0 grep hits each | **ABSENT** |
| §5.7 error codes | none | **ABSENT** |

**Summary:** RI-PY has the correct hash primitive and nothing else. It is missing the entire canonicalization layer, so it cannot produce a single required digest from its own inputs — confirmed by execution, where its own serializer produced `8d1c93a3…` against the required `a303ba4e…` for record-000's payload.

---

## 15. Exact remaining gaps

**Hash-bearing byte ambiguities: 0.** Every gap below is normative-status, vocabulary, cross-reference, or verification-acceptance. None changes a preimage byte.

| ID | Gap | Where | Hash-bearing? | Severity | Required Custodian decision |
|---|---|---|---|---|---|
| **G-1** | APS-200 §4 and §5.1 both delegate canonical bytes / the "RFC 8785 JCS profile" to **§8 — which does not exist**. APS-200 ends at §5. | `APS-200` §4 line 58, §5.1 line 189 | **No** — RFC 8785 is named inline at both call sites and is self-sufficient; P0-2 §7 supplies UTF-8 encoding | High | Add §8, or retarget both references to §5.5 / P0-2 §7 |
| **G-2** | `0x02` normative-status conflict. APS-200 §5.1 states it with MUST; `conformance/DQ-003_AUDIT_RECORD_HASH_DOMAIN.md:74` says *"experimental and MUST NOT be treated as normative until DQ-003 closes"*; `conformance/dq-003/…` is marked **EXPERIMENTAL / NOT NORMATIVE** | 3 documents | **No** — identical octet in identical position either way | **Critical** | Declare which document governs. APS-200 outranks both, but the conflict must be retired explicitly, not implicitly |
| **G-3** | Event-type vocabulary is **empty**. `EVENT_TYPE_REGISTRY.md` is DRAFT with zero registered tokens and mandates rejection of unregistered tokens in strict mode. The Golden Fixture uses the unregistered `AUDIT_DECISION`. No §5.7 error code covers this condition | `EVENT_TYPE_REGISTRY.md` §5, §9; fixture; `APS-200` §5.7 | **No** for derivation; **blocking** for strict-mode acceptance | **Critical** | Register `AUDIT_DECISION` (with `payload_schema`), or exempt the DQ-003 profile from registry enforcement. Also add an error code. Tracked upstream as DQ-004 |
| **G-4** | Fixture-identifier collision: three files named `DQ-003-AUDIT-CHAIN-001.json`; the two EXPERIMENTAL ones use `"GENESIS"` / `"EXPECTED_FROM_R1"` placeholders that contradict §4.1's anti-keyword clause | `conformance/`, `conformance/fixtures/`, `fixtures/dq-003/` | No | High | Rename or retire the non-authoritative files |
| **G-5** | **"Session" is undefined corpus-wide.** `sequence_number` MUST be `0` "for the first record in a session" and increment "within that session", but no artifact defines a session boundary. `grep -i session aps/APS-000…` → 0 hits | `APS-200` §5 ENT-007, §5.3; `APS-000` | **No** — the integer's JCS bytes are exact; the *validity rule* is unanchorable | High | Define "session" in APS-000, or restate §5.3 against a defined scope |
| **G-6** | APS-200 §5.2's dependency diagram draws `integrity_hash → next.previous_record_hash`, contradicting §5.2 rule 4 and §5.3 in the same document | `APS-200` §5.2 | No — prose and fixture agree | Medium | Correct the diagram |
| **G-7** | Error-code selection conflict: APS-200 §5.7 *"most specific applicable"* vs P0-2 §9/§11 *"first applicable"* | `APS-200` §5.7; `P0-2` §9, §11 | No | Medium | Pick one rule; two conformant verifiers can otherwise emit different codes |
| **G-8** | Genesis indexing notation: DQ-003 working docs are 1-indexed (`R[1]…== GENESIS`); APS-200 §5.3 and the fixture are 0-indexed | `conformance/DQ-003_AUDIT_RECORD_HASH_DOMAIN.md` | No | Low | Align notation |
| **G-9** | Unicode normalization of member names (NFC vs NFD) unspecified for duplicate detection and for JCS ordering | not specified anywhere | **Potentially yes** in an adversarial case — but **no** for the current profile: nothing in the corpus permits or requires normalization, so exact-byte comparison is the only reading available, and RFC 8785 §3.2.3 orders by UTF-16 code units without normalizing | Medium | Resolve `C2-1-TBD-UNICODE-NORMALIZATION` explicitly, even if the answer is "no normalization, ever" |

### 15.1 Why this is CONDITIONAL PASS and not BLOCKED

The gate's own criterion: *BLOCKED if any hash-bearing semantic decision remains ambiguous.* Working through the four constructions:

- **`event_payload_hash`** — input class, canonicalization, encoding, and algorithm all pinned (§5.5). Determined.
- **`audit_record_hash`** — member set closed and enumerable (§5.1 + §5.6), member order fixed by RFC 8785, prefix pinned to one raw octet, algorithm pinned. Determined.
- **`integrity_hash`** — exclusion is *"only `integrity_hash` itself"*, no domain separator, algorithm pinned. Determined.
- **`previous_record_hash`** — linkage stated as an equation (§5.3); genesis pinned to byte count, encoding, and literal (§4.1). Determined.

No hash-bearing decision is open. **G-9** is the only gap that could ever touch a preimage byte, and only for inputs the current corpus neither permits nor addresses; it is called out rather than resolved.

### 15.2 Why this is CONDITIONAL PASS and not PASS

Nine defects are real. Two — **G-2** and **G-3** — mean that today a strict-conformance verifier built exactly to specification would **reject the Golden Fixture**, and an implementer could reasonably conclude the `0x02` domain is not yet binding. That is not a document-formatting complaint; it is a live contradiction between artifacts of different authority ranks. Calling this PASS would paper over it.

---

## 16. C3 verdict

```
C3 = CONDITIONAL PASS

  Contract completeness (hash bytes) ....... COMPLETE
  Hash-bearing ambiguities ................. 0
  Golden Fixture derivation ................ COMPLETE
  Golden Fixture strict-mode acceptance .... BLOCKED by G-3
  Non-hash-bearing gaps .................... 9  (2 critical, 3 high, 3 medium, 1 low)

  ENT-007 ....................... NOT IMPLEMENTED
  DQ-003 ........................ OPEN
  Golden Fixture ................ UNTOUCHED
  APS-200 ....................... UNTOUCHED
  RI-PY / RI-RS ................. UNTOUCHED
```

The ENT-007 composition surface **is** specified precisely enough to implement. It is **not yet** consistent enough to certify against.

---

## 17. Hand-off requirements for implementation

Implementation must not begin until the Custodian closes **G-2** and **G-3**. The rest can proceed in parallel with the remaining gaps.

### 17.1 Blocking preconditions

1. **G-2** — declare `0x02` normative and retire the "experimental" language, or state that DQ-003 must close first. Until then any `audit_record_hash` implementation rests on contested authority.
2. **G-3** — register `AUDIT_DECISION` (or exempt the DQ-003 profile from registry enforcement) and add an error code for unregistered `event_type`. Until then the fixture cannot pass strict-mode verification no matter how correct the implementation is.

### 17.2 What the implementation must supply

Available today, already production and verified — reuse, do not reimplement:

- `aura_guard::event_payload::validate_event_payload(&[u8]) -> Result<Value, EventPayloadError>` — EP-001 steps 1–4
- `aura_guard::canonical::canonical_bytes(&Value) -> Result<Vec<u8>, Error>` — RFC 8785, C1-verified
- `aura_guard::crypto::sha256_bytes_hex(&[u8]) -> String` — accepts arbitrary bytes, so `0x02` prefixing is expressible

Missing, and required:

| # | Surface | Contract |
|---|---|---|
| 1 | ENT-007 record type, all 11 fields MUST, `deny_unknown_fields` | §5 ENT-007, §5.6 |
| 2 | `R_AR` construction — exclude `audit_record_hash`, `integrity_hash` | §5.1 |
| 3 | `R_I` construction — exclude `integrity_hash` only | §5.2 |
| 4 | `event_payload_hash` = `SHA-256(JCS(P))`, no domain octet | §5.5 |
| 5 | `audit_record_hash` = `SHA-256(0x02 ‖ JCS(R_AR))`, one raw octet | §5.1 |
| 6 | `integrity_hash` = `SHA-256(JCS(R_I))` | §5.2 |
| 7 | Digest field representation — 64 lowercase hex; comparison over 32 raw bytes | §4.1 |
| 8 | Chain linkage + genesis sentinel + `sequence_number` rules | §5.3 |
| 9 | 17-step fail-fast verification order | P0-2 §9 |
| 10 | 14 `E_*` machine-readable error codes | §5.7 |

### 17.3 Constraints the implementation must honor

- **Do not touch `src/chain.rs`.** `chain_hash` and `audit_record_hash` are different constructions in different domains (§5.1). The new surface sits beside the existing chain, never reinterprets it.
- **Do not add duplicate detection to `canonical_bytes`.** RFC 8785 §3.1 places it upstream; C2-1 already implements it there.
- **Genesis is the hex *string*** `0`×64 serialized as a JCS string member — not 32 raw bytes injected into the preimage.
- **`0x02` is one raw octet**, prepended to the JCS bytes with no separator and no length prefix.
- **The Golden Fixture is the oracle.** It must not be regenerated, and expected values must not be adjusted to match an implementation.

### 17.4 Gate sequence

```
C1 PASS → C2 PASS → C2-1 PASS → PRODUCTION PROMOTION → C3 CONDITIONAL PASS  ← here
   → Custodian closes G-2, G-3
   → C4  ENT-007 composition implementation
   → C5  DQ-003 Golden Fixture replay
   → C6  RI-RS conformance confirmation
   → RI-PY remediation (separate workstream; RFC 8785 absent entirely)
   → CROSS-LANGUAGE-002
```

**DQ-003 remains OPEN.** This gate closes no defect and implements nothing.

---

## 18. Git discipline

| Item | Value |
|---|---|
| Branch | `claude/dq-003-conformance-audit-4ok63x` (session-mandated) |
| Intended branch | `c1/full-domain-jcs` (PR #60) |
| Base SHA | `aebbbe04287993ea303366cf8c453bf721d250cc` |
| HEAD before this gate | `9328484` |
| Files changed | **exactly one — this file (new)** |
| `src/`, `Cargo.toml`, `Cargo.lock`, APS-200, Golden Fixture, RI-PY, RI-RS | **unmodified** |
| Fast-forward to the intended branch | **possible** — `git push origin claude/dq-003-conformance-audit-4ok63x:c1/full-domain-jcs` |

Branch conflict reported, not auto-resolved. No merge, no rebase, no force-push, `main` untouched.
