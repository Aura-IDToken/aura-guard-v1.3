# D3_REAL_CHAIN_EXECUTION_PLAN

**Phase 1 output — reconnaissance only.**
No production source was modified. No exporter was created. No CI was modified.

- Repository: `AuraIDToken/aura-guard-v1.3`
- Base branch: `main`
- Base commit: `443f72e58483c3ea6112ea517647cc0dbf459960`
- Working branch: `d3/real-chain-fixture-export`

---

## A. Actual execution path

The execution order presumed:

```
fixture -> models -> engine -> chain -> crypto
```

The **actual** runtime path traced from source is:

```
POST /v1/audit
  -> api::audit::handle_audit                     src/api/audit.rs:41      (orchestrator)
     -> api::audit::resolve_policy                src/api/audit.rs:234     (cache-only lookup)
        -> policy::load_policy                    src/policy.rs:184        (boot-time; supplies policy_hash + name)
     -> format!("{} {} {}", context, prompt, response)
                                                  src/api/audit.rs:104-107 (`original`)
     -> normalizer::shadow_normalize              src/normalizer.rs:49     (`shadow`)
     -> crypto::sha256_hex(original)              src/crypto.rs:8          (`input_hash`)
     -> crypto::sha256_hex(shadow)                src/crypto.rs:8          (`shadow_hash`)
     -> engine::evaluate(shadow, context, rules)  src/engine.rs:14         (`decision`, `violations`)
     -> log_writer::next_seq()                    src/log_writer.rs:74     (`seq`)
     -> log_writer::current_head()                src/log_writer.rs:80     (`prev_hash`)
     -> chrono::Utc::now().to_rfc3339()           src/api/audit.rs:117     (`timestamp`)
     -> chain::compute_chain_hash(...)            src/chain.rs:25          (canonicalization)
        -> [9 fields].join("|")                   src/chain.rs:36-47       (`canonical`, LOCAL BINDING)
        -> crypto::sha256_hex(&canonical)         src/crypto.rs:8          (`chain_hash`)
     -> models::AuditEntry { .. }                 src/models.rs:50         (DTO assembly)
     -> log_writer::append(&entry)                src/log_writer.rs:88
```

### Deviations from the presumed path

1. **`src/api/audit.rs` is the real orchestrator.** It is not named anywhere in the
   execution order, yet it is the module that assembles every value fed into the
   chain digest. It is the true "chain record creation" site.
2. **`models.rs` is not a processing stage.** It is a pure `serde` DTO module with
   no logic. It participates as types only.
3. **`engine.rs` does not feed the chain directly.** It returns `(decision, violations)`
   to `handle_audit`, which passes `decision` onward. `violations` never reaches the digest.
4. **`policy.rs` and `normalizer.rs` are load-bearing** for `policy_hash`, `policy_set`
   and `shadow_hash`, and are absent from the presumed path.

### Answers to the Phase 1 questions

| Question | Answer |
|---|---|
| What function creates the chain record? | `api::audit::handle_audit` (`src/api/audit.rs:41`) |
| What function computes the canonical representation? | `chain::compute_chain_hash` (`src/chain.rs:25`), inline at lines 36-47 |
| What function computes `chain_hash`? | `crypto::sha256_hex` (`src/crypto.rs:8`), called from `src/chain.rs:48` |
| Is `policy_hash` from raw YAML bytes? | **Yes.** `sha256_bytes_hex(std::fs::read(<name>.yaml))` — `src/policy.rs:184-188`. Raw file bytes, pre-parse. |
| Is `prev_hash` / genesis included? | **Yes**, field 1. Genesis = `sha256_hex("AURA-GUARD-GENESIS-v1.3")` — `src/crypto.rs:27` |
| Does `seq` participate? | **Yes**, field 8, as `u64::to_string()` (decimal ASCII, no padding) |
| Does `timestamp` participate? | **Yes**, field 9, RFC 3339 via `Utc::now().to_rfc3339()` |
| Do `violations` participate? | **No.** Recorded in `AuditEntry`, excluded from the digest. |
| Does `policy_set` participate? | **Yes**, field 3 — sourced from `policy.name` (the YAML `name:` key), **not** from the request field. |
| Does `decision` participate? | **Yes**, field 2 |
| Are `input_hash` / `shadow_hash` computed internally? | **Yes**, in `handle_audit` (`src/api/audit.rs:109-110`) before the chain call. |
| Can the existing CI runner execute this path? | The runner builds and tests the crate (`.github/workflows/ci.yml`). It cannot export the canonical preimage — see section C. |

---

## B. Source trace

Chain preimage = 9 fields joined by the separator `|` (`SEP`, `src/chain.rs:20`),
then UTF-8 encoded and SHA-256'd.

| # | Field | Source type | Transformation | Hash participation |
|---|---|---|---|---|
| — | `context` | `String` (`AuditRequest.context`) | verbatim | **YES** (field 5); also feeds `original` |
| — | `prompt` | `String` (`Payload.prompt`) | into `original` = `"{context} {prompt} {response}"` | INDIRECT (via `input_hash`, `shadow_hash`) |
| — | `response` | `String` (`Payload.response`) | into `original` | INDIRECT (via `input_hash`, `shadow_hash`) |
| — | policy YAML | file bytes on disk | `sha256_bytes_hex(raw bytes)` | **YES** as `policy_hash` (field 4) |
| 1 | `prev_hash` | `String` from `log.current_head()` | verbatim | **YES** |
| 2 | `decision` | `String` from `engine::evaluate` | verbatim (`DENY`/`REVIEW`/`ALLOW`) | **YES** |
| 3 | `policy_set` | `String` = `CompiledPolicy.name` | verbatim | **YES** |
| 4 | `policy_hash` | `String` hex | verbatim | **YES** |
| 5 | `context` | `String` | verbatim | **YES** |
| 6 | `input_hash` | `String` hex | `sha256_hex(original)` | **YES** |
| 7 | `shadow_hash` | `String` hex | `sha256_hex(shadow_normalize(original))` | **YES** |
| 8 | `seq` | `u64` | `.to_string()` — decimal ASCII | **YES** |
| 9 | `timestamp` | `String` | `Utc::now().to_rfc3339()` | **YES** |
| — | `violations` | `Vec<Violation>` | — | **NO** |
| — | `schema` | `String` | — | **NO** |
| — | `audit_id` | `String` (UUIDv4) | — | **NO** |
| — | `request_id` | `Option<String>` | — | **NO** |

---

## C. Execution feasibility

> ## REAL RUST EXECUTION BLOCKED

Three independent blockers. Each is sufficient on its own.

### C-1 — The canonical preimage is not exposed (STOP-6, with STOP-3 / STOP-1 on the workarounds)

`src/chain.rs:36-48`:

```rust
let canonical = [ /* 9 fields */ ].join(SEP);
sha256_hex(&canonical)
```

`canonical` is a **function-local binding**. `compute_chain_hash` returns only the
hex digest. `recompute_for_entry` likewise. No public or private API anywhere in
the crate returns, borrows, logs, or otherwise exposes the entry-level canonical
string or its bytes.

The execution order makes the raw byte stream **mandatory** (sections 0 and 8):
`rust_canonical_string` and `rust_canonical_bytes_hex` are required outputs, and
"the final digest alone is not sufficient evidence."

There are exactly three ways to obtain it, and the order forbids all three:

| Option | Verdict |
|---|---|
| Modify `chain.rs` to return the preimage | **Forbidden** — section 1 ("modify chain.rs"); triggers STOP-1 and fails the section 10 integrity check |
| Re-implement `[..].join("|")` in the exporter | **Forbidden** — section 6 ("Do NOT create a second implementation of: canonicalization"); triggers **STOP-3** |
| Recover the preimage from the digest | Cryptographically infeasible |

Therefore an exporter that satisfies section 8 **cannot** be built under the
constraints of section 1 and section 6. This blocker holds regardless of the fixture.

**Relevant precedent already in the codebase.** `SegmentManifest::segment_chain_preimage`
(`src/segment.rs:91-106`) is a **public** function returning the segment-level canonical
preimage `String`, with the digest derived separately in
`recompute_segment_chain_hash` (`src/segment.rs:108-117`). The segment layer is
therefore already forensically exportable; the entry layer is not. Introducing the
symmetric accessor at the entry layer is the change that would unblock D-3 — and it
is an architectural change, reserved to the Protocol Custodian.

### C-2 — Fixture identity cannot be established (STOP-2)

`D3_REAL_CHAIN_SEMANTIC_FIXTURE.json` could not be located in **any** authoritative source:

| Search scope | Result |
|---|---|
| `aura-guard-v1.3` working tree @ `443f72e` | not found |
| `aura-guard-v1.3` all 30+ remote branches | not found |
| `aura-guard-v1.3` complete git object history | not found |
| `aura-poc-a-core-v3.3` (tracked files) | not found |
| `aura-specification` (tracked files) | not found |
| Container filesystem (`find /`) | not found |
| GitHub global code search | 0 results |
| "Provided working materials" | none accompanied the order |

Section 5 requires the fixture to be used **exactly** and its SHA-256 recorded as an
immutable identity. Zero authoritative copies exist, so no identity can be recorded.

Authoring a fixture here would not be a clerical act: it would mean choosing which
fields the fixture pins — in particular whether it supplies `timestamp`, `seq` and
`prev_hash`, which the production path generates at runtime (see C-3). That is a
semantic decision about the experiment's own subject matter, and section 1 forbids
it.

### C-3 — The production path is not fixture-drivable end-to-end (STOP-8)

Three of the nine hashed fields are generated at runtime from live process state,
not from any request payload:

- `timestamp` — `Utc::now().to_rfc3339()` (`src/api/audit.rs:117`)
- `seq` — `state.log.next_seq()` (`src/api/audit.rs:116`)
- `prev_hash` — `state.log.current_head()` (`src/api/audit.rs:118`)

A fixture therefore cannot deterministically drive `handle_audit`. Reaching a
reproducible digest requires bypassing the orchestrator and calling
`chain::compute_chain_hash` directly with fixture-supplied values.

Whether that bypass still constitutes "executing the real chain implementation"
— or instead substitutes a synthetic harness for the production path — is a
competing architectural interpretation. Section 17 (STOP-8) reserves that judgement
to architectural authority.

---

## D. Additional finding — normative documentation divergence in production source

Not a blocker; recorded as observation. **Not corrected**, per section 1
("modify models.rs", "'fix' a discrepancy discovered during execution").

`src/models.rs:95` documents a **7-field** preimage:

```
SHA-256(prev_hash || decision || policy_set || input_hash || shadow_hash || seq || timestamp)
```

`src/chain.rs:6-8` documents, and `src/chain.rs:36-47` implements, a **9-field** preimage:

```
SHA-256(prev_hash || decision || policy_set || policy_hash || context || input_hash || shadow_hash || seq || timestamp)
```

`models.rs` omits `policy_hash` and `context`. The implementation is the 9-field
form. Any independent implementation written against the `models.rs` docstring
would produce a different digest. This is a candidate root cause for
cross-implementation divergence and is referred to architectural authority.

---

## E. Production files inspected

| File | Modified |
|---|---|
| `src/chain.rs` | NO |
| `src/models.rs` | NO |
| `src/engine.rs` | NO |
| `src/crypto.rs` | NO |
| `src/api/audit.rs` | NO |
| `src/policy.rs` | NO |
| `src/normalizer.rs` | NO |
| `src/log_writer.rs` | NO |
| `src/segment.rs` | NO |
| `.github/workflows/*` | NO |

**Production files modified: NONE.**
