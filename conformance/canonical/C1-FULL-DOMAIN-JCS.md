# C1 — Full-Domain RFC 8785 Verification

## Purpose

C1 is the Custodian gate for the existing RI-RS JCS candidate surface:

```text
conformance/canonical/jcs.rs
        |
        v
C1 RFC 8785 full-domain verification
        |
   PASS / GAP
```

C1 answers one question only:

> Is the existing JCS surface sufficiently conformant to RFC 8785 for the
> canonicalization capability required before ENT-007 composition?

C1 does **not** implement ENT-007, does **not** integrate JCS into `src/`,
 does **not** change the production dependency graph, and does **not** compare
RI-PY with RI-RS.

## Evidence basis

The corpus is derived from the normative behavior and published test material
in RFC 8785:

- §3.1 — I-JSON input constraints
- §3.2.1 — whitespace
- §3.2.2.1 — literals
- §3.2.2.2 — strings and escaping
- §3.2.2.3 — IEEE-754/ECMAScript number serialization
- §3.2.3 — recursive property sorting using UTF-16 code units
- §3.2.4 — UTF-8 output
- Appendix B — number serialization samples

The RFC explicitly requires duplicate property names to be excluded by the
I-JSON input-validation step, and requires JCS output to be UTF-8 with no
whitespace between JSON tokens.

## C1 matrix

| Domain | C1 evidence | Status |
|---|---|---|
| Primitive literals | RFC §3.2.2.1 sample | TESTED |
| String escaping | RFC §3.2.2.2 sample | TESTED |
| Unicode preservation | RFC §3.2.2.2 + §3.2.4 | TESTED |
| Whitespace elimination | §3.2.1 | TESTED |
| Integer representation | Appendix B | TESTED |
| Negative numbers | Appendix B | TESTED |
| Zero / negative zero | Appendix B | TESTED |
| Exponent notation | Appendix B | TESTED |
| Threshold number cases | Appendix B | TESTED |
| Rounding boundary | Appendix B | TESTED |
| Arrays | recursive corpus | TESTED |
| Nested objects | recursive corpus | TESTED |
| Recursive key ordering | §3.2.3 | TESTED |
| UTF-16 property ordering | §3.2.3 published test data | TESTED |
| Exact UTF-8 bytes | §3.2.4 | TESTED |
| Non-finite numbers | §3.2.2.3 / JSON input boundary | TESTED |
| Duplicate-property rejection | §3.1 I-JSON precondition | **BOUNDARY — upstream parser responsibility** |
| Lone-surrogate rejection | §3.2.2.2 | TESTED at JSON input boundary |
| ENT-007 representative structures | separate DQ-003 fixture work | **DEFERRED** |

## Important boundary: duplicate properties

`jcs.rs` has the deliberately narrow surface:

```text
serde_json::Value -> RFC 8785 JCS -> Vec<u8>
```

It does not parse raw JSON. Therefore it cannot observe duplicate property names
once the input has been materialized as `serde_json::Value`. RFC 8785 §3.1
places that constraint in the I-JSON input-data stage.

C1 records this as an explicit architectural boundary rather than silently
claiming that the serializer performs duplicate-key rejection. A future
production integration MUST ensure that the upstream input path enforces the
I-JSON precondition before canonicalization.

## Decision rule

C1 is **PASS** only when every in-scope serializer capability above passes and
no unresolved in-scope RFC 8785 behavior remains.

C1 PASS does **not** mean:

- JCS is already a production dependency;
- JCS is wired into `src/`;
- ENT-007 is implemented;
- RI-PY equals RI-RS;
- DQ-003 is closed.

Only a C1 PASS permits the next architectural gate:

```text
C1 PASS
  -> production dependency decision
  -> C2 production JCS integration
  -> C3 ENT-007 composition
  -> C4 DQ-003 fixture replay
  -> C5 RI-PY / RI-RS comparison
  -> CROSS-LANGUAGE-002
```

## Branch boundary

This work is confined to:

```text
dq-003/custodian-jcs-decision
        |
        +-- c1/full-domain-jcs
```

`main` is unchanged by C1.

---

# C1 Full-Domain RFC 8785 Verification

*Execution record. Appended after actual test execution; nothing above this line was altered.*

## A. Execution metadata

| Item | Value |
|---|---|
| Repository | `Aura-IDToken/aura-guard-v1.3` |
| Branch | `c1/full-domain-jcs` |
| Pull request | #60 (draft), head `aebbbe04287993ea303366cf8c453bf721d250cc`, base `main` @ `35082d7b4880dad780fb55a1a5f3ac0ef4322674` |
| Commit SHA under test | `aebbbe04287993ea303366cf8c453bf721d250cc` |
| Working tree state | **CLEAN** — `git status --porcelain` empty before and after execution |
| Rust | `rustc 1.94.1 (e408947bf 2026-03-25)` |
| Cargo | `cargo 1.94.1 (29ea6fb6a 2026-03-24)` |
| JCS engine | `serde_json_canonicalizer =0.3.2` (**`[dev-dependencies]`**, unchanged) |
| Surface under test | `conformance/canonical/jcs.rs::canonical_bytes` — **byte-identical to `main`** |
| Primary command | `cargo test --test c1_full_domain_jcs` |
| Secondary command | `cargo test --test c1_full_domain_jcs -- --nocapture` |
| Supporting command | `cargo test --test canonical_001` |
| Timestamp (UTC) | `2026-08-22T20:54:11Z` |
| Harness corrections required | **NONE** — the test target executed as committed; no source file was modified to make execution possible |

### A.1 Branch-content verification (pre-execution)

`git diff --stat origin/main...origin/c1/full-domain-jcs`:

```
 Cargo.toml                                  |   7 +-
 conformance/canonical/C1-FULL-DOMAIN-JCS.md | 119 +++++++++++++++++++
 conformance/canonical/c1_full_domain_jcs.rs | 177 ++++++++++++++++++++++++++++
 3 files changed, 302 insertions(+), 1 deletion(-)
```

Exactly the intended C1 changes; no unexpected modifications. Verified explicitly:

- `src/` — unchanged vs `main`.
- `conformance/canonical/jcs.rs` — unchanged vs `main` (the surface under test was not touched by the test that judges it).
- `Cargo.toml` — the only changes are registration of the `c1_full_domain_jcs` test target and one comment edit. `serde_json_canonicalizer` remains in **`[dev-dependencies]`**; **no production promotion occurred.**

## B. Corpus

Nine test functions in `conformance/canonical/c1_full_domain_jcs.rs`. All expected byte vectors are frozen from RFC 8785 published material, not generated by the engine under test.

| # | C1 category | Test function | RFC 8785 basis |
|---|---|---|---|
| 1 | Primitive/literal values (`null`, `true`, `false`) | `c1_rfc_section_3_2_2_primitive_and_string_sample` | 3.2.2.1, 3.2.4 |
| 2 | String escaping | same | 3.2.2.2 |
| 3 | Unicode preservation | same + `c1_utf8_is_exactly_the_canonical_output_encoding` | 3.2.2.2, 3.2.4 |
| 4 | Exact UTF-8 output bytes | `c1_utf8_is_exactly_the_canonical_output_encoding` | 3.2.4 |
| 5 | Whitespace elimination | `c1_whitespace_is_not_emitted` | 3.2.1 |
| 6 | Arrays (order preserved, not sorted) | `c1_recursive_object_and_array_order_is_preserved` | 3.2.3 |
| 7 | Recursive objects / nested key ordering | same | 3.2.3 |
| 8 | UTF-16 property ordering | `c1_rfc_utf16_property_sorting_sample` | 3.2.3 published test data |
| 9 | Appendix B numeric corpus (24 cases) | `c1_rfc_appendix_b_number_serialization_samples` | 3.2.2.3, Appendix B |
| 10 | Zero / negative zero | same (`"0"`, `"-0.0"`) | Appendix B |
| 11 | Exponent thresholds | same (`1e+21`, `999999999999999900000`, `0.000001`, `9.999999999999997e-7`) | 3.2.2.3 |
| 12 | Rounding boundaries | same (`333333333.3333332`…`333333333.33333343`, `1424953923781206.25`) | Appendix B |
| 13 | Extreme/denormal boundaries | same (`5e-324`, `±1.7976931348623157e+308`, `±9007199254740992`) | Appendix B |
| 14 | Non-finite number boundary | `c1_boundary_nonfinite_numbers_are_not_json_values` | 3.2.2.3 / JSON input boundary |
| 15 | Lone-surrogate boundary | `c1_boundary_lone_surrogate_is_rejected_before_canonicalization` | 3.2.2.2 |
| 16 | Duplicate-property boundary | `c1_i_json_duplicate_property_is_rejected_as_input_precondition` | 3.1 I-JSON precondition |

No category was removed, weakened, skipped, or converted to `#[ignore]`. Ignored count is `0`.

### B.1 Independent verification that the corpus is discriminating

Two checks were run outside the repository to confirm the corpus can actually fail, rather than asserting whatever the engine emits.

**Pinned RFC hex vector (test 1).** The frozen hex string in the test decodes to 118 bytes whose content is the RFC 3.2.4 canonical output verbatim:

- object keys ordered `literals` < `numbers` < `string`;
- numbers rendered `333333333.3333333`, `1e+30`, `4.5`, `0.002`, `1e-27`;
- the string value rendered with a literal UTF-8 Euro sign, `` in **lowercase** hex, `\n` for U+000A, `\"` and `\\` escapes, and an **unescaped** solidus.

The expectation is therefore independent of the engine: it was pinned from the RFC, and decoding it outside the repository reproduces the RFC text exactly.

**UTF-16 vs code-point ordering (test 8).** The RFC key set `{U+000D, U+0031, U+0080, U+00F6, U+20AC, U+1F600, U+FB33}` sorts differently under the two rules:

```
code-point order : U+000D, U+0031, U+0080, U+00F6, U+20AC, U+FB33,  U+1F600
UTF-16 CU order  : U+000D, U+0031, U+0080, U+00F6, U+20AC, U+1F600, U+FB33
orders differ    : True
```

The test's expected output places U+1F600 (grinning face) **before** U+FB33 (Hebrew dalet with dagesh) — UTF-16 code-unit ordering. A code-point-sorting implementation would fail this assertion. It passed, so the engine implements 3.2.3 property ordering, not ordinary Unicode sorting.

## C. Execution result

```
$ cargo test --test c1_full_domain_jcs
   Compiling aura-guard v1.3.0 (/home/user/aura-guard-v1.3)
   Compiling serde_json_canonicalizer v0.3.2
    Finished `test` profile [unoptimized + debuginfo] target(s) in 53.20s
     Running conformance/canonical/c1_full_domain_jcs.rs (target/debug/deps/c1_full_domain_jcs-062b64bab4c4dd2e)

running 9 tests
test c1_boundary_lone_surrogate_is_rejected_before_canonicalization ... ok
test c1_boundary_nonfinite_numbers_are_not_json_values ... ok
test c1_i_json_duplicate_property_is_rejected_as_input_precondition ... ok
test c1_recursive_object_and_array_order_is_preserved ... ok
test c1_rfc_utf16_property_sorting_sample ... ok
test c1_rfc_section_3_2_2_primitive_and_string_sample ... ok
test c1_rfc_appendix_b_number_serialization_samples ... ok
test c1_utf8_is_exactly_the_canonical_output_encoding ... ok
test c1_whitespace_is_not_emitted ... ok

test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

| Metric | Value |
|---|---|
| Total | 9 |
| Passed | 9 |
| Failed | 0 |
| Ignored | 0 |
| Filtered out | 0 |
| Panicked | 0 |
| **Exit code** | **0** |

Re-run with `-- --nocapture`: identical result, exit code `0`.

Supporting run — `cargo test --test canonical_001`: `5 passed; 0 failed; 0 ignored`, exit code `0`. This is context only; CANONICAL-001 passing is **not** evidence for C1.

### C.1 Numeric corpus detail (24 sub-cases, all passing)

| Input | Expected canonical | Boundary exercised |
|---|---|---|
| `0` | `0` | zero |
| `-0.0` | `0` | negative zero collapses to `0` (3.2.2.3) |
| `5e-324` / `-5e-324` | unchanged | min denormal |
| `1.7976931348623157e+308` / negative | unchanged | max finite double |
| `9007199254740992` / negative | unchanged | 2^53 integer |
| `295147905179352830000` | unchanged | large integer below the 1e21 threshold |
| `9.999999999999997e+22`, `1e+23`, `1.0000000000000001e+23` | unchanged | exponential notation |
| `999999999999999700000`, `999999999999999900000` | unchanged | just below the 1e21 threshold, so plain notation |
| `1e+21` | `1e+21` | at the 1e21 threshold, so exponential |
| `9.999999999999997e-7` | unchanged | below 1e-6, so exponential |
| `0.000001` | `0.000001` | at 1e-6, so plain |
| `333333333.3333332`, `.33333325`, `.3333333`, `.3333334`, `.33333343` | unchanged | shortest round-trip rounding boundary |
| `-0.0000033333333333333333` | unchanged | small negative decimal |
| `1424953923781206.25` | `1424953923781206.2` | ECMAScript shortest-representation rounding |

Every expected value is the RFC/ECMAScript representation, not "whatever serde_json emits". The last row is the proof: echoing the input would have produced `1424953923781206.25` and failed.

## D. Failure details

None. No test failed, panicked, or was ignored.

## E. Environment limitations and scope boundaries

Execution itself was unconstrained: dependency resolution succeeded, compilation succeeded, all tests ran. The following are **scope boundaries of the C1 corpus**, recorded so PASS is not over-read. They are not failures, and no expected value was altered on their account.

1. **Duplicate-property rejection is NOT demonstrated — it is demonstrated to be absent from this surface.** `jcs.rs` accepts an already-materialized `serde_json::Value`, so duplicate names cannot be observed. `serde_json::from_str` on `{"a":1,"a":2}` succeeds with last-wins semantics, and the test asserts exactly that (`parsed["a"] == 2`, canonical output `{"a":2}`). This matches the boundary documented above in *"Important boundary: duplicate properties"* — observed parser behavior and documented contract agree. **RFC 8785 3.1 requires the I-JSON input-validation step to reject duplicates; no component on this branch performs that rejection.** Any production integration MUST supply it upstream. This is a real precondition gap in the surrounding pipeline, not in the serializer.
2. **Non-finite numbers and lone surrogates are input-boundary cases, not canonicalization cases.** `NaN`, `Infinity`, `-Infinity` and `"\uDEAD"` are rejected by `serde_json::from_str` before `canonical_bytes` is reached. The tests assert rejection only; **no canonical output was manufactured for invalid input**, as required.
3. **Only a lone low surrogate (`\uDEAD`) is covered.** A lone high surrogate (`\uD800`) and an unpaired-then-valid sequence are not in the corpus. Both are rejected by the same parser path, so this is coverage narrowness rather than a divergence.
4. **The corpus tests the engine, not its reachability.** `jcs.rs` remains unexported from `src/` and `serde_json_canonicalizer` remains a dev-dependency. C1 says nothing about production wiring.
5. **ENT-007 representative structures are DEFERRED** to DQ-003, per the C1 matrix above, and were not exercised here.

## F. Verdict

```
C1 = PASS
```

All 9 mandatory C1 tests executed and passed; exit code `0`; 0 failed, 0 ignored. The expected vectors are RFC-derived and were independently verified to be discriminating.

## G. Custodian consequence

> **Eligible for Custodian review of conditional JCS production promotion.**

The following are explicitly **NOT** done and **NOT** authorized by this result:

- `serde_json_canonicalizer` remains in `[dev-dependencies]` — **NOT PROMOTED**.
- `jcs.rs` remains unreachable from `src/` — **no production integration**.
- **No ENT-007 adapter**, `audit_record_hash`, `integrity_hash`, or `event_payload_hash` implementation was created.
- **DQ-003 remains OPEN / CONFORMANCE GAP.**
- **C2 NOT STARTED.**
- RI-PY (`aura-poc-a-core-v3.3`) untouched; no cross-language comparison performed.

The Custodian decision on conditional promotion must additionally account for boundary E.1: the I-JSON duplicate-property precondition is unimplemented anywhere in the pipeline, and production integration would need to close it upstream of canonicalization.
