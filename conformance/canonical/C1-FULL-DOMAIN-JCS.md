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
