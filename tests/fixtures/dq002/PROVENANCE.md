# DQ-002 fixture provenance (RI-RS)

`FIX-CK003-DQ002-*.json` are verbatim copies of the DQ-002 fixtures held in
`Aura-IDToken/aura-specification`. They are vendored so `cargo test` needs no
cross-repository checkout. **This repository is not their authority.**

| Item | Value |
| --- | --- |
| Source repository | Aura-IDToken/aura-specification |
| Source branch | claude/aura-cross-language-002-6t2kdo |
| Source path | `ck003/dq-002-hash-domain/fixtures/` |
| Copied | 2026-08-18 |

`RI-RS-VECTORS.json` is **generated output**, not an input fixture. It is
produced by `tests/dq002_cross_language.rs::dq002_emit_cross_language_vectors`
and is the RI-RS half of the CROSS-LANGUAGE-002 comparison. Regenerate it with
`cargo test --test dq002_cross_language`; never edit it by hand.

| File | Role | SHA-256 |
| --- | --- | --- |
| `FIX-CK003-DQ002-RFC6962-2LEAF.json` | input fixture | `bf21d2b8f3c947ebaf23bc7662f1ac8e590ef6c3a77850e27c84422967ce9aae` |
| `FIX-CK003-DQ002-RFC6962-EDGE-MATRIX.json` | input fixture | `dfa5320cb06ba1a3eb88ad60424869e9722384b29f310ee9978390811f9f3eb8` |
| `RI-RS-VECTORS.json` | generated output | `82e47587b046bfdb121a5170b967a44403dd98ccd6cbbfedd2321db010e8a67b` |

The expected values in the two `FIX-` files were produced by an independent
GNU coreutils SHA-256 oracle
(`ck003/dq-002-hash-domain/tools/rfc6962_oracle.sh`), not by this crate and not
by RI-PY. Passing these tests is conformance evidence against
`ADR-CK003-DQ002-HASH-DOMAIN`, whose status is
`PROPOSED — awaiting Chief Architect approval`. It does not make the contract
normative and does not close DQ-002.
