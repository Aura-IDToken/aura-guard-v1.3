# R1-JCS-DISCRIMINATING — RI-RS execution surface

Frozen conformance probe. Same contract as CANONICAL-001; different fixture, and
that difference is the whole point.

## Why

CANONICAL-001 proved RI-RS *can* run an RFC 8785 engine. It could not prove
RFC 8785 was *required*: its fixture is ASCII keys plus one small integer, for
which `serde_json::to_vec` emits byte-identical output. Measured, with
`jcs.rs` temporarily rewired to `serde_json::to_vec`:

```text
cargo test --locked --test canonical_001            5 passed, 0 failed
cargo test --locked --test r1_jcs_discriminating    7 passed, 4 failed
```

CANONICAL-001 does not detect a non-JCS implementation. R1 does.

## Contract

```text
JSON object
    -> RFC 8785 JCS
    -> canonical UTF-8 bytes
    -> SHA-256(canonical_bytes)
    -> SHA-256(0x00 || canonical_bytes)      (RFC 6962 leaf domain)
```

## Fixture

`input.json`, SHA-256
`64b737306d2421092cd9f28a5deb525437100c788ab7c39891aaf6b61cd472ca`, byte-identical
to the copy in `Aura-IDToken/aura-poc-a-core-v3.3`:

```json
{
  "\u{FF3A}": -0.0,
  "a": 1.0,
  "\u{1F600}": 1e-7
}
```

Two independent discriminating dimensions:

* **D1 — UTF-16 code-unit key ordering (RFC 8785 §3.2.3).** `U+1F600` encodes to
  the surrogate pair `D83D DE00`; `U+FF3A` is a lone `FF3A`. Because
  `0xD83D < 0xFF3A`, JCS emits `U+1F600` first — while code-point ordering (which
  is what `serde_json`'s `BTreeMap<String, _>` gives, UTF-8 byte order being
  equivalent) emits it last. The two orderings are inverted.
* **D2 — ECMAScript `Number::toString` (RFC 8785 §3.2.2.3).** `1.0 → 1` and
  `-0.0 → 0`; `serde_json` emits `1.0` and `-0.0`.

The file's own key order is non-canonical under both orderings, so ordering stays
the engine's job.

## Layout

| File | Role |
| --- | --- |
| `input.json` | Frozen fixture input. |
| `ri-rs.json` | RI-RS execution artifact, written by the test run itself. |
| `../../canonical/jcs.rs` | Adapter, shared verbatim with CANONICAL-001. R1 adds no second canonicalization implementation. |
| `../../canonical/r1_jcs_discriminating.rs` | The executable conformance test. |

Run:

```text
cargo test --locked --test r1_jcs_discriminating -- --nocapture
```

Running the test **is** the evidence: it drives the JCS boundary over the
fixture and writes `ri-rs.json` *before* asserting anything, so a mismatch is
recorded rather than hidden. The engine pin is verified against `Cargo.lock`
rather than trusted from a source constant. Nothing here reads an RI-PY value.

## Observed values

```text
canonical_bytes (hex)    7b2261223a312c22f09f9880223a31652d372c22efbcba223a307d
canonical_bytes_len      27
SHA-256(canonical)       a8c01577f4cc4ef73b258cbe66da0103b009fdd88be480c0b811ff2c1ad0946c
SHA-256(0x00||canonical) fb988d990e39fa4f2f35f9158aaa9bac88aad84add3aaf47fb27426eb450656d
```

Discrimination evidence, recorded alongside and never hashed:

```text
serde_json::to_vec       {"a":1.0,"\u{FF3A}":-0.0,"\u{1F600}":1e-7}   32 bytes
```

Cross-language equality against RI-PY (`rfc8785` 0.1.4) is evaluated in
`Aura-IDToken/aura-poc-a-core-v3.3`; see
`conformance/corpus/r1-jcs-discriminating/EXECUTION-EVIDENCE.md` there for the
full evidence package, negative controls and deviations.

## Boundaries

* `src/` is **read, never written**. `r1_merkle_leaf_domain_matches_rfc6962`
  observes the shipping `leaf_hash` and reports agreement; it does not repair it.
* `Cargo.lock` is unchanged. `Cargo.toml` gains a `[[test]]` target registration
  and nothing else — `serde_json_canonicalizer = "=0.3.2"` was already a
  dev-dependency from CANONICAL-001, so the production dependency graph is
  untouched.
* JCS is **not** wired into the production runtime, serializer or Merkle engine.
  That integration remains a separate, unapproved decision.
* This probe does not close DQ-006 or DQ-002.
