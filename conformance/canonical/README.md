# CANONICAL-001 — RI-RS canonical serialization conformance

Frozen conformance probe for **DQ-006**. Scope is deliberately narrow: it proves
that the Rust reference implementation (RI-RS) can execute the canonical
serialization + hash-domain contract. It proves nothing else.

## Contract

```
JSON object
    -> RFC 8785 JCS
    -> canonical UTF-8 bytes
    -> SHA-256(canonical_bytes)
    -> SHA-256(0x00 || canonical_bytes)      (RFC 6962 leaf domain)
```

## Layout

| File | Role |
| --- | --- |
| `CANONICAL-001.json` | Frozen input object. Key order here is intentionally non-canonical — ordering is the JCS engine's job. |
| `jcs.rs` | Adapter: `serde_json::Value -> RFC 8785 -> Vec<u8>`. Nothing else. |
| `canonical_001.rs` | The executable conformance test (`cargo test --test canonical_001`). |

## Engine

[`serde_json_canonicalizer`](https://github.com/evik42/serde-json-canonicalizer)
`=0.3.2` (MIT), a **dev-dependency only**. `serde_json::to_vec` /
`serde_json::to_string` are not used as canonical serializers.

## Observed values

```
canonical_bytes (UTF-8) {"event_type":"AUDIT_RECORD","payload":{"value":42},"protocol_version":"1.0","schema_version":"1.0"}
canonical_bytes (hex)   7b226576656e745f74797065223a2241554449545f5245434f5244222c227061796c6f6164223a7b2276616c7565223a34327d2c2270726f746f636f6c5f76657273696f6e223a22312e30222c22736368656d615f76657273696f6e223a22312e30227d
SHA-256(canonical)      b6c3660ce6dee498b37443a92bf87c5efead6fe863fcf19197c0baeda139a4e6
SHA-256(0x00||canonical) ce6b36733d97699230f37d80a14e14104c19d2e787526a6fc3aaae6b6648c039
```

Every value above is **computed** by the test from the JCS output; none is
asserted constant-against-constant. Comparison against the expected canonical
bytes is byte-for-byte, not semantic JSON equality.

## Boundaries

* `src/merkle.rs` is **read, never written**. `merkle_leaf_domain_matches_rfc6962`
  observes the shipping `leaf_hash` and reports agreement; it does not repair it.
* JCS is **not** wired into the production runtime, the production serializer, or
  the Merkle engine. That integration is a separate, unapproved decision.
* No existing hash domain, Merkle semantic, protocol semantic, `event_type`
  semantic, fixture, or expected digest was changed.
* This probe does **not** demonstrate `RI-PY == RI-RS`. Cross-language equality
  is the next phase; DQ-006 stays open until then, and DQ-002 is untouched.
