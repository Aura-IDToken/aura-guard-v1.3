# RI-RS CANONICAL-001 Conformance

Status: BLOCKED_PENDING_JCS_BOUNDARY

This test MUST execute the exact CANONICAL-001 object from aura-specification.

Required outputs:
1. canonical_bytes_hex
2. SHA-256(canonical_bytes)
3. SHA-256(0x00 || canonical_bytes)

Expected independent oracle:
- canonical_bytes_hex = 7b226576656e745f74797065223a2241554449545f5245434f5244222c227061796c6f6164223a7b2276616c7565223a34327d2c2270726f746f636f6c5f76657273696f6e223a22312e30222c22736368656d615f76657273696f6e223a22312e30227d
- SHA-256(canonical_bytes) = b6c3660ce6dee498b37443a92bf87c5efead6fe863fcf19197c0baeda139a4e6
- leaf = ce6b36733d97699230f37d80a14e14104c19d2e787526a6fc3aaae6b6648c039

A PASS requires equality of all three values. If the Guard has no RFC 8785 JCS boundary, the result MUST remain BLOCKED.
