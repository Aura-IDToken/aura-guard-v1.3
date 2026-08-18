#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    #[test]
    fn canonical_001_is_blocked_until_jcs_binding() {
        // The production Merkle core is intentionally not changed here.
        // This test records the required independent oracle and remains
        // non-conformant until the RFC 8785 JCS adapter is bound.
        let expected_leaf = "ce6b36733d97699230f37d80a14e14104c19d2e787526a6fc3aaae6b6648c039";
        let canonical_bytes_hex = "7b226576656e745f74797065223a2241554449545f5245434f5244222c227061796c6f6164223a7b2276616c7565223a34327d2c2270726f746f636f6c5f76657273696f6e223a22312e30222c22736368656d615f76657273696f6e223a22312e30227d";
        let bytes = hex::decode(canonical_bytes_hex).expect("valid oracle hex");
        let mut preimage = Vec::with_capacity(bytes.len() + 1);
        preimage.push(0x00);
        preimage.extend_from_slice(&bytes);
        let actual_leaf = format!("{:x}", Sha256::digest(&preimage));
        assert_eq!(actual_leaf, expected_leaf);
        // This validates only the frozen oracle/hash domain, not JCS execution.
        // JCS conformance remains BLOCKED until conformance/canonical/jcs.rs is bound.
    }
}
