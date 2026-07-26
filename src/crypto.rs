//! SHA-256 hashing helpers and Ed25519 signature verification.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// Hex-encoded SHA-256 hash of the input string (UTF-8 bytes).
#[must_use]
pub fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

/// Hex-encoded SHA-256 hash of arbitrary bytes.
#[must_use]
pub fn sha256_bytes_hex(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hex::encode(hasher.finalize())
}

/// Genesis hash that seeds the audit chain (`SHA-256("AURA-GUARD-GENESIS-v1.3")`).
///
/// This value is the canonical Root-of-Trust used by every implementation of the
/// chain verifier. It must never be changed without bumping the protocol version.
#[must_use]
pub fn genesis_hash() -> String {
    sha256_hex("AURA-GUARD-GENESIS-v1.3")
}

/// Decode a hex-encoded Ed25519 public key (32 bytes / 64 hex chars).
pub fn parse_pubkey_hex(hex_str: &str) -> Result<VerifyingKey, String> {
    let bytes =
        hex::decode(hex_str.trim()).map_err(|e| format!("invalid hex for public key: {e}"))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("public key must be 32 bytes, got {}", bytes.len()))?;
    VerifyingKey::from_bytes(&arr).map_err(|e| format!("invalid Ed25519 public key: {e}"))
}

/// Verify an Ed25519 signature (hex-encoded, 64 bytes) over `message` using
/// the given verifier `pubkey`.
pub fn verify_signature(
    pubkey: &VerifyingKey,
    message: &[u8],
    signature_hex: &str,
) -> Result<(), String> {
    let sig_bytes =
        hex::decode(signature_hex.trim()).map_err(|e| format!("invalid hex signature: {e}"))?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("signature must be 64 bytes, got {}", sig_bytes.len()))?;
    let signature = Signature::from_bytes(&sig_arr);
    pubkey
        .verify(message, &signature)
        .map_err(|e| format!("Ed25519 verification failed: {e}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_matches_known_vector() {
        assert_eq!(
            sha256_hex(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn genesis_hash_is_stable() {
        // Pin the genesis hash: changing this value is a protocol break.
        assert_eq!(
            genesis_hash(),
            sha256_hex("AURA-GUARD-GENESIS-v1.3"),
            "genesis hash must derive from the canonical protocol seed"
        );
        assert_eq!(genesis_hash().len(), 64);
    }

    // Additional tests for SHA-256 functions
    #[test]
    fn sha256_hex_is_lowercase() {
        let hash = sha256_hex("test");
        assert!(hash.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
    }

    #[test]
    fn sha256_hex_deterministic() {
        let h1 = sha256_hex("deterministic");
        let h2 = sha256_hex("deterministic");
        assert_eq!(h1, h2);
    }

    #[test]
    fn sha256_hex_different_inputs_different_outputs() {
        let h1 = sha256_hex("input1");
        let h2 = sha256_hex("input2");
        assert_ne!(h1, h2);
    }

    #[test]
    fn sha256_hex_sensitive_to_case() {
        let h1 = sha256_hex("Test");
        let h2 = sha256_hex("test");
        assert_ne!(h1, h2);
    }

    #[test]
    fn sha256_hex_unicode_input() {
        let hash = sha256_hex("测试");
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn sha256_hex_long_input() {
        let long = "a".repeat(100000);
        let hash = sha256_hex(&long);
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn sha256_bytes_hex_matches_known_vector() {
        assert_eq!(
            sha256_bytes_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_bytes_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_bytes_hex_vs_sha256_hex_consistent() {
        let input = "test string";
        let h1 = sha256_hex(input);
        let h2 = sha256_bytes_hex(input.as_bytes());
        assert_eq!(h1, h2);
    }

    #[test]
    fn sha256_bytes_hex_binary_data() {
        let binary = vec![0u8, 1u8, 2u8, 255u8];
        let hash = sha256_bytes_hex(&binary);
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // Tests for Ed25519 functions
    #[test]
    fn parse_pubkey_hex_rejects_invalid_hex() {
        let err = parse_pubkey_hex("not_hex").expect_err("should reject invalid hex");
        assert!(err.contains("invalid hex"));
    }

    #[test]
    fn parse_pubkey_hex_rejects_wrong_length() {
        // 31 bytes (62 hex chars) instead of 32
        let short = "a".repeat(62);
        let err = parse_pubkey_hex(&short).expect_err("should reject wrong length");
        assert!(err.contains("32 bytes"));
    }

    #[test]
    fn parse_pubkey_hex_rejects_too_long() {
        // 33 bytes (66 hex chars) instead of 32
        let long = "a".repeat(66);
        let err = parse_pubkey_hex(&long).expect_err("should reject too long");
        assert!(err.contains("32 bytes"));
    }

    #[test]
    fn parse_pubkey_hex_handles_whitespace() {
        // Valid hex with leading/trailing whitespace
        let hex_with_space = "  d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a  ";
        let result = parse_pubkey_hex(hex_with_space);
        assert!(result.is_ok());
    }

    #[test]
    fn parse_pubkey_hex_valid_key() {
        // Valid Ed25519 public key (example from ed25519-dalek test vectors)
        let valid_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let result = parse_pubkey_hex(valid_hex);
        assert!(result.is_ok());
    }

    #[test]
    fn verify_signature_rejects_invalid_hex() {
        let pubkey_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let pubkey = parse_pubkey_hex(pubkey_hex).unwrap();
        let err = verify_signature(&pubkey, b"message", "not_hex")
            .expect_err("should reject invalid signature hex");
        assert!(err.contains("invalid hex"));
    }

    #[test]
    fn verify_signature_rejects_wrong_length() {
        let pubkey_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let pubkey = parse_pubkey_hex(pubkey_hex).unwrap();
        // 63 bytes (126 hex chars) instead of 64
        let short_sig = "a".repeat(126);
        let err = verify_signature(&pubkey, b"message", &short_sig)
            .expect_err("should reject wrong signature length");
        assert!(err.contains("64 bytes"));
    }

    #[test]
    fn verify_signature_handles_whitespace() {
        let pubkey_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let pubkey = parse_pubkey_hex(pubkey_hex).unwrap();
        let sig_with_space = format!("  {}  ", "a".repeat(128));
        // Will fail verification but should not fail parsing
        let result = verify_signature(&pubkey, b"message", &sig_with_space);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("verification failed"));
    }

    #[test]
    fn genesis_hash_idempotent() {
        let g1 = genesis_hash();
        let g2 = genesis_hash();
        assert_eq!(g1, g2);
    }

    #[test]
    fn genesis_hash_format() {
        let g = genesis_hash();
        assert_eq!(g.len(), 64);
        assert!(g.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(g.chars().all(|c| !c.is_ascii_uppercase()));
    }

    // Property-based tests for crypto
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_sha256_hex_always_64_chars(input in ".*") {
            let hash = sha256_hex(&input);
            prop_assert_eq!(hash.len(), 64);
        }

        #[test]
        fn prop_sha256_hex_is_hex(input in ".{0,1000}") {
            let hash = sha256_hex(&input);
            prop_assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
        }

        #[test]
        fn prop_sha256_bytes_hex_always_64_chars(input in prop::collection::vec(any::<u8>(), 0..1000)) {
            let hash = sha256_bytes_hex(&input);
            prop_assert_eq!(hash.len(), 64);
        }

        #[test]
        fn prop_sha256_deterministic(input in ".*") {
            let h1 = sha256_hex(&input);
            let h2 = sha256_hex(&input);
            prop_assert_eq!(h1, h2);
        }

        #[test]
        fn prop_parse_pubkey_hex_rejects_non_hex(s in "[^0-9a-fA-F]+") {
            if !s.is_empty() {
                let result = parse_pubkey_hex(&s);
                prop_assert!(result.is_err());
            }
        }

        #[test]
        fn prop_parse_pubkey_hex_rejects_wrong_length(
            hex in "[0-9a-f]{0,63}|[0-9a-f]{65,128}"
        ) {
            let result = parse_pubkey_hex(&hex);
            prop_assert!(result.is_err());
        }
    }
}
