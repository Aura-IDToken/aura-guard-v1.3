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
}
