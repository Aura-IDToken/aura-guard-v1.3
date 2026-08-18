#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! CANONICAL-001 — RI-RS canonical serialization + hash-domain conformance.
//!
//! # Contract under test
//!
//! ```text
//! JSON object
//!     -> RFC 8785 JCS
//!     -> canonical UTF-8 bytes
//!     -> SHA-256(canonical_bytes)
//!     -> SHA-256(0x00 || canonical_bytes)
//! ```
//!
//! Every stage is **executed**, not asserted from a table: the canonical bytes
//! are produced by a real RFC 8785 engine, both digests are computed from those
//! produced bytes, and the expected values are compared byte-for-byte. A test
//! that only compared two hardcoded constants would prove nothing.
//!
//! # Scope
//!
//! This is a conformance probe for the Rust reference implementation (RI-RS)
//! only. It does **not** claim RI-PY equality, does not close DQ-002, and does
//! not integrate JCS into the production runtime. `src/merkle.rs` is read, never
//! written: `merkle_leaf_domain_matches_rfc6962` observes the shipping
//! `leaf_hash` and reports agreement or disagreement.

mod jcs;

use sha2::{Digest, Sha256};

/// CANONICAL-001 input object. Key order in the source file is deliberately
/// *not* canonical — RFC 8785 ordering is the engine's job, not the fixture's.
const CANONICAL_001_INPUT: &str = include_str!("CANONICAL-001.json");

/// Expected RFC 8785 canonical bytes, hex-encoded.
const EXPECTED_CANONICAL_BYTES_HEX: &str = "7b226576656e745f74797065223a2241554449545f5245434f5244222c227061796c6f6164223a7b2276616c7565223a34327d2c2270726f746f636f6c5f76657273696f6e223a22312e30222c22736368656d615f76657273696f6e223a22312e30227d";

/// Expected `SHA-256(canonical_bytes)`.
const EXPECTED_CANONICAL_SHA256_HEX: &str =
    "b6c3660ce6dee498b37443a92bf87c5efead6fe863fcf19197c0baeda139a4e6";

/// Expected RFC 6962 leaf digest `SHA-256(0x00 || canonical_bytes)`.
const EXPECTED_LEAF_HEX: &str = "ce6b36733d97699230f37d80a14e14104c19d2e787526a6fc3aaae6b6648c039";

/// Produce the canonical bytes for the CANONICAL-001 input by actually running
/// the JCS engine over the parsed object.
fn canonical_001_bytes() -> Vec<u8> {
    let value: serde_json::Value =
        serde_json::from_str(CANONICAL_001_INPUT).expect("CANONICAL-001 input must be valid JSON");
    jcs::canonical_bytes(&value).expect("JCS canonicalization must succeed")
}

/// Stage 1 — RFC 8785 canonical bytes, compared byte-for-byte.
///
/// Semantic JSON equality is explicitly insufficient here: the digest domain is
/// defined over bytes, so only a byte-exact match counts.
#[test]
fn canonical_001_canonical_bytes_are_byte_exact() {
    let actual = canonical_001_bytes();
    let expected = hex::decode(EXPECTED_CANONICAL_BYTES_HEX).expect("expected hex must decode");

    assert_eq!(
        hex::encode(&actual),
        EXPECTED_CANONICAL_BYTES_HEX,
        "CANONICAL-001 canonical bytes differ from the expected RFC 8785 serialization"
    );
    assert_eq!(actual, expected, "byte-for-byte comparison failed");
}

/// Stage 2 — `SHA-256(canonical_bytes)`, computed over the bytes produced in
/// stage 1 rather than over the expected constant.
#[test]
fn canonical_001_sha256_of_canonical_bytes() {
    let bytes = canonical_001_bytes();
    let digest = Sha256::digest(&bytes);

    assert_eq!(
        hex::encode(digest),
        EXPECTED_CANONICAL_SHA256_HEX,
        "SHA-256(canonical_bytes) mismatch"
    );
}

/// Stage 3 — RFC 6962 leaf domain `SHA-256(0x00 || canonical_bytes)`.
///
/// The preimage is asserted structurally before it is hashed: the first byte
/// must be the raw octet `0x00`, and the remainder must be the raw canonical
/// bytes. Hashing the ASCII text `"0x00"`, a hex string, or a re-serialized
/// JSON string would all be wrong domains and are ruled out here.
#[test]
fn canonical_001_leaf_uses_raw_0x00_prefix() {
    let bytes = canonical_001_bytes();

    let mut preimage = Vec::with_capacity(1 + bytes.len());
    preimage.push(0x00u8);
    preimage.extend_from_slice(&bytes);

    assert_eq!(preimage[0], 0x00, "leaf preimage must start with raw 0x00");
    assert_eq!(
        &preimage[1..],
        &bytes[..],
        "leaf preimage must continue with raw canonical bytes"
    );
    assert_eq!(
        preimage.len(),
        bytes.len() + 1,
        "leaf preimage must be exactly one octet longer"
    );

    let leaf = Sha256::digest(&preimage);
    assert_eq!(hex::encode(leaf), EXPECTED_LEAF_HEX, "leaf digest mismatch");
}

/// Merkle compatibility — the shipping `aura_guard::merkle::leaf_hash` must
/// already implement `SHA-256(0x00 || data)`.
///
/// This test **observes** production code. It never modifies `src/merkle.rs`;
/// a mismatch here is reported as a conformance failure, not repaired.
#[test]
fn merkle_leaf_domain_matches_rfc6962() {
    let bytes = canonical_001_bytes();

    let from_production = aura_guard::merkle::leaf_hash(&bytes);
    assert_eq!(
        hex::encode(from_production),
        EXPECTED_LEAF_HEX,
        "production leaf_hash does not implement SHA-256(0x00 || canonical_bytes)"
    );

    // Independent recomputation, so the assertion above cannot pass merely
    // because both sides share the same helper.
    let mut h = Sha256::new();
    h.update([0x00u8]);
    h.update(&bytes);
    assert_eq!(from_production, <[u8; 32]>::from(h.finalize()));
}

/// Full pipeline in one pass, emitting the evidence values under `--nocapture`.
#[test]
fn canonical_001_pipeline_evidence() {
    let value: serde_json::Value =
        serde_json::from_str(CANONICAL_001_INPUT).expect("CANONICAL-001 input must be valid JSON");
    let bytes = jcs::canonical_bytes(&value).expect("JCS canonicalization must succeed");
    let sha = Sha256::digest(&bytes);

    let mut preimage = vec![0x00u8];
    preimage.extend_from_slice(&bytes);
    let leaf = Sha256::digest(&preimage);

    println!(
        "CANONICAL-001 canonical_bytes_utf8 = {}",
        String::from_utf8_lossy(&bytes)
    );
    println!(
        "CANONICAL-001 canonical_bytes_hex  = {}",
        hex::encode(&bytes)
    );
    println!("CANONICAL-001 sha256(canonical)    = {}", hex::encode(sha));
    println!("CANONICAL-001 leaf(0x00||canonical)= {}", hex::encode(leaf));

    assert_eq!(hex::encode(&bytes), EXPECTED_CANONICAL_BYTES_HEX);
    assert_eq!(hex::encode(sha), EXPECTED_CANONICAL_SHA256_HEX);
    assert_eq!(hex::encode(leaf), EXPECTED_LEAF_HEX);
}
