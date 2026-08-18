//! RFC 8785 (JCS) canonical serialization adapter — conformance surface only.
//!
//! # Responsibility
//!
//! Exactly one transformation, and nothing else:
//!
//! ```text
//! serde_json::Value  ->  RFC 8785 JCS  ->  Vec<u8>
//! ```
//!
//! # What this is NOT
//!
//! This adapter is **not** wired into the production runtime. It is not
//! reachable from `src/`, it does not touch `src/merkle.rs`, and it does not
//! change any hash domain, Merkle semantic, or protocol semantic. It exists so
//! that CANONICAL-001 can execute the canonical-serialization contract against
//! a real RFC 8785 implementation without perturbing the shipping code path.
//!
//! Integration of JCS into the production serializer is a separate, not-yet-
//! approved decision (DQ-006 remains open until cross-language equality is
//! demonstrated).
//!
//! # Engine
//!
//! [`serde_json_canonicalizer`] (pinned `=0.3.2`, MIT). Plain
//! `serde_json::to_vec` / `serde_json::to_string` are deliberately **not**
//! used as canonical serializers: they emit insertion/BTree order with
//! serde_json's own number formatting, which is not the RFC 8785 contract.

/// Serialize `value` to RFC 8785 canonical UTF-8 bytes.
///
/// Key ordering, number formatting, and string escaping are decided by the
/// JCS engine — the caller supplies no ordering hints and performs no
/// pre-normalization.
///
/// # Errors
///
/// Returns the underlying [`serde_json::Error`] if the value cannot be
/// canonically serialized (e.g. non-string map keys, or a non-finite number).
pub fn canonical_bytes(value: &serde_json::Value) -> Result<Vec<u8>, serde_json::Error> {
    serde_json_canonicalizer::to_vec(value)
}
