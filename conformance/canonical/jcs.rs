//! Isolated RFC 8785 JCS adapter for conformance only.
//! Production Merkle/hash code is intentionally untouched.

use serde_json::Value;

/// Return RFC 8785 JCS UTF-8 bytes for a JSON value.
pub fn canonical_bytes(value: &Value) -> Result<Vec<u8>, serde_json_canonicalizer::Error> {
    serde_json_canonicalizer::to_vec(value)
}
