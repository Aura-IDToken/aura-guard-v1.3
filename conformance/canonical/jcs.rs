//! Isolated RFC 8785 JCS adapter contract for conformance only.
//! Production Merkle/hash code is intentionally untouched.

use serde_json::Value;

/// Canonicalize a JSON value according to RFC 8785 JCS.
///
/// Implementation is intentionally left as a conformance dependency boundary;
/// the production hash/Merkle core must consume bytes only after this boundary
/// is independently validated.
pub fn canonical_bytes(_value: &Value) -> Result<Vec<u8>, &'static str> {
    Err("JCS implementation dependency not yet bound; conformance remains BLOCKED")
}
