//! EP-BOUNDARY-001 — Event Payload input validation.
//!
//! The I-JSON input stage that RFC 8785 §3.1 requires, and that
//! [`crate::canonical`] deliberately does not perform.
//!
//! # Why this module exists
//!
//! [`serde_json::Value`] **cannot represent a duplicate object member name**.
//! Parsing `{"a":1,"a":2}` yields a map of length 1 — last-wins, silently. Any
//! validator that parses to a `Value` and inspects it afterwards is inspecting
//! evidence that has already been destroyed.
//!
//! [`validate_event_payload`] therefore rejects the second occurrence of a
//! member name **while the document is still being streamed off the parser**,
//! before the enclosing map is built.
//!
//! ```text
//! raw UTF-8 bytes
//!      │  UTF-8 check                    -> EventPayloadError::InvalidUtf8
//!      ▼
//!    &str
//!      │  streaming parse                -> EventPayloadError::MalformedJson
//!      │    duplicate member name, any   -> EventPayloadError::DuplicateMember
//!      │    depth, detected in-stream
//!      ▼
//! serde_json::Value  (duplicate-free by construction)
//!      │  top-level shape                -> EventPayloadError::NonObjectTopLevel
//!      ▼
//! validated Event Payload object
//!      │  crate::canonical::canonical_bytes
//!      ▼
//! RFC 8785 canonical bytes
//! ```
//!
//! # Scope
//!
//! Input validation only. This module computes no hash, defines no hash
//! domain, and knows nothing about ENT-007, Audit Records, or the evidence
//! chain. It provides the validated input boundary that a future Event Payload
//! implementation may consume; that composition is a later gate.
//!
//! # Error codes
//!
//! [`EventPayloadError`] variants are Rust-level categories for callers to
//! branch on. They are **not** APS-200 normative error codes — no
//! machine-readable protocol error taxonomy is defined yet
//! (`ERROR-CODE TAXONOMY: TBD — separate contract`).
//!
//! # Known unspecified behavior
//!
//! `C2-1-TBD-UNICODE-NORMALIZATION` — duplicate detection compares member
//! names by exact string equality. Whether two names differing only by Unicode
//! normalization form (NFC vs NFD) must be treated as duplicates is not
//! specified by RFC 8785 §3.1 or by any Aura artifact. This module performs no
//! normalization and does not resolve the question.

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use std::fmt;
use thiserror::Error;

/// Marker embedded in the streaming reader's `serde` error so the outer
/// function can distinguish a duplicate-member rejection from an ordinary
/// syntax error without threading a custom error type through `serde`.
const DUPLICATE_SENTINEL: &str = "duplicate member name";

/// Why an Event Payload was refused at the input boundary.
///
/// These are implementation categories, not APS-200 normative error codes.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum EventPayloadError {
    /// The raw bytes are not valid UTF-8.
    #[error("event payload is not valid UTF-8")]
    InvalidUtf8,

    /// The bytes are valid UTF-8 but not well-formed JSON.
    #[error("event payload is not well-formed JSON: {0}")]
    MalformedJson(String),

    /// A JSON object contained the same member name twice, at some depth.
    ///
    /// RFC 8785 §3.1 requires the I-JSON input stage to reject this.
    #[error("event payload contains a duplicate object member name: '{0}'")]
    DuplicateMember(String),

    /// The Event Payload's top-level JSON value is not an object.
    ///
    /// RFC 8785 canonicalizes any JSON value; requiring an object at the top
    /// level is an Aura constraint on the Event Payload specifically.
    #[error("event payload top-level value must be a JSON object")]
    NonObjectTopLevel,
}

/// A JSON value parsed with duplicate object member names rejected at every
/// depth.
///
/// The rejection happens inside [`Visitor::visit_map`], while member names are
/// still being pulled off the parser — not after a [`serde_json::Map`] has
/// silently collapsed them.
struct StrictJson(Value);

impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StrictVisitor;

        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = Value;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("any JSON value with no duplicate object member names")
            }

            fn visit_unit<E>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }
            fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
                Ok(Value::Bool(v))
            }
            fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
                Ok(Value::from(v))
            }
            fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
                Ok(Value::from(v))
            }
            fn visit_f64<E>(self, v: f64) -> Result<Value, E> {
                Ok(Value::from(v))
            }
            fn visit_str<E>(self, v: &str) -> Result<Value, E> {
                Ok(Value::String(v.to_owned()))
            }
            fn visit_string<E>(self, v: String) -> Result<Value, E> {
                Ok(Value::String(v))
            }

            /// Array elements recurse through `StrictJson`, so an object nested
            /// inside an array is validated exactly like a top-level one.
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
                let mut items = Vec::new();
                while let Some(StrictJson(v)) = seq.next_element()? {
                    items.push(v);
                }
                Ok(Value::Array(items))
            }

            /// The duplicate check. `next_key` yields member names in document
            /// order; the second occurrence aborts the parse.
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
                let mut out = serde_json::Map::new();
                while let Some(name) = map.next_key::<String>()? {
                    if out.contains_key(&name) {
                        return Err(de::Error::custom(format!("{DUPLICATE_SENTINEL}: {name}")));
                    }
                    let StrictJson(value) = map.next_value()?;
                    out.insert(name, value);
                }
                Ok(Value::Object(out))
            }
        }

        deserializer.deserialize_any(StrictVisitor).map(StrictJson)
    }
}

/// Validate raw Event Payload bytes and return the accepted JSON object.
///
/// Only a value returned by this function is eligible to enter
/// [`crate::canonical::canonical_bytes`].
///
/// Guarantees, in this order:
///
/// 1. the input is valid UTF-8;
/// 2. the input is well-formed JSON;
/// 3. no object anywhere in the document repeats a member name — checked
///    in-stream, **before** the value is materialized;
/// 4. the top-level value is a JSON object.
///
/// # Errors
///
/// Returns the [`EventPayloadError`] describing the first violation found.
/// Because duplicate detection runs during parsing, a document containing both
/// a duplicate member and a later syntax error is reported as
/// [`EventPayloadError::DuplicateMember`].
pub fn validate_event_payload(raw: &[u8]) -> Result<Value, EventPayloadError> {
    // 1. UTF-8, checked on the raw bytes so it stays distinguishable from a
    //    JSON syntax error.
    let text = std::str::from_utf8(raw).map_err(|_| EventPayloadError::InvalidUtf8)?;

    // 2-3. Well-formed JSON, with duplicate member names rejected recursively
    //      while the document is still being streamed.
    let value = serde_json::from_str::<StrictJson>(text)
        .map(|StrictJson(v)| v)
        .map_err(|e| {
            let message = e.to_string();
            match message.split_once(&format!("{DUPLICATE_SENTINEL}: ")) {
                Some((_, rest)) => {
                    let name = rest.split(" at line ").next().unwrap_or(rest);
                    EventPayloadError::DuplicateMember(name.to_owned())
                }
                None => EventPayloadError::MalformedJson(message),
            }
        })?;

    // 4. Event Payload top-level value MUST be a JSON object.
    if !value.is_object() {
        return Err(EventPayloadError::NonObjectTopLevel);
    }

    Ok(value)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::canonical::canonical_bytes;

    fn accept(raw: &str) -> Value {
        validate_event_payload(raw.as_bytes())
            .unwrap_or_else(|e| panic!("expected ACCEPT for {raw}, got {e:?}"))
    }

    fn reject(raw: &str) -> EventPayloadError {
        match validate_event_payload(raw.as_bytes()) {
            Ok(v) => panic!("expected REJECT for {raw}, got ACCEPT with {v}"),
            Err(e) => e,
        }
    }

    fn dup(name: &str) -> EventPayloadError {
        EventPayloadError::DuplicateMember(name.to_owned())
    }

    // --- EP-BOUNDARY-001 mandatory corpus A-J ----------------------------

    #[test]
    fn a_valid_object_is_accepted() {
        assert_eq!(accept(r#"{"a":1}"#), serde_json::json!({"a": 1}));
    }

    #[test]
    fn b_top_level_array_is_rejected() {
        assert_eq!(reject("[1,2]"), EventPayloadError::NonObjectTopLevel);
    }

    #[test]
    fn c_top_level_scalar_is_rejected() {
        for raw in ["42", r#""text""#, "null", "true"] {
            assert_eq!(reject(raw), EventPayloadError::NonObjectTopLevel);
        }
    }

    #[test]
    fn d_duplicate_top_level_property_is_rejected() {
        assert_eq!(reject(r#"{"a":1,"a":2}"#), dup("a"));
    }

    #[test]
    fn e_duplicate_nested_property_is_rejected() {
        assert_eq!(reject(r#"{"outer":{"a":1,"a":2}}"#), dup("a"));
    }

    #[test]
    fn f_duplicate_inside_array_element_is_rejected() {
        assert_eq!(reject(r#"[{"a":1,"a":2}]"#), dup("a"));
        assert_eq!(reject(r#"{"arr":[{"a":1,"a":2}]}"#), dup("a"));
    }

    #[test]
    fn g_three_way_duplicate_is_rejected() {
        assert_eq!(reject(r#"{"a":1,"a":2,"a":3}"#), dup("a"));
    }

    #[test]
    fn h_type_changing_duplicate_is_rejected() {
        assert_eq!(reject(r#"{"a":1,"a":"x"}"#), dup("a"));
        assert_eq!(reject(r#"{"a":{"deep":1},"a":"scalar"}"#), dup("a"));
    }

    #[test]
    fn i_valid_nested_object_is_accepted() {
        assert_eq!(
            accept(r#"{"outer":{"a":1,"b":[2,3]}}"#),
            serde_json::json!({"outer": {"a": 1, "b": [2, 3]}})
        );
    }

    #[test]
    fn j_valid_unicode_object_is_accepted() {
        let v = accept(r#"{"k":"€ / 😀 / דּ / å / 中文","€":"euro"}"#);
        assert_eq!(v["k"], "€ / 😀 / דּ / å / 中文");
        assert_eq!(v["€"], "euro");
    }

    // --- recursion depth --------------------------------------------------

    #[test]
    fn duplicate_is_detected_at_arbitrary_depth() {
        assert_eq!(reject(r#"{"w":{"x":{"y":{"z":1,"z":2}}}}"#), dup("z"));
        assert_eq!(reject(r#"{"arr":[0,{"n":{"d":1,"d":2}}]}"#), dup("d"));
    }

    // --- THE critical property: detection precedes information loss -------

    #[test]
    fn detection_precedes_value_materialization() {
        let raw = r#"{"a":1,"a":2}"#;

        // The flawed path: Value collapses the duplicate and reports success.
        let collapsed: Value = serde_json::from_str(raw).expect("Value accepts duplicates");
        assert_eq!(collapsed, serde_json::json!({"a": 2}));
        assert_eq!(
            collapsed.as_object().expect("object").len(),
            1,
            "Value cannot represent a duplicate member: the evidence is already gone"
        );

        // The boundary names the offending member — information the collapsed
        // value above does not contain, so it cannot have come from inspecting
        // a materialized Value.
        assert_eq!(validate_event_payload(raw.as_bytes()), Err(dup("a")));
    }

    #[test]
    fn duplicate_is_reported_before_a_later_syntax_error() {
        // Each input carries a duplicate EARLY and a fatal syntax error LATER.
        // A parse-then-inspect validator can only report the syntax error,
        // because it never obtains a Value to inspect.
        for raw in [r#"{"a":1,"a":2,"#, r#"{"a":1,"a":2,"b":@}"#] {
            assert!(
                serde_json::from_str::<Value>(raw).is_err(),
                "parse-then-inspect cannot reach an inspection step for {raw}"
            );
            assert_eq!(
                validate_event_payload(raw.as_bytes()),
                Err(dup("a")),
                "duplicate must be reported before the later syntax error in {raw}"
            );
        }
    }

    // --- UTF-8 / malformed categories -------------------------------------

    #[test]
    fn invalid_utf8_is_its_own_category() {
        let mut raw: Vec<u8> = br#"{"a":""#.to_vec();
        raw.push(0xFF);
        raw.extend_from_slice(br#""}"#);
        assert_eq!(
            validate_event_payload(&raw),
            Err(EventPayloadError::InvalidUtf8)
        );
    }

    #[test]
    fn malformed_json_is_rejected() {
        for raw in [r#"{"a":1,}"#, r#"{"a":1"#, ""] {
            assert!(matches!(reject(raw), EventPayloadError::MalformedJson(_)));
        }
    }

    #[test]
    fn rfc8785_invalid_values_remain_rejected_at_the_input_stage() {
        for raw in [
            r#"{"n":NaN}"#,
            r#"{"n":Infinity}"#,
            r#"{"n":-Infinity}"#,
            r#"{"t":"\uDEAD"}"#,
            r#"{"t":"\uD800"}"#,
        ] {
            assert!(matches!(reject(raw), EventPayloadError::MalformedJson(_)));
        }
    }

    // --- composition with the promoted canonicalizer ----------------------

    #[test]
    fn validated_payload_composes_with_canonical_bytes() {
        let payload = accept(r#"{ "subject" : "s" , "action" : "ALLOW" , "resource" : "r" }"#);
        let canonical = canonical_bytes(&payload).expect("JCS canonicalization must succeed");
        assert_eq!(
            canonical,
            br#"{"action":"ALLOW","resource":"r","subject":"s"}"#
        );

        // The rejected form never reaches canonicalization.
        assert!(validate_event_payload(br#"{"action":"ALLOW","action":"DENY"}"#).is_err());
    }
}
