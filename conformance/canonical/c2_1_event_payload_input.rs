#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! C2-1 — Event Payload input boundary, executable evidence.
//!
//! # What this is
//!
//! A **test-only** reference validator for EP-BOUNDARY-001 plus the conformance
//! corpus that proves it. It exists to demonstrate that the boundary C2 found
//! missing is satisfiable with the dependencies already in this repository, and
//! to give the Custodian executable evidence for the JCS promotion decision.
//!
//! # What this is NOT
//!
//! - **Not production code.** Nothing here is reachable from `src/`. The
//!   production input path (`src/api/audit.rs` -> `Json<AuditRequest>`) is
//!   untouched, and no `src/` module gained an input validator.
//! - **Not a change to RFC 8785 semantics.** `conformance/canonical/jcs.rs` is
//!   byte-identical to `main`. Duplicate detection is deliberately kept
//!   *outside* `canonical_bytes`, because RFC 8785 3.1 places it in the I-JSON
//!   input stage, not in the serializer.
//! - **Not ENT-007.** No `event_payload_hash`, `audit_record_hash`,
//!   `integrity_hash`, or `previous_record_hash` is computed here.
//! - **Not a dependency promotion.** `serde_json_canonicalizer` remains a
//!   dev-dependency. The validator uses only `serde` + `serde_json`, which the
//!   package already depends on; C2-1 adds no dependency of any kind.
//!
//! # The property that matters
//!
//! `serde_json::Value` cannot represent a duplicate member name: parsing
//! `{"a":1,"a":2}` yields a map of length 1. Any validator that parses to
//! `Value` first and inspects afterwards is therefore inspecting evidence that
//! has already been destroyed. The reader below hooks `MapAccess` and rejects
//! the second occurrence of a name **as it is streamed**, before the enclosing
//! map is built. `c2_1_detection_precedes_value_materialization` and
//! `c2_1_duplicate_is_reported_before_a_later_syntax_error` prove that ordering
//! rather than asserting it.

mod jcs;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use std::fmt;

/// Marker embedded in the streaming reader's error so the caller can classify a
/// duplicate-member rejection without a bespoke error type crossing the serde
/// boundary. Machine-readable protocol error codes are out of C2-1 scope
/// (TBD - separate error-code contract).
const DUPLICATE_SENTINEL: &str = "duplicate member name";

/// Deterministic failure categories for EP-BOUNDARY-001.
///
/// These are C2-1 categories only. They are deliberately **not** frozen into
/// APS-200 and carry no machine-readable code yet.
#[derive(Debug, PartialEq, Eq)]
enum EpRejection {
    /// Raw bytes are not valid UTF-8.
    InvalidUtf8,
    /// Bytes are valid UTF-8 but not well-formed JSON.
    MalformedJson,
    /// A JSON object contained the same member name twice, at any depth.
    DuplicateMember(String),
    /// The Event Payload's top-level JSON value is not an object.
    NonObjectTopLevel,
}

/// A JSON value read with duplicate object member names rejected at every depth.
///
/// The reject happens inside [`Visitor::visit_map`], while member names are
/// still being streamed off the parser -- not after a `serde_json::Map` has
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

            /// Arrays recurse through `StrictJson`, so an object nested inside
            /// an array element is validated identically to a top-level one.
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
                let mut items = Vec::new();
                while let Some(StrictJson(v)) = seq.next_element()? {
                    items.push(v);
                }
                Ok(Value::Array(items))
            }

            /// The duplicate check. `next_key` yields each member name in
            /// document order; the second occurrence aborts the parse.
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
                let mut out = serde_json::Map::new();
                while let Some(name) = map.next_key::<String>()? {
                    if out.contains_key(&name) {
                        return Err(de::Error::custom(format!(
                            "{DUPLICATE_SENTINEL}: {name}"
                        )));
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

/// EP-BOUNDARY-001 reference validator: raw UTF-8 JSON bytes -> validated
/// Event Payload object.
///
/// Only a value returned by this function is eligible to enter RFC 8785
/// canonicalization.
fn validate_event_payload(raw: &[u8]) -> Result<Value, EpRejection> {
    // 1. UTF-8, checked on the raw bytes so it is distinguishable from a
    //    JSON syntax error.
    let text = std::str::from_utf8(raw).map_err(|_| EpRejection::InvalidUtf8)?;

    // 2 + 3 + 4. Well-formed JSON, with duplicate member names rejected
    //    recursively while the document is still being streamed.
    let value = serde_json::from_str::<StrictJson>(text)
        .map(|StrictJson(v)| v)
        .map_err(|e| {
            let msg = e.to_string();
            match msg.split_once(&format!("{DUPLICATE_SENTINEL}: ")) {
                Some((_, rest)) => {
                    let name = rest.split(" at line ").next().unwrap_or(rest);
                    EpRejection::DuplicateMember(name.to_owned())
                }
                None => EpRejection::MalformedJson,
            }
        })?;

    // 5. Event Payload top-level value MUST be a JSON object.
    if !value.is_object() {
        return Err(EpRejection::NonObjectTopLevel);
    }

    Ok(value)
}

fn accept(raw: &str) -> Value {
    validate_event_payload(raw.as_bytes())
        .unwrap_or_else(|e| panic!("expected ACCEPT for {raw}, got {e:?}"))
}

fn reject(raw: &str) -> EpRejection {
    match validate_event_payload(raw.as_bytes()) {
        Ok(v) => panic!("expected REJECT for {raw}, got ACCEPT with {v}"),
        Err(e) => e,
    }
}

// ---------------------------------------------------------------------------
// Mandatory corpus A-J
// ---------------------------------------------------------------------------

#[test]
fn c2_1_a_valid_object_is_accepted() {
    assert_eq!(accept(r#"{"a":1}"#), serde_json::json!({"a": 1}));
}

#[test]
fn c2_1_b_top_level_array_is_rejected() {
    assert_eq!(reject(r#"[1,2]"#), EpRejection::NonObjectTopLevel);
}

#[test]
fn c2_1_c_top_level_scalar_is_rejected() {
    assert_eq!(reject("42"), EpRejection::NonObjectTopLevel);
    assert_eq!(reject(r#""text""#), EpRejection::NonObjectTopLevel);
    assert_eq!(reject("null"), EpRejection::NonObjectTopLevel);
    assert_eq!(reject("true"), EpRejection::NonObjectTopLevel);
}

#[test]
fn c2_1_d_duplicate_top_level_property_is_rejected() {
    assert_eq!(
        reject(r#"{"a":1,"a":2}"#),
        EpRejection::DuplicateMember("a".into())
    );
}

#[test]
fn c2_1_e_duplicate_nested_property_is_rejected() {
    assert_eq!(
        reject(r#"{"outer":{"a":1,"a":2}}"#),
        EpRejection::DuplicateMember("a".into())
    );
}

#[test]
fn c2_1_f_duplicate_inside_array_element_is_rejected() {
    // Top-level array is also a NonObjectTopLevel violation, so the duplicate
    // must be caught first -- it is, because parsing completes before the
    // top-level shape is examined.
    assert_eq!(
        reject(r#"[{"a":1,"a":2}]"#),
        EpRejection::DuplicateMember("a".into())
    );
    // Same duplicate, this time inside an array held by a valid object, so the
    // only violation present is the duplicate.
    assert_eq!(
        reject(r#"{"arr":[{"a":1,"a":2}]}"#),
        EpRejection::DuplicateMember("a".into())
    );
}

#[test]
fn c2_1_g_three_way_duplicate_is_rejected() {
    assert_eq!(
        reject(r#"{"a":1,"a":2,"a":3}"#),
        EpRejection::DuplicateMember("a".into())
    );
}

#[test]
fn c2_1_h_type_changing_duplicate_is_rejected() {
    assert_eq!(
        reject(r#"{"a":1,"a":"x"}"#),
        EpRejection::DuplicateMember("a".into())
    );
    assert_eq!(
        reject(r#"{"a":{"deep":1},"a":"scalar"}"#),
        EpRejection::DuplicateMember("a".into())
    );
}

#[test]
fn c2_1_i_valid_nested_object_is_accepted() {
    assert_eq!(
        accept(r#"{"outer":{"a":1,"b":[2,3]}}"#),
        serde_json::json!({"outer": {"a": 1, "b": [2, 3]}})
    );
}

#[test]
fn c2_1_j_valid_unicode_object_is_accepted() {
    let v = accept(r#"{"k":"€ / 😀 / דּ / å / 中文","€":"euro"}"#);
    assert_eq!(v["k"], "€ / 😀 / דּ / å / 中文");
    assert_eq!(v["€"], "euro");
}

// ---------------------------------------------------------------------------
// Recursion depth beyond the mandatory corpus
// ---------------------------------------------------------------------------

#[test]
fn c2_1_duplicate_is_detected_at_arbitrary_depth() {
    assert_eq!(
        reject(r#"{"w":{"x":{"y":{"z":1,"z":2}}}}"#),
        EpRejection::DuplicateMember("z".into())
    );
    assert_eq!(
        reject(r#"{"arr":[0,{"n":{"d":1,"d":2}}]}"#),
        EpRejection::DuplicateMember("d".into())
    );
}

// ---------------------------------------------------------------------------
// THE critical property: detection precedes information loss
// ---------------------------------------------------------------------------

#[test]
fn c2_1_detection_precedes_value_materialization() {
    let raw = r#"{"a":1,"a":2}"#;

    // The flawed path: serde_json::Value collapses the duplicate last-wins and
    // reports success. The duplicated NAME is unrecoverable from this value.
    let collapsed: Value = serde_json::from_str(raw).expect("Value path accepts duplicates");
    assert_eq!(collapsed, serde_json::json!({"a": 2}));
    assert_eq!(
        collapsed.as_object().expect("object").len(),
        1,
        "Value cannot represent a duplicate member: the evidence is already gone"
    );

    // The boundary path: rejected, and it can still name the offending member.
    // That name is information the collapsed Value above does not contain, so
    // it cannot have been derived by inspecting a materialized Value.
    assert_eq!(
        validate_event_payload(raw.as_bytes()),
        Err(EpRejection::DuplicateMember("a".into()))
    );
}

#[test]
fn c2_1_duplicate_is_reported_before_a_later_syntax_error() {
    // Decisive ordering proof. Each input carries a duplicate member EARLY and
    // a fatal syntax error LATER.
    //
    // A parse-then-inspect validator can only ever report the syntax error,
    // because it never obtains a Value to inspect. A streaming validator
    // reports the duplicate, because it aborts at the duplicate first.
    for raw in [r#"{"a":1,"a":2,"#, r#"{"a":1,"a":2,"b":@}"#] {
        assert!(
            serde_json::from_str::<Value>(raw).is_err(),
            "parse-then-inspect cannot reach an inspection step for {raw}"
        );
        assert_eq!(
            validate_event_payload(raw.as_bytes()),
            Err(EpRejection::DuplicateMember("a".into())),
            "duplicate must be reported before the later syntax error in {raw}"
        );
    }
}

// ---------------------------------------------------------------------------
// UTF-8 / malformed-input categories
// ---------------------------------------------------------------------------

#[test]
fn c2_1_invalid_utf8_is_rejected_as_its_own_category() {
    // {"a":"<0xFF>"}
    let mut raw: Vec<u8> = br#"{"a":""#.to_vec();
    raw.push(0xFF);
    raw.extend_from_slice(br#""}"#);
    assert_eq!(validate_event_payload(&raw), Err(EpRejection::InvalidUtf8));
}

#[test]
fn c2_1_malformed_json_is_rejected() {
    assert_eq!(reject(r#"{"a":1,}"#), EpRejection::MalformedJson);
    assert_eq!(reject(r#"{"a":1"#), EpRejection::MalformedJson);
    assert_eq!(reject(""), EpRejection::MalformedJson);
}

#[test]
fn c2_1_rfc8785_invalid_values_remain_rejected_at_the_input_stage() {
    // Consistent with C1: these never reach canonicalization, and no canonical
    // output is manufactured for them.
    assert_eq!(reject(r#"{"n":NaN}"#), EpRejection::MalformedJson);
    assert_eq!(reject(r#"{"n":Infinity}"#), EpRejection::MalformedJson);
    assert_eq!(reject(r#"{"n":-Infinity}"#), EpRejection::MalformedJson);
    assert_eq!(reject(r#"{"t":"\uDEAD"}"#), EpRejection::MalformedJson);
    assert_eq!(reject(r#"{"t":"\uD800"}"#), EpRejection::MalformedJson);
}

// ---------------------------------------------------------------------------
// Composition: validated payload -> RFC 8785, with jcs.rs unchanged
// ---------------------------------------------------------------------------

#[test]
fn c2_1_validated_payload_composes_with_unmodified_jcs() {
    let payload = accept(r#"{ "subject" : "s" , "action" : "ALLOW" , "resource" : "r" }"#);
    let canonical = jcs::canonical_bytes(&payload).expect("JCS canonicalization must succeed");
    assert_eq!(
        canonical,
        br#"{"action":"ALLOW","resource":"r","subject":"s"}"#
    );

    // And the rejected form never gets that far.
    assert!(validate_event_payload(br#"{"action":"ALLOW","action":"DENY"}"#).is_err());
}
