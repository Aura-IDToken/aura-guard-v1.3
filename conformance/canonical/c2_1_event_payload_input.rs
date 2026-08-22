#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! C2-1 — Event Payload input boundary, executable evidence.
//!
//! # Status: PROMOTED
//!
//! This corpus originally carried its own test-local reference validator, to
//! prove EP-BOUNDARY-001 was satisfiable before any production code existed.
//! The C2-1 promotion gate moved that mechanism into
//! [`aura_guard::event_payload`], so the corpus now exercises the **production**
//! validator. The test cases, inputs, and expected outcomes are unchanged — only
//! the symbol under test moved, from a local copy to the shipped one. A retained
//! local copy would have left this suite verifying code the runtime never calls.
//!
//! # What this proves
//!
//! `serde_json::Value` cannot represent a duplicate member name: parsing
//! `{"a":1,"a":2}` yields a map of length 1. Any validator that parses to
//! `Value` first and inspects afterwards is inspecting evidence that has
//! already been destroyed. The production validator hooks `MapAccess` and
//! rejects the second occurrence of a name **as it is streamed**, before the
//! enclosing map is built. `c2_1_detection_precedes_value_materialization` and
//! `c2_1_duplicate_is_reported_before_a_later_syntax_error` prove that ordering
//! rather than asserting it.
//!
//! # Out of scope
//!
//! No hash is computed here. This suite says nothing about ENT-007,
//! `event_payload_hash`, `audit_record_hash`, `integrity_hash`, or the evidence
//! chain, and it does not bear on DQ-003, which remains OPEN.

mod jcs;

use aura_guard::event_payload::{validate_event_payload, EventPayloadError};
use serde_json::Value;

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

// ---------------------------------------------------------------------------
// Mandatory corpus A-J
// ---------------------------------------------------------------------------

#[test]
fn c2_1_a_valid_object_is_accepted() {
    assert_eq!(accept(r#"{"a":1}"#), serde_json::json!({"a": 1}));
}

#[test]
fn c2_1_b_top_level_array_is_rejected() {
    assert_eq!(reject(r#"[1,2]"#), EventPayloadError::NonObjectTopLevel);
}

#[test]
fn c2_1_c_top_level_scalar_is_rejected() {
    assert_eq!(reject("42"), EventPayloadError::NonObjectTopLevel);
    assert_eq!(reject(r#""text""#), EventPayloadError::NonObjectTopLevel);
    assert_eq!(reject("null"), EventPayloadError::NonObjectTopLevel);
    assert_eq!(reject("true"), EventPayloadError::NonObjectTopLevel);
}

#[test]
fn c2_1_d_duplicate_top_level_property_is_rejected() {
    assert_eq!(reject(r#"{"a":1,"a":2}"#), dup("a"));
}

#[test]
fn c2_1_e_duplicate_nested_property_is_rejected() {
    assert_eq!(reject(r#"{"outer":{"a":1,"a":2}}"#), dup("a"));
}

#[test]
fn c2_1_f_duplicate_inside_array_element_is_rejected() {
    // Top-level array is also a NonObjectTopLevel violation, so the duplicate
    // must be caught first -- it is, because parsing completes before the
    // top-level shape is examined.
    assert_eq!(reject(r#"[{"a":1,"a":2}]"#), dup("a"));
    // Same duplicate, this time inside an array held by a valid object, so the
    // only violation present is the duplicate.
    assert_eq!(reject(r#"{"arr":[{"a":1,"a":2}]}"#), dup("a"));
}

#[test]
fn c2_1_g_three_way_duplicate_is_rejected() {
    assert_eq!(reject(r#"{"a":1,"a":2,"a":3}"#), dup("a"));
}

#[test]
fn c2_1_h_type_changing_duplicate_is_rejected() {
    assert_eq!(reject(r#"{"a":1,"a":"x"}"#), dup("a"));
    assert_eq!(reject(r#"{"a":{"deep":1},"a":"scalar"}"#), dup("a"));
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
    assert_eq!(reject(r#"{"w":{"x":{"y":{"z":1,"z":2}}}}"#), dup("z"));
    assert_eq!(reject(r#"{"arr":[0,{"n":{"d":1,"d":2}}]}"#), dup("d"));
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
    assert_eq!(validate_event_payload(raw.as_bytes()), Err(dup("a")));
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
            Err(dup("a")),
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
    assert_eq!(
        validate_event_payload(&raw),
        Err(EventPayloadError::InvalidUtf8)
    );
}

#[test]
fn c2_1_malformed_json_is_rejected() {
    assert!(matches!(
        reject(r#"{"a":1,}"#),
        EventPayloadError::MalformedJson(_)
    ));
    assert!(matches!(
        reject(r#"{"a":1"#),
        EventPayloadError::MalformedJson(_)
    ));
    assert!(matches!(reject(""), EventPayloadError::MalformedJson(_)));
}

#[test]
fn c2_1_rfc8785_invalid_values_remain_rejected_at_the_input_stage() {
    // Consistent with C1: these never reach canonicalization, and no canonical
    // output is manufactured for them.
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

// ---------------------------------------------------------------------------
// Composition: validated payload -> RFC 8785, both now production surfaces
// ---------------------------------------------------------------------------

#[test]
fn c2_1_validated_payload_composes_with_promoted_jcs() {
    let payload = accept(r#"{ "subject" : "s" , "action" : "ALLOW" , "resource" : "r" }"#);
    let canonical = jcs::canonical_bytes(&payload).expect("JCS canonicalization must succeed");
    assert_eq!(
        canonical,
        br#"{"action":"ALLOW","resource":"r","subject":"s"}"#
    );

    // And the rejected form never gets that far.
    assert!(validate_event_payload(br#"{"action":"ALLOW","action":"DENY"}"#).is_err());
}
