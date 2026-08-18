//! RI-RS CANONICAL-001 execution test.
//!
//! Running this test *is* the RI-RS execution evidence: it drives the frozen
//! JCS boundary over the frozen fixture input, writes the observed values to
//! `conformance/corpus/canonical-001/ri-rs.json`, and only then asserts.
//!
//! Anti-fabrication rules enforced here:
//!
//! * The canonical bytes are whatever the engine returned. They are never
//!   constructed, patched, or corrected against an expectation.
//! * The artifact is written *before* the expectation assertions run, so a
//!   mismatch is recorded as evidence rather than hidden.
//! * Nothing in this crate reads the RI-PY artifact or any RI-PY value.
//!
//! Execution command:
//!
//! ```text
//! cargo test --locked --test canonical_001
//! ```

use aura_guard_conformance as conformance;

/// Frozen CANONICAL-001 reference values.
///
/// These are a *secondary* cross-check. The primary CROSS-LANGUAGE-001 gate is
/// `RI-PY actual == RI-RS actual`, evaluated outside this crate. These
/// constants are never used to produce, patch or backfill the artifact.
const FROZEN_CANONICAL_BYTES_HEX: &str = concat!(
    "7b226576656e745f74797065223a2241554449545f5245434f5244222c227061796c6f6164",
    "223a7b2276616c7565223a34327d2c2270726f746f636f6c5f76657273696f6e223a22312e",
    "30222c22736368656d615f76657273696f6e223a22312e30227d",
);
const FROZEN_SHA256: &str = "b6c3660ce6dee498b37443a92bf87c5efead6fe863fcf19197c0baeda139a4e6";
const FROZEN_LEAF_SHA256: &str = "ce6b36733d97699230f37d80a14e14104c19d2e787526a6fc3aaae6b6648c039";

#[test]
fn canonical_001_execute_and_emit_artifact() {
    let execution = conformance::execute_canonical_001();
    let artifact = conformance::artifact(&execution);

    // Evidence is persisted before any expectation is checked.
    conformance::write_artifact(&artifact);

    eprintln!(
        "RI-RS CANONICAL-001 execution\n{}",
        serde_json::to_string_pretty(&artifact).expect("artifact is serializable")
    );

    // Internal consistency of the emitted artifact.
    assert_eq!(
        artifact["canonical_bytes_hex"].as_str().expect("hex string"),
        hex::encode(&execution.canonical),
    );
    assert_eq!(
        artifact["sha256"].as_str().expect("sha string"),
        conformance::sha256_hex(&execution.canonical),
    );
    assert_eq!(
        artifact["leaf_sha256"].as_str().expect("leaf string"),
        conformance::leaf_sha256_hex(&execution.canonical),
    );
    assert_eq!(
        artifact["engine"].as_str().expect("engine string"),
        "serde_json_canonicalizer",
    );
    assert_eq!(
        artifact["engine_version"].as_str().expect("version string"),
        "0.3.2",
        "frozen protocol contract pins the RI-RS JCS engine to 0.3.2",
    );

    // Secondary cross-check against the frozen reference values.
    assert_eq!(
        hex::encode(&execution.canonical),
        FROZEN_CANONICAL_BYTES_HEX,
        "RI-RS canonical bytes diverge from the frozen CANONICAL-001 reference",
    );
    assert_eq!(execution.sha256, FROZEN_SHA256);
    assert_eq!(execution.leaf_sha256, FROZEN_LEAF_SHA256);
}

#[test]
fn canonical_bytes_are_valid_utf8_and_whitespace_free() {
    let execution = conformance::execute_canonical_001();
    let text = std::str::from_utf8(&execution.canonical).expect("JCS output is UTF-8");
    assert!(!text.contains(' '));
    assert!(!text.contains('\n'));
    assert!(text.starts_with('{') && text.ends_with('}'));
}

#[test]
fn jcs_sorts_object_keys_and_preserves_array_order() {
    let value: serde_json::Value =
        serde_json::from_str(r#"{"b":1,"a":2,"C":3,"arr":[3,1,2]}"#).expect("valid JSON");
    let bytes = conformance::canonical_bytes(&value).expect("canonicalization succeeds");
    assert_eq!(
        std::str::from_utf8(&bytes).expect("UTF-8"),
        r#"{"C":3,"a":2,"arr":[3,1,2],"b":1}"#,
    );
}

#[test]
fn leaf_domain_is_rfc6962_zero_byte() {
    assert_eq!(conformance::LEAF_DOMAIN, 0x00);
    let bytes = b"abc";
    let mut expected = vec![0x00u8];
    expected.extend_from_slice(bytes);
    assert_eq!(
        conformance::leaf_sha256_hex(bytes),
        conformance::sha256_hex(&expected),
    );
}
