#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! INFRA-002 — byte-representation fixture framework tests.
//!
//! Exercises the generic framework in `tests/support/mod.rs`: fixture storage,
//! deterministic replay, raw-byte comparison, mutation detection, and the
//! separation of semantic identity from byte representation.
//!
//! # Governance boundary
//!
//! **DQ-006 remains unresolved. Nothing here establishes canonical
//! serialization.** No encoding, field order, separator, timestamp form,
//! optional-field rule or numeric representation is selected or proposed for
//! the protocol.
//!
//! Fixtures marked `PROPOSED` are **synthetic comparison inputs built for this
//! test file**. They are not proposed protocol serializations, and they must
//! not be cited as candidate formats.
//!
//! # Recording
//!
//! ```text
//! BYTE_FIXTURES_RECORD=1 cargo test --test byte_representations
//! ```

mod support;

use aura_guard::chain::compute_chain_hash;
use aura_guard::crypto::{genesis_hash, sha256_bytes_hex, sha256_hex};
use aura_guard::normalizer::shadow_normalize;
use support::{
    compare_bytes, compare_fixtures, fixtures_dir, replay, ByteFixture, FixtureSpec, FixtureStatus,
    Property,
};

const SUBDIR: &str = "byte_representations";

// ---------------------------------------------------------------------------
// Observation inputs
//
// Fixed values chosen to make an observation reproducible. They are inputs to
// a measurement, not reference data, and carry no protocol meaning.
// ---------------------------------------------------------------------------

const OBS_DECISION: &str = "DENY";
const OBS_POLICY_SET: &str = "finance-v1";
const OBS_CONTEXT: &str = "Finance Bot";
const OBS_TIMESTAMP_OFFSET_FORM: &str = "2026-01-01T00:00:00+00:00";
const OBS_SEQ: u64 = 0;
const OBS_PROMPT: &str = "Card 4111-1111-1111-1111 please";
const OBS_RESPONSE: &str = "I cannot process that.";

/// Semantic identity shared by every representation below.
const SEM_ENTRY: &str = "SEM-001_entry_chain_record";
/// Semantic identity for the pure framework-demonstration object.
const SEM_DEMO: &str = "SEM-002_framework_demonstration_object";

struct EntryInputs {
    prev_hash: String,
    policy_hash: String,
    input_hash: String,
    shadow_hash: String,
}

fn entry_inputs() -> EntryInputs {
    let combined = format!("{OBS_CONTEXT} {OBS_PROMPT} {OBS_RESPONSE}");
    let policy_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("policies")
        .join("finance-v1.yaml");
    let policy_bytes = std::fs::read(policy_path).expect("read shipped policy");

    EntryInputs {
        prev_hash: genesis_hash(),
        policy_hash: sha256_bytes_hex(&policy_bytes),
        input_hash: sha256_hex(&combined),
        shadow_hash: sha256_hex(&shadow_normalize(&combined)),
    }
}

// ---------------------------------------------------------------------------
// AS_IS_OBSERVED representation
// ---------------------------------------------------------------------------

/// Observe the entry-chain bytes the implementation hashes today.
///
/// The preimage is reconstructed and then proven faithful against
/// `chain::compute_chain_hash`, exactly as INFRA-001 does — no production seam
/// is added.
fn observed_entry_representation() -> ByteFixture {
    let i = entry_inputs();

    let reconstructed = [
        i.prev_hash.as_str(),
        OBS_DECISION,
        OBS_POLICY_SET,
        i.policy_hash.as_str(),
        OBS_CONTEXT,
        i.input_hash.as_str(),
        i.shadow_hash.as_str(),
        &OBS_SEQ.to_string(),
        OBS_TIMESTAMP_OFFSET_FORM,
    ]
    .join("|");

    let production = compute_chain_hash(
        &i.prev_hash,
        OBS_DECISION,
        OBS_POLICY_SET,
        &i.policy_hash,
        OBS_CONTEXT,
        &i.input_hash,
        &i.shadow_hash,
        OBS_SEQ,
        OBS_TIMESTAMP_OFFSET_FORM,
    );

    assert_eq!(
        sha256_hex(&reconstructed),
        production,
        "the reconstruction is no longer faithful to chain::compute_chain_hash"
    );

    ByteFixture::new(
        FixtureSpec {
            fixture_id: "BR-001_entry_chain_observed_rust",
            status: FixtureStatus::AsIsObserved,
            construction_id: SEM_ENTRY,
            representation_id: "observed_rust_delimited",
            encoding: Property::known("UTF-8"),
            field_order: Property::known(
                "prev_hash, decision, policy_set, policy_hash, context, input_hash, shadow_hash, seq, timestamp",
            ),
            separator: Property::known("U+007C"),
            source: "src/chain.rs:25-49; separator src/chain.rs:20",
            notes: "Bytes observed in the current implementation. Not canonical; DQ-006 unresolved.",
        },
        reconstructed.as_bytes(),
    )
}

#[test]
fn br_001_observed_entry_representation_replays() {
    let dir = fixtures_dir(SUBDIR);
    let observed = observed_entry_representation();
    assert_eq!(observed.status, FixtureStatus::AsIsObserved);
    support::assert_stored_and_replayed(&dir, &observed);
}

// ---------------------------------------------------------------------------
// PROPOSED synthetic representations of the SAME semantic object
//
// These exist only to demonstrate that a representation choice changes bytes.
// They are NOT proposed serializations for the protocol.
// ---------------------------------------------------------------------------

/// Same semantic fields, timestamp rendered in the `Z` form instead of the
/// `+00:00` form the implementation emits.
///
/// This fixture does **not** propose the `Z` form. It exists to demonstrate
/// that the unresolved choice produces different bytes and a different digest.
fn synthetic_timestamp_z_representation() -> ByteFixture {
    let i = entry_inputs();
    let synthetic = [
        i.prev_hash.as_str(),
        OBS_DECISION,
        OBS_POLICY_SET,
        i.policy_hash.as_str(),
        OBS_CONTEXT,
        i.input_hash.as_str(),
        i.shadow_hash.as_str(),
        &OBS_SEQ.to_string(),
        "2026-01-01T00:00:00Z",
    ]
    .join("|");

    ByteFixture::new(
        FixtureSpec {
            fixture_id: "BR-002_entry_chain_synthetic_timestamp_z",
            status: FixtureStatus::Proposed,
            construction_id: SEM_ENTRY,
            representation_id: "synthetic_delimited_timestamp_z",
            encoding: Property::known("UTF-8"),
            field_order: Property::known("same as BR-001"),
            separator: Property::known("U+007C"),
            source: "synthetic; constructed in tests/byte_representations.rs",
            notes: "Synthetic comparison input only. Does NOT propose the Z timestamp form \
                    or any other form. Demonstrates that an unresolved representation choice \
                    changes the bytes and the digest. DQ-006 unresolved.",
        },
        synthetic.as_bytes(),
    )
}

#[test]
fn br_002_synthetic_representation_replays() {
    let dir = fixtures_dir(SUBDIR);
    let f = synthetic_timestamp_z_representation();
    assert_eq!(f.status, FixtureStatus::Proposed);
    support::assert_stored_and_replayed(&dir, &f);
}

/// A purely synthetic demonstration object with an unknown provenance, used to
/// exercise the `UNKNOWN` path of the property model.
fn synthetic_demo_representation() -> ByteFixture {
    ByteFixture::new(
        FixtureSpec {
            fixture_id: "BR-003_demo_object_unknown_properties",
            status: FixtureStatus::Proposed,
            construction_id: SEM_DEMO,
            representation_id: "synthetic_opaque",
            encoding: Property::Unknown,
            field_order: Property::Unknown,
            separator: Property::Unknown,
            source: "synthetic; constructed in tests/byte_representations.rs",
            notes: "Framework demonstration object. Properties are UNKNOWN because nothing \
                    establishes them; they are deliberately not inferred.",
        },
        &[0x00, 0xFF, 0x10, 0x80, 0x7F],
    )
}

#[test]
fn br_003_unknown_properties_round_trip() {
    let dir = fixtures_dir(SUBDIR);
    let f = synthetic_demo_representation();
    let stored = support::assert_stored_and_replayed(&dir, &f);

    // UNKNOWN survives the round trip and is not silently filled in.
    assert_eq!(stored.encoding, Property::Unknown);
    assert_eq!(stored.field_order, Property::Unknown);
    assert_eq!(stored.separator, Property::Unknown);
    assert_eq!(stored.encoding.as_str(), "UNKNOWN");

    // The bytes are not valid UTF-8, so a text comparison could not stand in
    // for the byte comparison here.
    assert!(std::str::from_utf8(&stored.bytes()).is_err());
}

// ---------------------------------------------------------------------------
// Cross-representation test
//
// Same semantic identity, different bytes, different digest.
// ---------------------------------------------------------------------------

/// Two representations of the **same** semantic object are not byte-equal and
/// do not share a digest.
///
/// This is the test the framework exists for: it prevents semantic equivalence
/// from being mistaken for byte-level equivalence.
#[test]
fn cross_representation_same_semantics_differ_in_bytes() {
    let observed = observed_entry_representation();
    let synthetic = synthetic_timestamp_z_representation();

    // Same semantic object.
    assert_eq!(
        observed.construction_id, synthetic.construction_id,
        "both fixtures describe the same semantic object"
    );
    // Different representation.
    assert_ne!(
        observed.representation_id, synthetic.representation_id,
        "the two fixtures are distinct representations"
    );
    // Different epistemic status.
    assert_eq!(observed.status, FixtureStatus::AsIsObserved);
    assert_eq!(synthetic.status, FixtureStatus::Proposed);

    let cmp = compare_fixtures(&observed, &synthetic);

    assert!(
        !cmp.equal,
        "same semantic object must not be assumed byte-equal: {}",
        cmp.describe()
    );
    assert_ne!(
        cmp.sha256_a,
        cmp.sha256_b,
        "different bytes produced the same digest: {}",
        cmp.describe()
    );
    assert!(
        cmp.first_diff_offset.is_some(),
        "a difference must have a located offset: {}",
        cmp.describe()
    );

    // The two differ only in the trailing timestamp field, so the first
    // difference falls after the common prefix.
    let offset = cmp.first_diff_offset.unwrap();
    assert!(
        offset > 0 && offset < cmp.len_a,
        "expected the difference inside the trailing field, got {}",
        cmp.describe()
    );
    assert_ne!(cmp.len_a, cmp.len_b, "the two renderings differ in length");
}

/// Different semantic objects are also distinguishable, so the framework is
/// not merely detecting representation changes.
#[test]
fn cross_representation_distinct_semantic_identities() {
    let entry = observed_entry_representation();
    let demo = synthetic_demo_representation();

    assert_ne!(
        entry.construction_id, demo.construction_id,
        "distinct semantic objects carry distinct construction ids"
    );
    let cmp = compare_fixtures(&entry, &demo);
    assert!(!cmp.equal, "distinct objects differ: {}", cmp.describe());
}

// ---------------------------------------------------------------------------
// Byte comparison behaviour
// ---------------------------------------------------------------------------

#[test]
fn comparison_reports_equality() {
    let cmp = compare_bytes(b"identical", b"identical");
    assert!(cmp.equal);
    assert_eq!(cmp.len_a, 9);
    assert_eq!(cmp.len_b, 9);
    assert_eq!(cmp.first_diff_offset, None);
    assert_eq!(cmp.byte_a_at_diff, None);
    assert_eq!(cmp.byte_b_at_diff, None);
    assert_eq!(cmp.sha256_a, cmp.sha256_b);
}

#[test]
fn comparison_locates_first_differing_byte() {
    let cmp = compare_bytes(b"abcXef", b"abcYef");
    assert!(!cmp.equal);
    assert_eq!(cmp.first_diff_offset, Some(3));
    assert_eq!(cmp.byte_a_at_diff, Some(b'X'));
    assert_eq!(cmp.byte_b_at_diff, Some(b'Y'));
    assert_eq!(cmp.len_a, cmp.len_b);
    assert_ne!(cmp.sha256_a, cmp.sha256_b);
}

#[test]
fn comparison_handles_prefix_relationship() {
    // "abc" is a strict prefix of "abcd": the difference begins where the
    // shorter input ends, and only one side has a byte there.
    let cmp = compare_bytes(b"abc", b"abcd");
    assert!(!cmp.equal);
    assert_eq!(cmp.len_a, 3);
    assert_eq!(cmp.len_b, 4);
    assert_eq!(cmp.first_diff_offset, Some(3));
    assert_eq!(cmp.byte_a_at_diff, None);
    assert_eq!(cmp.byte_b_at_diff, Some(b'd'));
    assert_ne!(cmp.sha256_a, cmp.sha256_b);
}

#[test]
fn comparison_handles_empty_inputs() {
    let cmp = compare_bytes(b"", b"");
    assert!(cmp.equal);
    assert_eq!(cmp.first_diff_offset, None);

    let cmp = compare_bytes(b"", b"x");
    assert!(!cmp.equal);
    assert_eq!(cmp.first_diff_offset, Some(0));
    assert_eq!(cmp.byte_a_at_diff, None);
    assert_eq!(cmp.byte_b_at_diff, Some(b'x'));
}

/// The comparison is over raw bytes, not decoded text. Two byte sequences that
/// are not both valid UTF-8 must still compare cleanly.
#[test]
fn comparison_operates_on_raw_bytes_not_text() {
    // Built at runtime so the bytes are not a statically-checkable literal.
    let a: Vec<u8> = "Aé".as_bytes().to_vec(); // UTF-8: 41 C3 A9
                                               // Latin-1 rendering of the same text: 41 E9. Derived from `a` so the
                                               // bytes are not a statically-checkable literal.
    let b: Vec<u8> = vec![a[0], 0xE9];
    assert!(std::str::from_utf8(&b).is_err());

    let cmp = compare_bytes(&a, &b);
    assert!(
        !cmp.equal,
        "same text under different encodings is not byte-equal: {}",
        cmp.describe()
    );
    assert_eq!(cmp.first_diff_offset, Some(1));
    assert_ne!(cmp.sha256_a, cmp.sha256_b);
}

// ---------------------------------------------------------------------------
// Replay behaviour
// ---------------------------------------------------------------------------

#[test]
fn replay_reports_success_fields() {
    let f = observed_entry_representation();
    let o = replay(&f);
    assert!(o.matched);
    assert_eq!(o.fixture_id, f.fixture_id);
    assert_eq!(o.expected_sha256, f.sha256);
    assert_eq!(o.actual_sha256, f.sha256);
}

/// A fixture whose recorded digest disagrees with its bytes is reported as a
/// failure, naming the fixture and both digests.
#[test]
fn replay_reports_failure_fields() {
    let mut f = observed_entry_representation();
    let real = f.sha256.clone();
    f.sha256 = "0".repeat(64);

    let o = replay(&f);
    assert!(!o.matched, "a wrong digest must not replay successfully");
    assert_eq!(o.fixture_id, f.fixture_id);
    assert_eq!(o.expected_sha256, "0".repeat(64));
    assert_eq!(o.actual_sha256, real);
}

// ---------------------------------------------------------------------------
// Mutation test — framework integrity only
// ---------------------------------------------------------------------------

/// Changing one byte produces both byte inequality and digest inequality.
///
/// This is a **fixture-framework integrity test**. It is not a security proof
/// and makes no claim about SHA-256.
#[test]
fn mutation_changes_bytes_and_digest() {
    let original = observed_entry_representation();
    let mut mutated = original.bytes();
    assert!(!mutated.is_empty());

    let last = mutated.len() - 1;
    mutated[last] ^= 0x01;

    let cmp = compare_bytes(&original.bytes(), &mutated);

    // 1. byte inequality
    assert!(!cmp.equal, "a one-byte change must be detected as unequal");
    assert_eq!(cmp.first_diff_offset, Some(last));
    assert_eq!(cmp.len_a, cmp.len_b, "a flip does not change the length");

    // 2. digest inequality
    assert_ne!(
        cmp.sha256_a,
        cmp.sha256_b,
        "a one-byte change must alter the digest: {}",
        cmp.describe()
    );
    assert_eq!(cmp.sha256_a, original.sha256);
}

/// The same check on a non-UTF-8 fixture, so mutation detection is proven on
/// raw bytes too.
#[test]
fn mutation_detected_on_non_utf8_fixture() {
    let f = synthetic_demo_representation();
    let mut mutated = f.bytes();
    mutated[0] ^= 0xFF;

    let cmp = compare_bytes(&f.bytes(), &mutated);
    assert!(!cmp.equal);
    assert_eq!(cmp.first_diff_offset, Some(0));
    assert_ne!(cmp.sha256_a, cmp.sha256_b);
}

// ---------------------------------------------------------------------------
// Status model
// ---------------------------------------------------------------------------

/// No fixture in this repository carries `NORMATIVE`. The status exists so the
/// model is complete, not because any byte representation has normative
/// standing.
#[test]
fn no_fixture_is_labelled_normative() {
    let dir = fixtures_dir(SUBDIR);
    let entries = std::fs::read_dir(&dir).expect("fixtures dir exists");

    let mut checked = 0usize;
    for e in entries {
        let path = e.expect("dir entry").path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let raw = std::fs::read_to_string(&path).expect("read fixture");
        let v: serde_json::Value = serde_json::from_str(&raw).expect("parse fixture");
        let f = ByteFixture::from_json(&v);

        assert_ne!(
            f.status,
            FixtureStatus::Normative,
            "fixture {} is labelled NORMATIVE; no byte representation has normative standing",
            f.fixture_id
        );
        checked += 1;
    }
    assert!(
        checked >= 3,
        "expected at least three fixtures, saw {checked}"
    );
}

#[test]
fn status_strings_round_trip() {
    for s in [
        FixtureStatus::AsIsObserved,
        FixtureStatus::Proposed,
        FixtureStatus::Normative,
    ] {
        assert_eq!(FixtureStatus::parse(s.as_str()), s);
    }
    assert_eq!(FixtureStatus::AsIsObserved.as_str(), "AS_IS_OBSERVED");
    assert_eq!(FixtureStatus::Proposed.as_str(), "PROPOSED");
    assert_eq!(FixtureStatus::Normative.as_str(), "NORMATIVE");
}

// ---------------------------------------------------------------------------
// INFRA-001 fixtures are untouched
// ---------------------------------------------------------------------------

/// INFRA-002 must not have migrated or rewritten the INFRA-001 fixtures.
///
/// They keep their own schema and their own recording flag
/// (`HASH_DOMAINS_RECORD`); this test pins that separation so a future change
/// cannot silently absorb them.
#[test]
fn infra_001_fixtures_remain_in_their_own_schema() {
    let hd = fixtures_dir("hash_domains").join("HD-001_entry_chain_preimage.json");
    let raw = std::fs::read_to_string(&hd).expect("INFRA-001 fixture still present");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("parse INFRA-001 fixture");

    // INFRA-001 schema markers, still present.
    assert!(v.get("source_ref").is_some(), "INFRA-001 keeps source_ref");
    assert!(v.get("input_utf8").is_some(), "INFRA-001 keeps input_utf8");
    assert_eq!(
        v["status"].as_str(),
        Some("AS-IS IMPLEMENTATION BYTES — OBSERVED PREIMAGE"),
        "INFRA-001 status wording is unchanged"
    );
    // INFRA-002-only fields are absent from INFRA-001 fixtures.
    assert!(
        v.get("representation_id").is_none(),
        "INFRA-001 fixtures were not migrated to the INFRA-002 schema"
    );
}

/// The observed entry-chain bytes recorded by INFRA-001 and by INFRA-002 are
/// byte-identical, so the two harnesses agree on what the implementation does.
#[test]
fn infra_001_and_infra_002_observe_identical_entry_bytes() {
    let hd = fixtures_dir("hash_domains").join("HD-001_entry_chain_preimage.json");
    let raw = std::fs::read_to_string(&hd).expect("INFRA-001 fixture present");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("parse INFRA-001 fixture");
    let infra_001_hex = v["input_bytes_hex"].as_str().expect("hex field");

    let infra_002 = observed_entry_representation();

    let a = hex::decode(infra_001_hex).expect("INFRA-001 hex decodes");
    let b = infra_002.bytes();
    let cmp = compare_bytes(&a, &b);

    assert!(
        cmp.equal,
        "INFRA-001 and INFRA-002 disagree about the observed bytes: {}",
        cmp.describe()
    );
    assert_eq!(cmp.sha256_a, infra_002.sha256);
}
