#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! INFRA-003 — verification and regression harness.
//!
//! # What this is
//!
//! A **closed regression layer** over the observations already recorded by
//! INFRA-001 (`tests/hash_domains.rs`) and INFRA-002
//! (`tests/byte_representations.rs`). It exists to make an *unintended* change
//! to already-observed behaviour fail a test.
//!
//! It differs from INFRA-001/INFRA-002 in three ways, so it duplicates neither:
//!
//! 1. **Directory-driven sweeps.** INFRA-001/002 replay a fixed list of
//!    fixtures they construct themselves. This file walks the fixture
//!    directories, so an added, removed, renamed or corrupted fixture is
//!    caught too.
//! 2. **Governance-metadata regression.** It pins each fixture's recorded
//!    epistemic classification and disclaimer strings, so a silent
//!    reclassification fails.
//! 3. **Mutation detection for properties INFRA-001/002 do not yet mutate** —
//!    field order, separator and encoding.
//!
//! # Regression invariant
//!
//! ```text
//! OBSERVED IMPLEMENTATION BEHAVIOR  !=  NORMATIVE PROTOCOL CONTRACT
//! ```
//!
//! Every assertion here tests **what the implementation does today**. Nothing
//! here states what the protocol *should* do. DQ-002 (hash-domain
//! architecture) and DQ-006 (canonical serialization) are unresolved, and no
//! test in this file depends on either being resolved.
//!
//! In particular this file does **not** assert that `chain_hash` is
//! `integrity_hash`, that any observed byte sequence is a protocol canonical
//! serialization, or that any external canonicalization scheme applies. Those
//! belong to DQ-002/DQ-006.
//!
//! # Read-only over fixtures
//!
//! This harness never writes a fixture. Recording remains the responsibility
//! of INFRA-001 (`HASH_DOMAINS_RECORD`) and INFRA-002
//! (`BYTE_FIXTURES_RECORD`).

mod support;

use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use support::{compare_bytes, fixtures_dir, replay, ByteFixture, FixtureStatus, Property};

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Exact INFRA-001 disclaimer strings, pinned so a reclassification fails.
const INFRA_001_STATUS: &str = "AS-IS IMPLEMENTATION BYTES — OBSERVED PREIMAGE";
const INFRA_001_NOT_CANONICAL: &str =
    "DQ-002 and DQ-006 unresolved; these bytes carry no specification standing.";
/// Exact INFRA-002 disclaimer string.
const INFRA_002_GOVERNANCE: &str =
    "DQ-006 unresolved. This fixture does not establish canonical serialization.";

fn read_json(path: &Path) -> serde_json::Value {
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("fixture {} unreadable ({e})", path.display()));
    serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("fixture {} is not valid JSON ({e})", path.display()))
}

/// Every `*.json` in a fixture directory, sorted for determinism.
fn json_files(dir: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("fixture dir {} unreadable ({e})", dir.display()))
        .map(|e| e.expect("dir entry").path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("json"))
        .collect();
    out.sort();
    out
}

fn file_names(dir: &Path) -> BTreeSet<String> {
    json_files(dir)
        .iter()
        .map(|p| {
            p.file_name()
                .and_then(|s| s.to_str())
                .expect("utf-8 filename")
                .to_string()
        })
        .collect()
}

fn expected_set(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|s| (*s).to_string()).collect()
}

/// The observed entry-chain preimage, read from the INFRA-001 fixture.
///
/// Used as the mutation subject because it is the only stored observation with
/// an internally visible field structure (fields joined by a separator).
fn observed_entry_preimage() -> String {
    let v = read_json(&fixtures_dir("hash_domains").join("HD-001_entry_chain_preimage.json"));
    v["input_utf8"]
        .as_str()
        .expect("HD-001 records a UTF-8 view")
        .to_string()
}

fn digest_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

// ---------------------------------------------------------------------------
// 1. Fixture inventory regression — catches add / remove / rename
// ---------------------------------------------------------------------------

#[test]
fn regression_hash_domain_fixture_inventory_unchanged() {
    let found = file_names(&fixtures_dir("hash_domains"));
    let expected = expected_set(&[
        "HD-001_entry_chain_preimage.json",
        "HD-002_segment_chain_preimage.json",
        "HD-003_entry_genesis.json",
        "HD-004_segment_genesis.json",
        "HD-005_merkle_leaf.json",
        "HD-006_merkle_node.json",
        "HD-007_merkle_empty_root.json",
        "HD-008_policy_hash.json",
        "HD-009_input_hash.json",
        "HD-010_shadow_hash.json",
        "HD-011_tsa_message_imprint.json",
        "INVENTORY.json",
    ]);
    assert_eq!(
        found, expected,
        "the INFRA-001 fixture set changed; a fixture was added, removed or renamed"
    );
}

#[test]
fn regression_byte_representation_fixture_inventory_unchanged() {
    let found = file_names(&fixtures_dir("byte_representations"));
    let expected = expected_set(&[
        "BR-001_entry_chain_observed_rust.json",
        "BR-002_entry_chain_synthetic_timestamp_z.json",
        "BR-003_demo_object_unknown_properties.json",
    ]);
    assert_eq!(
        found, expected,
        "the INFRA-002 fixture set changed; a fixture was added, removed or renamed"
    );
}

// ---------------------------------------------------------------------------
// 2 & 3. Sweep replay — every stored fixture still reproduces exactly
// ---------------------------------------------------------------------------

/// Every INFRA-001 fixture: stored hex -> bytes -> SHA-256 -> stored digest,
/// and the recorded length still matches the recorded bytes.
#[test]
fn regression_every_hash_domain_fixture_replays() {
    let dir = fixtures_dir("hash_domains");
    let mut checked = 0usize;

    for path in json_files(&dir) {
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        if name == "INVENTORY.json" {
            continue; // inventory is metadata, not a preimage record
        }
        let v = read_json(&path);
        let hex_str = v["input_bytes_hex"].as_str().expect("input_bytes_hex");
        let stored_digest = v["sha256"].as_str().expect("sha256");
        let stored_len =
            usize::try_from(v["input_length"].as_u64().expect("input_length")).expect("usize");

        let bytes = hex::decode(hex_str)
            .unwrap_or_else(|e| panic!("{name}: input_bytes_hex does not decode ({e})"));

        assert_eq!(
            bytes.len(),
            stored_len,
            "{name}: recorded input_length disagrees with the recorded bytes"
        );
        assert_eq!(
            digest_hex(&bytes),
            stored_digest,
            "{name}: replaying the stored bytes no longer reproduces the stored digest"
        );
        checked += 1;
    }

    assert_eq!(checked, 11, "expected 11 replayable INFRA-001 fixtures");
}

/// Every INFRA-002 fixture, through the shared framework's own replay path.
#[test]
fn regression_every_byte_representation_fixture_replays() {
    let dir = fixtures_dir("byte_representations");
    let mut checked = 0usize;

    for path in json_files(&dir) {
        let f = ByteFixture::from_json(&read_json(&path));
        let outcome = replay(&f);
        assert!(
            outcome.matched,
            "{}: replay failed — expected {}, actual {}",
            outcome.fixture_id, outcome.expected_sha256, outcome.actual_sha256
        );
        assert_eq!(
            f.bytes().len(),
            f.input_length,
            "{}: recorded input_length disagrees with the recorded bytes",
            f.fixture_id
        );
        checked += 1;
    }

    assert_eq!(checked, 3, "expected 3 INFRA-002 fixtures");
}

/// The two harnesses recorded the same entry-chain observation. Compared at
/// **file level** (stored bytes vs stored bytes), which is distinct from
/// INFRA-002's recompute-level check.
#[test]
fn regression_stored_entry_observations_agree_across_harnesses() {
    let hd = read_json(&fixtures_dir("hash_domains").join("HD-001_entry_chain_preimage.json"));
    let br = read_json(
        &fixtures_dir("byte_representations").join("BR-001_entry_chain_observed_rust.json"),
    );

    let a = hex::decode(hd["input_bytes_hex"].as_str().expect("hex")).expect("HD-001 hex");
    let b = hex::decode(br["input_bytes_hex"].as_str().expect("hex")).expect("BR-001 hex");

    let cmp = compare_bytes(&a, &b);
    assert!(
        cmp.equal,
        "INFRA-001 and INFRA-002 stored different entry-chain bytes: {}",
        cmp.describe()
    );
    assert_eq!(cmp.sha256_a, cmp.sha256_b);
}

// ---------------------------------------------------------------------------
// 10. Governance-metadata regression — guards against reclassification
// ---------------------------------------------------------------------------

/// Every INFRA-001 fixture still carries its exact classification and
/// disclaimer strings.
#[test]
fn regression_infra_001_classification_unchanged() {
    let dir = fixtures_dir("hash_domains");
    let mut checked = 0usize;

    for path in json_files(&dir) {
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        if name == "INVENTORY.json" {
            continue;
        }
        let v = read_json(&path);
        assert_eq!(
            v["status"].as_str(),
            Some(INFRA_001_STATUS),
            "{name}: INFRA-001 epistemic status string changed"
        );
        assert_eq!(
            v["not_canonical"].as_str(),
            Some(INFRA_001_NOT_CANONICAL),
            "{name}: INFRA-001 non-canonical disclaimer changed"
        );
        checked += 1;
    }
    assert_eq!(checked, 11);
}

/// Every INFRA-002 fixture still carries its exact recorded status, and the
/// per-fixture classification is unchanged.
#[test]
fn regression_infra_002_classification_unchanged() {
    let dir = fixtures_dir("byte_representations");

    let expected: [(&str, FixtureStatus); 3] = [
        (
            "BR-001_entry_chain_observed_rust.json",
            FixtureStatus::AsIsObserved,
        ),
        (
            "BR-002_entry_chain_synthetic_timestamp_z.json",
            FixtureStatus::Proposed,
        ),
        (
            "BR-003_demo_object_unknown_properties.json",
            FixtureStatus::Proposed,
        ),
    ];

    for (name, want) in expected {
        let v = read_json(&dir.join(name));
        let f = ByteFixture::from_json(&v);
        assert_eq!(
            f.status, want,
            "{name}: epistemic classification changed — reclassification is out of scope here"
        );
        assert_eq!(
            v["governance"].as_str(),
            Some(INFRA_002_GOVERNANCE),
            "{name}: governance disclaimer changed"
        );
    }
}

/// No fixture in either directory is classified NORMATIVE.
///
/// No observed byte sequence has normative standing while DQ-002 and DQ-006
/// are unresolved.
#[test]
fn regression_no_fixture_became_normative() {
    for path in json_files(&fixtures_dir("byte_representations")) {
        let f = ByteFixture::from_json(&read_json(&path));
        assert_ne!(
            f.status,
            FixtureStatus::Normative,
            "{}: a fixture was promoted to NORMATIVE",
            f.fixture_id
        );
    }
    for path in json_files(&fixtures_dir("hash_domains")) {
        let v = read_json(&path);
        if let Some(s) = v["status"].as_str() {
            assert!(
                !s.contains("NORMATIVE"),
                "{}: INFRA-001 fixture status mentions NORMATIVE",
                path.display()
            );
        }
    }
}

/// UNKNOWN properties are still UNKNOWN — they were not quietly resolved.
#[test]
fn regression_unknown_properties_remain_unknown() {
    let f = ByteFixture::from_json(&read_json(
        &fixtures_dir("byte_representations").join("BR-003_demo_object_unknown_properties.json"),
    ));
    assert_eq!(f.encoding, Property::Unknown, "encoding became known");
    assert_eq!(f.field_order, Property::Unknown, "field_order became known");
    assert_eq!(f.separator, Property::Unknown, "separator became known");
}

/// The INFRA-001 inventory still records the same construction count, the same
/// exercised/unexercised split and the same UNKNOWN properties.
#[test]
fn regression_inventory_counts_and_unknowns_unchanged() {
    let v = read_json(&fixtures_dir("hash_domains").join("INVENTORY.json"));
    let constructions = v["constructions"].as_array().expect("constructions array");

    assert_eq!(constructions.len(), 15, "construction count changed");

    let exercised = constructions
        .iter()
        .filter(|c| c["exercised"].as_bool() == Some(true))
        .count();
    assert_eq!(exercised, 11, "exercised construction count changed");
    assert_eq!(
        constructions.len() - exercised,
        4,
        "unexercised construction count changed"
    );

    let unknown_field_orders = constructions
        .iter()
        .filter(|c| c["field_order"].as_str().map(|s| s.contains("UNKNOWN")) == Some(true))
        .count();
    assert_eq!(
        unknown_field_orders, 3,
        "the number of UNKNOWN field_order properties changed; UNKNOWN must not be \
         silently resolved"
    );

    // Every unexercised construction still states why.
    for c in constructions
        .iter()
        .filter(|c| c["exercised"].as_bool() == Some(false))
    {
        assert!(
            c["reason_not_exercised"].as_str().is_some(),
            "{}: an unexercised construction lost its stated reason",
            c["id"].as_str().unwrap_or("?")
        );
    }
}

// ---------------------------------------------------------------------------
// 4-9. Mutation detection
//
// Each mutation targets a property that an existing fixture actually records.
// These are harness-sensitivity checks, not security claims.
// ---------------------------------------------------------------------------

/// 4 — a changed field *value* is detected.
#[test]
fn mutation_field_value_detected() {
    let observed = observed_entry_preimage();
    let mut fields: Vec<&str> = observed.split('|').collect();
    assert_eq!(fields.len(), 9, "HD-001 records a 9-field preimage");

    // Field 2 is the decision value, recorded as `DENY` in HD-001.
    assert_eq!(fields[1], "DENY");
    fields[1] = "ALLOW";
    let mutated = fields.join("|");

    let cmp = compare_bytes(observed.as_bytes(), mutated.as_bytes());
    assert!(!cmp.equal, "a changed field value must be detected");
    assert_ne!(
        cmp.sha256_a,
        cmp.sha256_b,
        "a changed field value must change the digest: {}",
        cmp.describe()
    );
}

/// 7 — a changed field *order* is detected.
///
/// Field order is a property HD-001 and BR-001 both record, so mutating it is
/// in scope. Swapping two fields keeps the byte multiset and the length
/// identical, so only an order-sensitive construction notices.
#[test]
fn mutation_field_order_detected() {
    let observed = observed_entry_preimage();
    let mut fields: Vec<&str> = observed.split('|').collect();
    assert_eq!(fields.len(), 9);

    // Swap `input_hash` (index 5) and `shadow_hash` (index 6): both are
    // 64-char hex, so length is preserved exactly.
    assert_eq!(fields[5].len(), 64);
    assert_eq!(fields[6].len(), 64);
    fields.swap(5, 6);
    let reordered = fields.join("|");

    let cmp = compare_bytes(observed.as_bytes(), reordered.as_bytes());
    assert_eq!(
        cmp.len_a, cmp.len_b,
        "the swap preserves length, so length alone cannot be the signal"
    );
    assert!(!cmp.equal, "a field-order change must be detected");
    assert_ne!(
        cmp.sha256_a,
        cmp.sha256_b,
        "a field-order change must change the digest: {}",
        cmp.describe()
    );
}

/// 8 — a changed *separator* is detected.
///
/// HD-001/BR-001 record the separator as `U+007C`. Substituting a different
/// single byte preserves the length.
#[test]
fn mutation_separator_detected() {
    let observed = observed_entry_preimage();
    assert!(
        observed.contains('|'),
        "HD-001 records a '|'-joined preimage"
    );

    let mutated = observed.replace('|', "\u{001f}"); // ASCII unit separator

    let cmp = compare_bytes(observed.as_bytes(), mutated.as_bytes());
    assert_eq!(cmp.len_a, cmp.len_b, "both separators are one byte");
    assert!(!cmp.equal, "a separator change must be detected");
    assert_ne!(
        cmp.sha256_a,
        cmp.sha256_b,
        "a separator change must change the digest: {}",
        cmp.describe()
    );
}

/// 6 — the byte representation is encoding-sensitive.
///
/// HD-001/BR-001 record the encoding as UTF-8. Re-encoding the *same text* as
/// UTF-16LE yields different bytes and a different digest, so a silent
/// encoding change could not pass unnoticed.
#[test]
fn mutation_encoding_detected() {
    let observed = observed_entry_preimage();
    let utf8 = observed.as_bytes().to_vec();

    let utf16le: Vec<u8> = observed
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();

    assert_ne!(
        utf8.len(),
        utf16le.len(),
        "the two encodings differ in size"
    );

    let cmp = compare_bytes(&utf8, &utf16le);
    assert!(!cmp.equal, "an encoding change must be detected");
    assert_ne!(
        cmp.sha256_a,
        cmp.sha256_b,
        "an encoding change must change the digest: {}",
        cmp.describe()
    );
}

/// 9 — a changed *timestamp representation* is detected.
///
/// BR-001 records `+00:00` and BR-002 records `Z` for the same instant. This
/// pins that the two stored representations remain distinct in bytes and
/// digest.
///
/// **This asserts nothing about which form is correct.** BR-002 is classified
/// PROPOSED and is a synthetic comparison input, not a proposed protocol form.
#[test]
fn mutation_timestamp_representation_detected() {
    let dir = fixtures_dir("byte_representations");
    let a = ByteFixture::from_json(&read_json(
        &dir.join("BR-001_entry_chain_observed_rust.json"),
    ));
    let b = ByteFixture::from_json(&read_json(
        &dir.join("BR-002_entry_chain_synthetic_timestamp_z.json"),
    ));

    assert_eq!(
        a.construction_id, b.construction_id,
        "both fixtures describe the same semantic object"
    );
    assert_eq!(a.status, FixtureStatus::AsIsObserved);
    assert_eq!(b.status, FixtureStatus::Proposed);

    let cmp = compare_bytes(&a.bytes(), &b.bytes());
    assert!(
        !cmp.equal,
        "the two timestamp representations must differ in bytes: {}",
        cmp.describe()
    );
    assert_ne!(
        cmp.sha256_a,
        cmp.sha256_b,
        "the two timestamp representations must differ in digest: {}",
        cmp.describe()
    );
    assert!(
        cmp.first_diff_offset.is_some(),
        "the difference must have a located offset"
    );
}

/// 5 — a single-byte mutation is detected on a non-UTF-8 stored fixture, so
/// detection is proven on raw bytes and not only on text.
#[test]
fn mutation_single_byte_detected_on_raw_fixture() {
    let f = ByteFixture::from_json(&read_json(
        &fixtures_dir("byte_representations").join("BR-003_demo_object_unknown_properties.json"),
    ));
    let original = f.bytes();
    assert!(
        std::str::from_utf8(&original).is_err(),
        "BR-003 records non-UTF-8 bytes"
    );

    let mut mutated = original.clone();
    let last = mutated.len() - 1;
    mutated[last] ^= 0x01;

    let cmp = compare_bytes(&original, &mutated);
    assert!(!cmp.equal);
    assert_eq!(cmp.first_diff_offset, Some(last));
    assert_ne!(cmp.sha256_a, cmp.sha256_b);
    assert_eq!(cmp.sha256_a, f.sha256, "baseline matches the stored digest");
}

// ---------------------------------------------------------------------------
// Regression invariant
// ---------------------------------------------------------------------------

/// The stored fixtures still carry, in the files themselves, the statement
/// that observed bytes are not a normative contract.
///
/// This is the machine-checkable form of the INFRA-003 regression invariant:
/// `OBSERVED IMPLEMENTATION BEHAVIOR != NORMATIVE PROTOCOL CONTRACT`.
#[test]
fn regression_observed_is_not_normative_disclaimer_present() {
    let mut checked = 0usize;

    for path in json_files(&fixtures_dir("hash_domains")) {
        let v = read_json(&path);
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        let disclaimer = if name == "INVENTORY.json" {
            v["status"].as_str().map(str::to_string)
        } else {
            v["not_canonical"].as_str().map(str::to_string)
        };
        let d = disclaimer.unwrap_or_else(|| panic!("{name}: lost its disclaimer field"));
        assert!(
            d.contains("not canonical") || d.contains("no specification standing"),
            "{name}: disclaimer no longer denies specification standing"
        );
        checked += 1;
    }

    for path in json_files(&fixtures_dir("byte_representations")) {
        let v = read_json(&path);
        assert!(
            v["governance"]
                .as_str()
                .map(|s| s.contains("does not establish canonical serialization"))
                == Some(true),
            "{}: governance disclaimer no longer denies canonical standing",
            path.display()
        );
        checked += 1;
    }

    assert_eq!(
        checked, 15,
        "expected 15 fixture files across both harnesses"
    );
}
