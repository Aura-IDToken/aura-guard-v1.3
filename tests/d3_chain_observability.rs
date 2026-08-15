#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! D-3 instrumentation control.
//!
//! Pins the `chain_hash` that the **uninstrumented** implementation produced
//! for the D-3 semantic fixture (captured at `main@443f72e`, before
//! `chain_preimage` was extracted). If exposing the preimage ever alters the
//! digest, these tests fail.

use aura_guard::chain::{chain_preimage, compute_chain_hash};
use aura_guard::crypto::sha256_bytes_hex;
use std::path::PathBuf;

/// `chain_hash` observed on the uninstrumented baseline. Changing this value
/// is a protocol break, not a test fix.
const CHAIN_HASH_BEFORE_INSTRUMENTATION: &str =
    "6eb514bf3ce334676d894e669e3d9598d594cc7e21c9bb694daad017f8c20222";

const EXPECTED_PREIMAGE: &str = "b93b4ade8c758fa0086b464ac445fe6109681da57a99760eeb7f7bce3623562d|DENY|finance-v1|5e9ab2b25e6a748aeff8610b341f1ec9ba4b281df9e22304b1066fadf082b35d|Finance Bot|c2e552214097f038caddfa8cd86daca6eb0197a1feeab0234dda34ba3dd1413a|534b346b8ffd5ce800097347fce1fcfe4d0d3dc6ad20c04b3213fec3455c12a6|0|2026-01-01T00:00:00+00:00";

/// The nine fixture-supplied preimage fields.
struct Fields;
impl Fields {
    const PREV_HASH: &'static str =
        "b93b4ade8c758fa0086b464ac445fe6109681da57a99760eeb7f7bce3623562d";
    const DECISION: &'static str = "DENY";
    const POLICY_SET: &'static str = "finance-v1";
    const POLICY_HASH: &'static str =
        "5e9ab2b25e6a748aeff8610b341f1ec9ba4b281df9e22304b1066fadf082b35d";
    const CONTEXT: &'static str = "Finance Bot";
    const INPUT_HASH: &'static str =
        "c2e552214097f038caddfa8cd86daca6eb0197a1feeab0234dda34ba3dd1413a";
    const SHADOW_HASH: &'static str =
        "534b346b8ffd5ce800097347fce1fcfe4d0d3dc6ad20c04b3213fec3455c12a6";
    const SEQ: u64 = 0;
    const TIMESTAMP: &'static str = "2026-01-01T00:00:00+00:00";
}

fn hash() -> String {
    compute_chain_hash(
        Fields::PREV_HASH,
        Fields::DECISION,
        Fields::POLICY_SET,
        Fields::POLICY_HASH,
        Fields::CONTEXT,
        Fields::INPUT_HASH,
        Fields::SHADOW_HASH,
        Fields::SEQ,
        Fields::TIMESTAMP,
    )
}

fn preimage() -> String {
    chain_preimage(
        Fields::PREV_HASH,
        Fields::DECISION,
        Fields::POLICY_SET,
        Fields::POLICY_HASH,
        Fields::CONTEXT,
        Fields::INPUT_HASH,
        Fields::SHADOW_HASH,
        Fields::SEQ,
        Fields::TIMESTAMP,
    )
}

#[test]
fn instrumentation_does_not_change_chain_hash() {
    assert_eq!(
        hash(),
        CHAIN_HASH_BEFORE_INSTRUMENTATION,
        "chain_hash changed relative to the pre-instrumentation baseline — \
         exposing the preimage must be observational only"
    );
}

#[test]
fn exposed_preimage_is_the_hashed_preimage() {
    // The preimage accessor must return exactly the bytes compute_chain_hash
    // digests — otherwise the exported evidence would not correspond to the
    // digest the production path produces.
    assert_eq!(sha256_bytes_hex(preimage().as_bytes()), hash());
}

#[test]
fn preimage_is_byte_exact() {
    assert_eq!(preimage(), EXPECTED_PREIMAGE);
    assert_eq!(preimage().len(), 315);
}

#[test]
fn preimage_has_nine_fields_separated_by_pipe() {
    // Guards field-count and separator drift. Hex digests and the RFC 3339
    // timestamp contain no '|', so the split is unambiguous for this fixture.
    assert_eq!(preimage().split('|').count(), 9);
}

#[test]
fn fixture_file_matches_pinned_values() {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("D3_REAL_CHAIN_SEMANTIC_FIXTURE.json");
    let bytes = std::fs::read(&path).expect("D-3 fixture is present");
    let v: serde_json::Value = serde_json::from_slice(&bytes).expect("D-3 fixture is valid JSON");

    let f = &v["chain_preimage_fields"];
    assert_eq!(f["prev_hash"], Fields::PREV_HASH);
    assert_eq!(f["decision"], Fields::DECISION);
    assert_eq!(f["policy_set"], Fields::POLICY_SET);
    assert_eq!(f["policy_hash"], Fields::POLICY_HASH);
    assert_eq!(f["context"], Fields::CONTEXT);
    assert_eq!(f["input_hash"], Fields::INPUT_HASH);
    assert_eq!(f["shadow_hash"], Fields::SHADOW_HASH);
    assert_eq!(f["seq"], Fields::SEQ);
    assert_eq!(f["timestamp"], Fields::TIMESTAMP);
    assert_eq!(
        v["expected"]["chain_hash_before_instrumentation"],
        CHAIN_HASH_BEFORE_INSTRUMENTATION
    );
}
