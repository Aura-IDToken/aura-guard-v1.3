#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! INFRA-001 — hash domain observation and replay harness.
//!
//! # What this is
//!
//! A **read-only observation harness** over the SHA-256 constructions that
//! `aura-guard` implements **today**. It records the exact bytes that enter
//! SHA-256, stores them as fixtures, and replays them so that any future change
//! to a construction fails a test instead of passing silently.
//!
//! # What this is NOT
//!
//! The bytes captured here are **AS-IS IMPLEMENTATION BYTES** — an
//! **OBSERVED PREIMAGE** of the current code. They are deliberately *not*
//! called canonical, normative, protocol-mandated or compliant. DQ-002
//! (hash-domain architecture) and DQ-006 (canonical serialization) are both
//! unresolved, so no fixture in this harness carries any specification
//! standing.
//!
//! Any dependency this harness records between two constructions is an
//! **implementation dependency observed in the source**, never a normative
//! relationship.
//!
//! # Observation technique
//!
//! No production code is modified and no test-only seam is added.
//!
//! Two constructions expose their preimage through the existing public API
//! (`SegmentManifest::segment_chain_preimage`). The entry-chain preimage is
//! not exposed by `chain::compute_chain_hash`, which returns only a digest.
//! For that construction the harness **reconstructs** the preimage from the
//! same inputs and then **proves the reconstruction is faithful** by asserting
//!
//! ```text
//! crypto::sha256_hex(reconstructed) == chain::compute_chain_hash(..)
//! ```
//!
//! If production ever changes its field set, ordering, separator or encoding,
//! that equality breaks and the test fails. The reconstruction is therefore
//! self-validating rather than assumed.
//!
//! # Recording fixtures
//!
//! Fixtures under `tests/fixtures/hash_domains/` are committed. To regenerate
//! them after an intentional, separately-approved change:
//!
//! ```text
//! HASH_DOMAINS_RECORD=1 cargo test --test hash_domains
//! ```

use aura_guard::chain::compute_chain_hash;
use aura_guard::crypto::{genesis_hash, sha256_bytes_hex, sha256_hex};
use aura_guard::merkle::{empty_root, leaf_hash, node_hash};
use aura_guard::normalizer::shadow_normalize;
use aura_guard::segment::{segment_genesis_hash, SegmentManifest};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Fixture model
// ---------------------------------------------------------------------------

/// One observed construction, serialised to `tests/fixtures/hash_domains/`.
///
/// `input_bytes_hex` is authoritative for replay; `input_utf8` is a
/// convenience view and is `None` when the preimage is not valid UTF-8.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Fixture {
    fixture_id: String,
    construction_id: String,
    source_ref: String,
    input_bytes_hex: String,
    input_length: usize,
    input_utf8: Option<String>,
    sha256: String,
}

impl Fixture {
    fn new(
        fixture_id: &str,
        construction_id: &str,
        source_ref: &str,
        input_bytes: &[u8],
        sha256: &str,
    ) -> Self {
        Self {
            fixture_id: fixture_id.to_string(),
            construction_id: construction_id.to_string(),
            source_ref: source_ref.to_string(),
            input_bytes_hex: hex::encode(input_bytes),
            input_length: input_bytes.len(),
            input_utf8: std::str::from_utf8(input_bytes).ok().map(str::to_string),
            sha256: sha256.to_string(),
        }
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "fixture_id": self.fixture_id,
            "construction_id": self.construction_id,
            "source_ref": self.source_ref,
            "status": "AS-IS IMPLEMENTATION BYTES — OBSERVED PREIMAGE",
            "not_canonical": "DQ-002 and DQ-006 unresolved; these bytes carry no specification standing.",
            "input_bytes_hex": self.input_bytes_hex,
            "input_length": self.input_length,
            "input_utf8": self.input_utf8,
            "sha256": self.sha256,
        })
    }

    fn from_json(v: &serde_json::Value) -> Self {
        Self {
            fixture_id: v["fixture_id"].as_str().unwrap().to_string(),
            construction_id: v["construction_id"].as_str().unwrap().to_string(),
            source_ref: v["source_ref"].as_str().unwrap().to_string(),
            input_bytes_hex: v["input_bytes_hex"].as_str().unwrap().to_string(),
            input_length: usize::try_from(v["input_length"].as_u64().unwrap()).unwrap(),
            input_utf8: v["input_utf8"].as_str().map(str::to_string),
            sha256: v["sha256"].as_str().unwrap().to_string(),
        }
    }
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("hash_domains")
}

fn recording() -> bool {
    std::env::var("HASH_DOMAINS_RECORD").is_ok()
}

/// Write the fixture when recording; always read it back and compare.
fn persist_and_load(f: &Fixture) -> Fixture {
    let path = fixtures_dir().join(format!("{}.json", f.fixture_id));
    if recording() {
        std::fs::create_dir_all(fixtures_dir()).expect("create fixtures dir");
        let body = serde_json::to_string_pretty(&f.to_json()).expect("serialise fixture");
        std::fs::write(&path, format!("{body}\n")).expect("write fixture");
    }
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "fixture {} missing ({e}). Regenerate with HASH_DOMAINS_RECORD=1 cargo test --test hash_domains",
            path.display()
        )
    });
    let v: serde_json::Value = serde_json::from_str(&raw).expect("parse fixture");
    Fixture::from_json(&v)
}

/// Replay: recorded hex -> bytes -> SHA-256 -> must equal recorded digest,
/// and the recorded observation must equal what the code produces now.
fn assert_replay(observed: &Fixture) {
    let stored = persist_and_load(observed);

    assert_eq!(
        stored.input_bytes_hex, observed.input_bytes_hex,
        "[{}] observed preimage differs from the stored fixture — the implementation's \
         hash input changed. This harness does not authorise that change; see DQ-002/DQ-006.",
        observed.construction_id
    );
    assert_eq!(
        stored.input_length, observed.input_length,
        "[{}] preimage length changed",
        observed.construction_id
    );

    let replayed_bytes = hex::decode(&stored.input_bytes_hex).expect("fixture hex decodes");
    let replayed_digest = hex::encode(Sha256::digest(&replayed_bytes));

    assert_eq!(
        replayed_digest, stored.sha256,
        "[{}] replaying the stored bytes did not reproduce the stored digest",
        observed.construction_id
    );
    assert_eq!(
        replayed_digest, observed.sha256,
        "[{}] replayed digest differs from the digest the implementation produced now",
        observed.construction_id
    );
}

// ---------------------------------------------------------------------------
// Shared observation inputs
//
// Fixed, arbitrary values. They are inputs to an observation, not reference
// data, and carry no protocol meaning.
// ---------------------------------------------------------------------------

const OBS_DECISION: &str = "DENY";
const OBS_POLICY_SET: &str = "finance-v1";
const OBS_CONTEXT: &str = "Finance Bot";
const OBS_TIMESTAMP: &str = "2026-01-01T00:00:00+00:00";
const OBS_SEQ: u64 = 0;
const OBS_PROMPT: &str = "Card 4111-1111-1111-1111 please";
const OBS_RESPONSE: &str = "I cannot process that.";
const OBS_SEALED_AT: &str = "2026-01-01T01:00:00+00:00";

fn obs_policy_hash() -> String {
    // policy_hash is SHA-256 over the raw policy file bytes (src/policy.rs:188).
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("policies")
        .join("finance-v1.yaml");
    let bytes = std::fs::read(path).expect("read shipped policy");
    sha256_bytes_hex(&bytes)
}

fn obs_combined_input() -> String {
    // src/api/audit.rs:104-107 — space-joined context, prompt, response.
    format!("{OBS_CONTEXT} {OBS_PROMPT} {OBS_RESPONSE}")
}

// ---------------------------------------------------------------------------
// HD-001 — entry chain preimage
// ---------------------------------------------------------------------------

/// Reconstruct the entry-chain preimage exactly as `src/chain.rs:36-47` builds
/// it, and prove the reconstruction faithful against the production digest.
fn observe_entry_chain() -> Fixture {
    let prev_hash = genesis_hash();
    let input_hash = sha256_hex(&obs_combined_input());
    let shadow_hash = sha256_hex(&shadow_normalize(&obs_combined_input()));
    let policy_hash = obs_policy_hash();

    // Field order, separator and `seq` rendering mirror src/chain.rs:36-47.
    let reconstructed = [
        prev_hash.as_str(),
        OBS_DECISION,
        OBS_POLICY_SET,
        policy_hash.as_str(),
        OBS_CONTEXT,
        input_hash.as_str(),
        shadow_hash.as_str(),
        &OBS_SEQ.to_string(),
        OBS_TIMESTAMP,
    ]
    .join("|");

    let production = compute_chain_hash(
        &prev_hash,
        OBS_DECISION,
        OBS_POLICY_SET,
        &policy_hash,
        OBS_CONTEXT,
        &input_hash,
        &shadow_hash,
        OBS_SEQ,
        OBS_TIMESTAMP,
    );

    // Fidelity proof: the reconstruction is the observed preimage only if
    // hashing it reproduces exactly what production returned.
    assert_eq!(
        sha256_hex(&reconstructed),
        production,
        "HD-001 reconstruction is not faithful to chain::compute_chain_hash — \
         the production preimage (fields, order, separator or encoding) has changed."
    );

    Fixture::new(
        "HD-001_entry_chain_preimage",
        "entry_chain_hash",
        "src/chain.rs:25-49 (compute_chain_hash); separator src/chain.rs:20",
        reconstructed.as_bytes(),
        &production,
    )
}

#[test]
fn hd_001_entry_chain_preimage_replays() {
    assert_replay(&observe_entry_chain());
}

// ---------------------------------------------------------------------------
// HD-002 — segment chain preimage (preimage is public API)
// ---------------------------------------------------------------------------

fn observe_segment_chain() -> (Fixture, SegmentManifest) {
    let merkle_root = hex::encode(leaf_hash(b"observation-leaf"));
    let prev_segment_chain_hash = segment_genesis_hash();

    let preimage = SegmentManifest::segment_chain_preimage(
        &prev_segment_chain_hash,
        &merkle_root,
        0,
        41,
        OBS_SEALED_AT,
    );
    let digest = hex::encode(Sha256::digest(preimage.as_bytes()));

    let manifest = SegmentManifest {
        schema: "aura-guard.segment.v1".to_string(),
        segment_id: 0,
        first_seq: 0,
        last_seq: 41,
        entry_count: 42,
        merkle_root,
        prev_merkle_root: String::new(),
        prev_segment_chain_hash,
        segment_chain_hash: digest.clone(),
        head_chain_hash_at_close: genesis_hash(),
        sealed_at: OBS_SEALED_AT.to_string(),
        tst_path: None,
    };

    // The manifest recomputes the same digest from its own fields.
    assert_eq!(
        manifest.recompute_segment_chain_hash(),
        digest,
        "HD-002 recompute_segment_chain_hash disagrees with the observed preimage"
    );

    let f = Fixture::new(
        "HD-002_segment_chain_preimage",
        "segment_chain_hash",
        "src/segment.rs:91-118 (segment_chain_preimage / recompute_segment_chain_hash)",
        preimage.as_bytes(),
        &digest,
    );
    (f, manifest)
}

#[test]
fn hd_002_segment_chain_preimage_replays() {
    let (f, _) = observe_segment_chain();
    assert_replay(&f);
}

// ---------------------------------------------------------------------------
// HD-003 / HD-004 — genesis constants
// ---------------------------------------------------------------------------

#[test]
fn hd_003_entry_genesis_replays() {
    // src/crypto.rs:27-29 — sha256_hex("AURA-GUARD-GENESIS-v1.3").
    const SEED: &str = "AURA-GUARD-GENESIS-v1.3";
    let produced = genesis_hash();
    assert_eq!(
        sha256_hex(SEED),
        produced,
        "HD-003 genesis seed string no longer reproduces genesis_hash()"
    );
    assert_replay(&Fixture::new(
        "HD-003_entry_genesis",
        "entry_genesis_hash",
        "src/crypto.rs:22-29 (genesis_hash)",
        SEED.as_bytes(),
        &produced,
    ));
}

#[test]
fn hd_004_segment_genesis_replays() {
    // src/segment.rs:47-50 — Sha256::digest(b"AURA-GUARD-SEGMENT-GENESIS-v1").
    const SEED: &[u8] = b"AURA-GUARD-SEGMENT-GENESIS-v1";
    let produced = segment_genesis_hash();
    assert_eq!(
        hex::encode(Sha256::digest(SEED)),
        produced,
        "HD-004 segment genesis seed no longer reproduces segment_genesis_hash()"
    );
    assert_replay(&Fixture::new(
        "HD-004_segment_genesis",
        "segment_genesis_hash",
        "src/segment.rs:46-50 (segment_genesis_hash)",
        SEED,
        &produced,
    ));
}

/// The two genesis constants are distinct. Recorded as an observed property of
/// the implementation, not as a claim about domain-separation adequacy.
#[test]
fn hd_003_004_genesis_constants_are_distinct() {
    assert_ne!(
        genesis_hash(),
        segment_genesis_hash(),
        "entry and segment chains are seeded from distinct constants in the current code"
    );
}

// ---------------------------------------------------------------------------
// HD-005 / HD-006 / HD-007 — RFC 6962 Merkle constructions
// ---------------------------------------------------------------------------

#[test]
fn hd_005_merkle_leaf_replays() {
    // src/merkle.rs:29-34 — SHA-256(0x00 || data).
    let data = b"observation-leaf";
    let mut preimage = vec![0x00u8];
    preimage.extend_from_slice(data);

    let produced = hex::encode(leaf_hash(data));
    assert_eq!(
        hex::encode(Sha256::digest(&preimage)),
        produced,
        "HD-005 leaf preimage (0x00 tag) no longer reproduces leaf_hash()"
    );
    assert_replay(&Fixture::new(
        "HD-005_merkle_leaf",
        "merkle_leaf_hash",
        "src/merkle.rs:27-34 (leaf_hash, 0x00 prefix)",
        &preimage,
        &produced,
    ));
}

#[test]
fn hd_006_merkle_node_replays() {
    // src/merkle.rs:38-44 — SHA-256(0x01 || left || right).
    let left = leaf_hash(b"left");
    let right = leaf_hash(b"right");
    let mut preimage = vec![0x01u8];
    preimage.extend_from_slice(&left);
    preimage.extend_from_slice(&right);

    let produced = hex::encode(node_hash(&left, &right));
    assert_eq!(
        hex::encode(Sha256::digest(&preimage)),
        produced,
        "HD-006 node preimage (0x01 tag) no longer reproduces node_hash()"
    );
    assert_replay(&Fixture::new(
        "HD-006_merkle_node",
        "merkle_node_hash",
        "src/merkle.rs:36-44 (node_hash, 0x01 prefix)",
        &preimage,
        &produced,
    ));
}

#[test]
fn hd_007_merkle_empty_root_replays() {
    // src/merkle.rs:48-50 — SHA-256 of the empty input.
    let produced = hex::encode(empty_root());
    assert_replay(&Fixture::new(
        "HD-007_merkle_empty_root",
        "merkle_empty_root",
        "src/merkle.rs:46-50 (empty_root)",
        &[],
        &produced,
    ));
}

/// Leaf and node tags differ, so the same 32 bytes hash differently in each
/// position. Observed property of the current code.
#[test]
fn hd_005_006_leaf_and_node_tags_differ() {
    let x = leaf_hash(b"x");
    assert_ne!(
        hex::encode(leaf_hash(&x)),
        hex::encode(node_hash(&x, &x)),
        "leaf and node constructions are tag-separated in the current code"
    );
}

// ---------------------------------------------------------------------------
// HD-008 / HD-009 / HD-010 — policy, input and shadow digests
// ---------------------------------------------------------------------------

#[test]
fn hd_008_policy_hash_replays() {
    // src/policy.rs:188 — sha256_bytes_hex over the raw policy file bytes.
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("policies")
        .join("finance-v1.yaml");
    let bytes = std::fs::read(&path).expect("read shipped policy");
    let produced = sha256_bytes_hex(&bytes);
    assert_replay(&Fixture::new(
        "HD-008_policy_hash",
        "policy_hash",
        "src/policy.rs:188 (sha256_bytes_hex over policies/finance-v1.yaml)",
        &bytes,
        &produced,
    ));
}

#[test]
fn hd_009_input_hash_replays() {
    // src/api/audit.rs:104-109 — sha256_hex(format!("{context} {prompt} {response}")).
    let combined = obs_combined_input();
    let produced = sha256_hex(&combined);
    assert_replay(&Fixture::new(
        "HD-009_input_hash",
        "input_hash",
        "src/api/audit.rs:104-109 (space-joined context, prompt, response)",
        combined.as_bytes(),
        &produced,
    ));
}

#[test]
fn hd_010_shadow_hash_replays() {
    // src/api/audit.rs:108,110 — sha256_hex(shadow_normalize(original)).
    let shadow = shadow_normalize(&obs_combined_input());
    let produced = sha256_hex(&shadow);
    assert_replay(&Fixture::new(
        "HD-010_shadow_hash",
        "shadow_hash",
        "src/api/audit.rs:108,110 (sha256_hex over shadow_normalize output)",
        shadow.as_bytes(),
        &produced,
    ));
}

// ---------------------------------------------------------------------------
// HD-011 — TSA message imprint
// ---------------------------------------------------------------------------

/// `tsa_message_imprint` hashes the *same* preimage string as
/// `segment_chain_hash` (`src/segment.rs:120-132`). Recorded here as an
/// **observed implementation dependency**. It is not a normative statement
/// that the two are one domain.
#[test]
fn hd_011_tsa_imprint_matches_segment_chain_preimage() {
    let (segment_fixture, manifest) = observe_segment_chain();
    let imprint = hex::encode(manifest.tsa_message_imprint());

    assert_eq!(
        imprint, segment_fixture.sha256,
        "HD-011: in the current code tsa_message_imprint and segment_chain_hash \
         hash the same preimage"
    );

    assert_replay(&Fixture::new(
        "HD-011_tsa_message_imprint",
        "tsa_message_imprint",
        "src/segment.rs:120-132 (tsa_message_imprint; same preimage as segment_chain_hash)",
        segment_fixture.input_utf8.as_deref().unwrap().as_bytes(),
        &imprint,
    ));
}

// ---------------------------------------------------------------------------
// Observed implementation dependency: entry chain -> Merkle leaf
// ---------------------------------------------------------------------------

/// `entry_leaf_hash` hex-decodes an entry's `chain_hash` and feeds the raw 32
/// bytes to `leaf_hash` (`src/segment.rs:135-148`). Recorded as an observed
/// dependency of the implementation only.
#[test]
fn observed_dependency_entry_chain_feeds_merkle_leaf() {
    let f = observe_entry_chain();
    let raw = hex::decode(&f.sha256).expect("entry chain digest is hex");
    assert_eq!(raw.len(), 32, "entry chain digest is 32 bytes");

    let mut preimage = vec![0x00u8];
    preimage.extend_from_slice(&raw);

    assert_eq!(
        hex::encode(leaf_hash(&raw)),
        hex::encode(Sha256::digest(&preimage)),
        "Merkle leaf over a chain digest follows the 0x00-tagged construction"
    );
}

// ---------------------------------------------------------------------------
// Negative test — harness integrity check only
// ---------------------------------------------------------------------------

/// Flipping a single byte of an observed preimage changes the digest.
///
/// This proves the harness would notice a changed preimage. It is **not** a
/// cryptographic security claim about SHA-256.
#[test]
fn negative_single_byte_change_alters_digest() {
    let f = observe_entry_chain();
    let mut bytes = hex::decode(&f.input_bytes_hex).expect("observed hex decodes");
    assert!(!bytes.is_empty(), "preimage is non-empty");

    let original = hex::encode(Sha256::digest(&bytes));
    assert_eq!(
        original, f.sha256,
        "baseline digest matches the observation"
    );

    // Flip the low bit of the final byte.
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    let mutated = hex::encode(Sha256::digest(&bytes));

    assert_ne!(
        mutated, original,
        "harness integrity: a one-byte change must alter the digest"
    );
}

/// The same check on a raw-byte construction, so the harness is proven on a
/// non-UTF-8 preimage too.
#[test]
fn negative_single_byte_change_alters_merkle_leaf_digest() {
    let data = b"observation-leaf";
    let original = leaf_hash(data);

    let mut mutated_data = data.to_vec();
    let last = mutated_data.len() - 1;
    mutated_data[last] ^= 0x01;

    assert_ne!(
        hex::encode(leaf_hash(&mutated_data)),
        hex::encode(original),
        "harness integrity: a one-byte change must alter the leaf digest"
    );
}

// ---------------------------------------------------------------------------
// Machine-readable inventory
// ---------------------------------------------------------------------------

/// Emit and verify the inventory of SHA-256 construction sites.
///
/// `UNKNOWN` marks a property the source does not establish. Nothing here is
/// inferred.
#[test]
fn inventory_is_current() {
    let inventory = serde_json::json!({
        "artifact": "INFRA-001 hash construction inventory",
        "status": "AS-IS OBSERVATION — not canonical, not normative",
        "dq_boundary": "INFRA-001 does not resolve DQ-002 and does not establish \
                        any normative hash-domain relationship.",
        "repository": "AuraIDToken/aura-guard-v1.3",
        "constructions": [
            {"id": "entry_chain_hash", "source": "src/chain.rs:25-49", "algorithm": "SHA-256",
             "input": "9 fields joined", "field_order": "prev_hash, decision, policy_set, policy_hash, context, input_hash, shadow_hash, seq, timestamp",
             "separator": "U+007C", "encoding": "UTF-8 -> lowercase hex",
             "constants": "genesis seed for entry 0", "exercised": true, "fixture": "HD-001_entry_chain_preimage"},
            {"id": "segment_chain_hash", "source": "src/segment.rs:91-118", "algorithm": "SHA-256",
             "input": "5 fields joined", "field_order": "prev_segment_chain_hash, merkle_root, first_seq, last_seq, sealed_at",
             "separator": "U+007C", "encoding": "UTF-8 -> lowercase hex",
             "constants": "segment genesis seed", "exercised": true, "fixture": "HD-002_segment_chain_preimage"},
            {"id": "entry_genesis_hash", "source": "src/crypto.rs:22-29", "algorithm": "SHA-256",
             "input": "literal \"AURA-GUARD-GENESIS-v1.3\"", "field_order": "n/a", "separator": "n/a",
             "encoding": "UTF-8 -> lowercase hex", "constants": "AURA-GUARD-GENESIS-v1.3",
             "exercised": true, "fixture": "HD-003_entry_genesis"},
            {"id": "segment_genesis_hash", "source": "src/segment.rs:46-50", "algorithm": "SHA-256",
             "input": "literal b\"AURA-GUARD-SEGMENT-GENESIS-v1\"", "field_order": "n/a", "separator": "n/a",
             "encoding": "raw bytes -> lowercase hex", "constants": "AURA-GUARD-SEGMENT-GENESIS-v1",
             "exercised": true, "fixture": "HD-004_segment_genesis"},
            {"id": "merkle_leaf_hash", "source": "src/merkle.rs:27-34", "algorithm": "SHA-256",
             "input": "0x00 || data", "field_order": "n/a", "separator": "1-byte tag 0x00",
             "encoding": "raw bytes", "constants": "0x00", "exercised": true, "fixture": "HD-005_merkle_leaf"},
            {"id": "merkle_node_hash", "source": "src/merkle.rs:36-44", "algorithm": "SHA-256",
             "input": "0x01 || left || right", "field_order": "left then right", "separator": "1-byte tag 0x01",
             "encoding": "raw bytes", "constants": "0x01", "exercised": true, "fixture": "HD-006_merkle_node"},
            {"id": "merkle_empty_root", "source": "src/merkle.rs:46-50", "algorithm": "SHA-256",
             "input": "empty", "field_order": "n/a", "separator": "n/a", "encoding": "raw bytes",
             "constants": "none", "exercised": true, "fixture": "HD-007_merkle_empty_root"},
            {"id": "policy_hash", "source": "src/policy.rs:188", "algorithm": "SHA-256",
             "input": "raw policy file bytes", "field_order": "n/a", "separator": "n/a",
             "encoding": "raw bytes -> lowercase hex", "constants": "none",
             "exercised": true, "fixture": "HD-008_policy_hash"},
            {"id": "input_hash", "source": "src/api/audit.rs:104-109", "algorithm": "SHA-256",
             "input": "context + \" \" + prompt + \" \" + response", "field_order": "context, prompt, response",
             "separator": "U+0020", "encoding": "UTF-8 -> lowercase hex", "constants": "none",
             "exercised": true, "fixture": "HD-009_input_hash"},
            {"id": "shadow_hash", "source": "src/api/audit.rs:108,110", "algorithm": "SHA-256",
             "input": "shadow_normalize(combined input)", "field_order": "n/a", "separator": "n/a",
             "encoding": "UTF-8 -> lowercase hex", "constants": "none",
             "exercised": true, "fixture": "HD-010_shadow_hash"},
            {"id": "tsa_message_imprint", "source": "src/segment.rs:120-132", "algorithm": "SHA-256",
             "input": "same preimage as segment_chain_hash", "field_order": "see segment_chain_hash",
             "separator": "U+007C", "encoding": "UTF-8 -> 32 raw bytes", "constants": "none",
             "exercised": true, "fixture": "HD-011_tsa_message_imprint"},
            {"id": "rfc3161_request_digest", "source": "src/rfc3161.rs:138", "algorithm": "SHA-256",
             "input": "caller-supplied preimage bytes", "field_order": "UNKNOWN — determined by caller",
             "separator": "n/a", "encoding": "raw bytes -> 32 raw bytes", "constants": "none",
             "exercised": false, "reason_not_exercised": "requires a live RFC 3161 TSA over the network",
             "fixture": null},
            {"id": "tst_verify_digest_message_imprint", "source": "src/tst_verify.rs:657", "algorithm": "SHA-256",
             "input": "TST-embedded bytes", "field_order": "UNKNOWN", "separator": "n/a",
             "encoding": "raw bytes", "constants": "none", "exercised": false,
             "reason_not_exercised": "reached only through private TST parsing paths; covered by tests/tst_verify.rs",
             "fixture": null},
            {"id": "tst_verify_digest_signed_attrs", "source": "src/tst_verify.rs:839", "algorithm": "SHA-256",
             "input": "CMS signed attributes", "field_order": "UNKNOWN — DER ordering", "separator": "n/a",
             "encoding": "DER bytes", "constants": "none", "exercised": false,
             "reason_not_exercised": "reached only through private CMS verification paths",
             "fixture": null},
            {"id": "aura_seal_cli_digest", "source": "src/bin/aura_seal.rs:500", "algorithm": "SHA-256",
             "input": "segment preimage string", "field_order": "see segment_chain_hash", "separator": "U+007C",
             "encoding": "UTF-8 -> 32 raw bytes", "constants": "none", "exercised": false,
             "reason_not_exercised": "lives in a binary target, not the library surface",
             "fixture": null}
        ],
        "primitives": [
            {"id": "sha256_hex", "source": "src/crypto.rs:8-12", "note": "UTF-8 string -> lowercase hex"},
            {"id": "sha256_bytes_hex", "source": "src/crypto.rs:16-20", "note": "raw bytes -> lowercase hex"}
        ],
        "observed_implementation_dependencies": [
            "entry_chain_hash digest -> hex-decoded to 32 bytes -> merkle_leaf_hash (src/segment.rs:135-148)",
            "merkle root -> segment_chain_hash preimage (src/segment.rs:91-106)",
            "segment_chain_hash preimage -> tsa_message_imprint (src/segment.rs:120-132)"
        ],
        "not_asserted": [
            "No relationship is claimed between these constructions and APS-200 integrity_hash, event_payload_hash or previous_record_hash.",
            "No construction here is asserted to be canonical or specification-conformant."
        ]
    });

    let path = fixtures_dir().join("INVENTORY.json");
    if recording() {
        std::fs::create_dir_all(fixtures_dir()).expect("create fixtures dir");
        let body = serde_json::to_string_pretty(&inventory).expect("serialise inventory");
        std::fs::write(&path, format!("{body}\n")).expect("write inventory");
    }

    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "inventory {} missing ({e}). Regenerate with HASH_DOMAINS_RECORD=1",
            path.display()
        )
    });
    let stored: serde_json::Value = serde_json::from_str(&raw).expect("parse inventory");

    assert_eq!(
        stored, inventory,
        "the committed inventory no longer matches the harness's view of the source; \
         re-run with HASH_DOMAINS_RECORD=1 after verifying the change is intended"
    );

    let n = stored["constructions"].as_array().expect("array").len();
    assert_eq!(n, 15, "construction count changed");
}
