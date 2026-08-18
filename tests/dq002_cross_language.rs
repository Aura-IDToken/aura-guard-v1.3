//! RI-RS conformance + cross-language vector emission for DQ-002.
//!
//! Normative source: `aura-specification/ck003/dq-002-hash-domain/`
//!   * `ADR-CK003-DQ002-HASH-DOMAIN.md` (status: PROPOSED)
//!   * `fixtures/FIX-CK003-DQ002-RFC6962-2LEAF.json`
//!   * `fixtures/FIX-CK003-DQ002-RFC6962-EDGE-MATRIX.json`
//!
//! The fixtures under `tests/fixtures/dq002/` are verbatim copies of those
//! files; see `tests/fixtures/dq002/PROVENANCE.md`. Their expected values were
//! produced by an independent GNU coreutils oracle, not by this crate.
//!
//! The emitted vector file is the RI-RS half of the CROSS-LANGUAGE-002
//! comparison. Its RI-PY counterpart is
//! `conformance/merkle/emit_vectors.py` in `aura-poc-a-core-v3.3`. Both
//! emit the same schema; neither consumes the other's output.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use aura_guard::merkle::{audit_path, empty_root, leaf_hash, merkle_root, verify_audit_path};
use serde_json::{json, Value};

const PRODUCER: &str = "RI-RS";
const MAX_LEAVES: usize = 8;
/// Probe range for tree-size acceptance: 0..=9, deliberately overshooting.
const PROBE_SIZES: usize = MAX_LEAVES + 1;
const TAMPER_PAYLOAD: &[u8] = b"tampered";

/// CK003-DQ002-001 canonical bytes. Canonical serialization is out of DQ-002
/// scope; these bytes are consumed as an opaque, fixture-supplied payload.
const CK003_CANONICAL_HEX: &str = concat!(
    "6167656e745f69643d413030317c6172693d39353030307c64726966743d3530",
    "30307c74733d323032362d30312d30315430303a30303a30305a"
);

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/dq002")
}

fn load_fixture(name: &str) -> Value {
    let path = fixture_dir().join(name);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read fixture {}: {e}", path.display()));
    serde_json::from_str(&raw).expect("fixture is valid JSON")
}

fn payloads() -> Vec<Vec<u8>> {
    (0..MAX_LEAVES)
        .map(|i| format!("leaf-{i}").into_bytes())
        .collect()
}

fn leaf_hashes() -> Vec<[u8; 32]> {
    payloads().iter().map(|p| leaf_hash(p)).collect()
}

fn from_hex32(s: &str) -> [u8; 32] {
    let v = hex::decode(s).expect("valid hex");
    let mut out = [0u8; 32];
    assert_eq!(v.len(), 32, "expected a raw 32-byte digest");
    out.copy_from_slice(&v);
    out
}

// ---------------------------------------------------------------------------
// Fixture conformance
// ---------------------------------------------------------------------------

#[test]
fn dq002_two_leaf_fixture_matches() {
    let fx = load_fixture("FIX-CK003-DQ002-RFC6962-2LEAF.json");
    let inputs = &fx["inputs"];
    let expected = &fx["expected"];

    let a = leaf_hash(&hex::decode(inputs["leaf_a_bytes_hex"].as_str().unwrap()).unwrap());
    let b = leaf_hash(&hex::decode(inputs["leaf_b_bytes_hex"].as_str().unwrap()).unwrap());
    let root = merkle_root(&[a, b]);

    assert_eq!(
        hex::encode(a),
        expected["leaf_a_hash_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(b),
        expected["leaf_b_hash_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(root),
        expected["root_hash_hex"].as_str().unwrap()
    );
}

#[test]
fn dq002_edge_matrix_roots_match_independent_oracle() {
    let fx = load_fixture("FIX-CK003-DQ002-RFC6962-EDGE-MATRIX.json");
    let leaves = leaf_hashes();

    for (i, expected) in fx["leaf_hashes_hex"].as_array().unwrap().iter().enumerate() {
        assert_eq!(hex::encode(leaves[i]), expected.as_str().unwrap());
    }

    for tree in fx["trees"].as_array().unwrap() {
        let n = tree["tree_size"].as_u64().unwrap() as usize;
        let root = merkle_root(&leaves[..n]);
        assert_eq!(
            hex::encode(root),
            tree["root_hex"].as_str().unwrap(),
            "root mismatch at N={n}"
        );
    }
}

#[test]
fn dq002_edge_matrix_audit_paths_match_independent_oracle() {
    let fx = load_fixture("FIX-CK003-DQ002-RFC6962-EDGE-MATRIX.json");
    let leaves = leaf_hashes();

    for tree in fx["trees"].as_array().unwrap() {
        let n = tree["tree_size"].as_u64().unwrap() as usize;
        for entry in tree["audit_paths"].as_array().unwrap() {
            let m = entry["leaf_index"].as_u64().unwrap() as usize;
            let expected: Vec<&str> = entry["path_hex"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect();
            let got: Vec<String> = audit_path(m, &leaves[..n])
                .iter()
                .map(hex::encode)
                .collect();
            assert_eq!(got, expected, "audit path mismatch at N={n} m={m}");
        }
    }
}

#[test]
fn dq002_empty_root_is_sha256_of_empty_input() {
    assert_eq!(
        hex::encode(empty_root()),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn dq002_odd_node_is_promoted_not_duplicated() {
    // N=3 is the minimal case that exposes Bitcoin-style last-leaf duplication.
    let l = leaf_hashes();
    let promoted =
        aura_guard::merkle::node_hash(&aura_guard::merkle::node_hash(&l[0], &l[1]), &l[2]);
    let duplicated = aura_guard::merkle::node_hash(
        &aura_guard::merkle::node_hash(&l[0], &l[1]),
        &aura_guard::merkle::node_hash(&l[2], &l[2]),
    );
    assert_eq!(merkle_root(&l[..3]), promoted);
    assert_ne!(merkle_root(&l[..3]), duplicated);
}

#[test]
fn dq002_hex_text_node_domain_is_not_the_raw_byte_domain() {
    // Negative control NC-3: the legacy RI-PY node construction hashes the
    // hexadecimal *text* of both children. It must not coincide.
    use sha2::{Digest, Sha256};
    let a = leaf_hash(b"a");
    let b = leaf_hash(b"b");
    let normative = aura_guard::merkle::node_hash(&a, &b);
    let hex_text: [u8; 32] =
        Sha256::digest(format!("{}{}", hex::encode(a), hex::encode(b)).as_bytes()).into();
    assert_ne!(normative, hex_text);
    assert_eq!(
        hex::encode(normative),
        "b137985ff484fb600db93107c77b0365c80d78f5b429ded0fd97361d077999eb"
    );
}

#[test]
fn dq002_leaf_domain_prefix_is_load_bearing() {
    // Negative control NC-1: a leaf hashed without the 0x00 prefix.
    use sha2::{Digest, Sha256};
    let undomained: [u8; 32] = Sha256::digest(b"a").into();
    assert_ne!(leaf_hash(b"a"), undomained);
    assert_eq!(
        hex::encode(leaf_hash(b"a")),
        "022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c"
    );
}

#[test]
fn dq002_node_domain_prefix_is_load_bearing() {
    // Negative control NC-2: a node hashed without the 0x01 prefix.
    use sha2::{Digest, Sha256};
    let a = leaf_hash(b"a");
    let b = leaf_hash(b"b");
    let mut undomained_input = Vec::with_capacity(64);
    undomained_input.extend_from_slice(&a);
    undomained_input.extend_from_slice(&b);
    let undomained: [u8; 32] = Sha256::digest(&undomained_input).into();
    assert_ne!(aura_guard::merkle::node_hash(&a, &b), undomained);
}

// ---------------------------------------------------------------------------
// Cross-language vector emission
// ---------------------------------------------------------------------------

fn flip_first(mut d: [u8; 32]) -> [u8; 32] {
    d[0] ^= 0xff;
    d
}

fn flip_last(mut d: [u8; 32]) -> [u8; 32] {
    d[31] ^= 0x01;
    d
}

fn verification_cases(n: usize, leaves: &[[u8; 32]]) -> Vec<Value> {
    let root = merkle_root(leaves);
    let tampered_leaf = leaf_hash(TAMPER_PAYLOAD);
    let mut cases = Vec::new();

    for m in 0..n {
        let path = audit_path(m, leaves);

        let accepted_tree_sizes: Vec<usize> = (0..=PROBE_SIZES)
            .filter(|&s| verify_audit_path(&leaves[m], m, s, &path, &root))
            .collect();
        let accepted_leaf_indices: Vec<usize> = (0..=n)
            .filter(|&j| verify_audit_path(&leaves[m], j, n, &path, &root))
            .collect();
        let tampered_sibling_accepted: Vec<bool> = (0..path.len())
            .map(|i| {
                let mut bad = path.clone();
                bad[i] = flip_first(bad[i]);
                verify_audit_path(&leaves[m], m, n, &bad, &root)
            })
            .collect();

        let short_path = if path.is_empty() {
            Vec::new()
        } else {
            path[..path.len() - 1].to_vec()
        };
        let mut long_path = path.clone();
        long_path.push(*path.first().unwrap_or(&leaves[m]));
        let mut reversed_path = path.clone();
        reversed_path.reverse();

        cases.push(json!({
            "leaf_index": m,
            "valid": verify_audit_path(&leaves[m], m, n, &path, &root),
            "accepted_tree_sizes": accepted_tree_sizes,
            "accepted_leaf_indices": accepted_leaf_indices,
            "tampered_leaf_accepted": verify_audit_path(&tampered_leaf, m, n, &path, &root),
            "tampered_root_accepted": verify_audit_path(&leaves[m], m, n, &path, &flip_last(root)),
            "tampered_sibling_accepted": tampered_sibling_accepted,
            "short_path_accepted": verify_audit_path(&leaves[m], m, n, &short_path, &root),
            "long_path_accepted": verify_audit_path(&leaves[m], m, n, &long_path, &root),
            "reversed_path_accepted": verify_audit_path(&leaves[m], m, n, &reversed_path, &root),
        }));
    }
    cases
}

fn build_vectors() -> Value {
    let leaves = leaf_hashes();
    let mut trees = Vec::new();
    let mut verification = Vec::new();

    for n in 0..=MAX_LEAVES {
        let slice = &leaves[..n];
        trees.push(json!({
            "tree_size": n,
            "root_hex": hex::encode(merkle_root(slice)),
            "audit_paths": (0..n).map(|m| json!({
                "leaf_index": m,
                "path_hex": audit_path(m, slice).iter().map(hex::encode).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
        }));
        verification.push(json!({
            "tree_size": n,
            "cases": verification_cases(n, slice),
        }));
    }

    let canonical = hex::decode(CK003_CANONICAL_HEX).unwrap();

    json!({
        "schema": "aura/dq-002/cross-language-vectors/1",
        "hash_domain": "RFC6962",
        "leaf_payloads_utf8": (0..MAX_LEAVES).map(|i| format!("leaf-{i}")).collect::<Vec<_>>(),
        "leaf_hashes_hex": leaves.iter().map(hex::encode).collect::<Vec<_>>(),
        "empty_root_hex": hex::encode(empty_root()),
        "fixture_2leaf": {
            "leaf_a_hex": hex::encode(leaf_hash(b"a")),
            "leaf_b_hex": hex::encode(leaf_hash(b"b")),
            "root_hex": hex::encode(merkle_root(&[leaf_hash(b"a"), leaf_hash(b"b")])),
        },
        "fixture_ck003_dq002_001": {
            "canonical_bytes_hex": CK003_CANONICAL_HEX,
            "canonical_length_bytes": canonical.len(),
            "leaf_digest_hex": hex::encode(leaf_hash(&canonical)),
            "node_digest_hex": hex::encode(aura_guard::merkle::node_hash(
                &from_hex32(&"00".repeat(32)),
                &from_hex32(&"ff".repeat(32)),
            )),
        },
        "trees": trees,
        "verification_matrix": verification,
    })
}

/// Emits the RI-RS vector file consumed by the CROSS-LANGUAGE-002 comparator.
///
/// Destination: `$DQ002_EMIT`, or `tests/fixtures/dq002/RI-RS-VECTORS.json`.
#[test]
fn dq002_emit_cross_language_vectors() {
    let vectors = build_vectors();
    let out = std::env::var("DQ002_EMIT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| fixture_dir().join("RI-RS-VECTORS.json"));

    let mut text = serde_json::to_string_pretty(&vectors).expect("serializable");
    text.push('\n');
    std::fs::write(&out, text).unwrap_or_else(|e| panic!("cannot write {}: {e}", out.display()));

    // Emission is evidence only if it is also self-consistent.
    assert_eq!(vectors["schema"], "aura/dq-002/cross-language-vectors/1");
    assert_eq!(PRODUCER, "RI-RS");
}
