#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! R1-JCS-DISCRIMINATING — RI-RS execution, emission and discrimination proof.
//!
//! # Why R1 exists
//!
//! CANONICAL-001 proved that RI-RS *can* run an RFC 8785 engine. It could not
//! prove that RFC 8785 was *required*: its fixture uses ASCII keys and one small
//! integer, for which a conventional sorted-key serializer emits byte-identical
//! output. A non-JCS implementation passes CANONICAL-001.
//!
//! R1 uses a fixture on which RFC 8785 and a conventional serializer disagree,
//! in two independent dimensions:
//!
//! * **D1 — key ordering.** RFC 8785 §3.2.3 sorts object keys by UTF-16 code
//!   unit. A conventional serializer sorts by code point (for `serde_json`,
//!   equivalently by UTF-8 byte order, since `Map` is a `BTreeMap<String, _>`).
//!   The orderings differ exactly when a supplementary-plane key — whose UTF-16
//!   form begins with a high surrogate in `U+D800..=U+DBFF` — meets a BMP key
//!   above `U+DBFF`. The fixture pairs `U+1F600` against `U+FF3A`.
//! * **D2 — number serialization.** RFC 8785 §3.2.2.3 mandates the ECMAScript
//!   `Number::toString` algorithm: `1.0` becomes `1`, `-0.0` becomes `0`.
//!
//! # Anti-fabrication rules enforced here
//!
//! * The canonical bytes are whatever [`jcs::canonical_bytes`] returned. They
//!   are never constructed, patched, or corrected against an expectation.
//! * The artifact is written **before** any expectation is asserted, so a
//!   mismatch is recorded as evidence rather than hidden.
//! * Nothing in this file reads the RI-PY artifact or any RI-PY value.
//! * The conventional serialization is *evidence only*. It is never hashed and
//!   never becomes a protocol value.
//!
//! # Scope
//!
//! Conformance only. `src/` is neither read for canonicalization nor written.
//! JCS is not wired into the production runtime, serializer, hash or Merkle
//! path by this file.
//!
//! Execution command:
//!
//! ```text
//! cargo test --locked --test r1_jcs_discriminating -- --nocapture
//! ```

mod jcs;

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

/// Fixture identifier, recorded verbatim in the execution artifact.
const FIXTURE: &str = "R1-JCS-DISCRIMINATING";
/// Repository this evidence originates from.
const REPOSITORY: &str = "Aura-IDToken/aura-guard-v1.3";
/// RFC 6962 leaf domain separator.
const LEAF_DOMAIN: u8 = 0x00;
/// Frozen protocol contract: the RI-RS JCS engine.
const ENGINE: &str = "serde_json_canonicalizer";
/// Frozen protocol contract: the RI-RS JCS engine version.
const ENGINE_VERSION: &str = "0.3.2";
/// Command that produces this evidence.
const EXECUTION_COMMAND: &str = "cargo test --locked --test r1_jcs_discriminating";

/// `U+FF3A` FULLWIDTH LATIN CAPITAL LETTER Z — BMP, above the surrogate range.
const KEY_FULLWIDTH_Z: char = '\u{FF3A}';
/// `U+1F600` GRINNING FACE — supplementary plane.
const KEY_GRINNING_FACE: char = '\u{1F600}';
/// ASCII anchor key.
const KEY_ASCII_A: char = 'a';

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn corpus_dir() -> PathBuf {
    repo_root().join("conformance/corpus/r1-jcs-discriminating")
}

fn input_path() -> PathBuf {
    corpus_dir().join("input.json")
}

fn artifact_path() -> PathBuf {
    corpus_dir().join("ri-rs.json")
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn leaf_sha256_hex(canonical: &[u8]) -> String {
    let mut preimage = Vec::with_capacity(1 + canonical.len());
    preimage.push(LEAF_DOMAIN);
    preimage.extend_from_slice(canonical);
    sha256_hex(&preimage)
}

fn file_sha256_hex(path: &Path) -> String {
    sha256_hex(&std::fs::read(path).expect("file must be readable"))
}

fn git(args: &[&str]) -> String {
    let out = Command::new("git")
        .args(args)
        .current_dir(repo_root())
        .output()
        .expect("git must be runnable");
    String::from_utf8(out.stdout)
        .expect("git output must be UTF-8")
        .trim()
        .to_string()
}

/// The engine version, read from the committed lockfile rather than trusted
/// from a constant. This is what makes the pin assertion meaningful.
fn locked_engine_version() -> String {
    let lock = std::fs::read_to_string(repo_root().join("Cargo.lock"))
        .expect("Cargo.lock must be readable");
    let marker = format!("name = \"{ENGINE}\"");
    let start = lock
        .find(&marker)
        .unwrap_or_else(|| panic!("{ENGINE} must be present in Cargo.lock"));
    let rest = &lock[start..];
    let vline = rest
        .lines()
        .find(|l| l.starts_with("version = "))
        .expect("locked package must declare a version");
    vline
        .trim_start_matches("version = ")
        .trim_matches('"')
        .to_string()
}

/// The conventional (non-JCS) serializer, used **only** as discrimination
/// evidence. `serde_json::Map` is a `BTreeMap<String, Value>`, so this sorts by
/// UTF-8 byte order — that is, by Unicode code point — and formats floats with
/// serde_json's own algorithm. Neither is the RFC 8785 contract.
fn conventional_bytes(value: &serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("conventional serialization must succeed")
}

/// One R1 execution of the frozen RI-RS JCS boundary.
struct Execution {
    value: serde_json::Value,
    canonical: Vec<u8>,
    conventional: Vec<u8>,
    sha256: String,
    leaf_sha256: String,
}

fn execute() -> Execution {
    let raw = std::fs::read_to_string(input_path()).expect("R1 input must be readable");
    let value: serde_json::Value = serde_json::from_str(&raw).expect("R1 input must be valid JSON");

    // --- the only place canonical bytes come into existence ----------------
    let canonical = jcs::canonical_bytes(&value).expect("JCS canonicalization must succeed");
    // -----------------------------------------------------------------------

    let conventional = conventional_bytes(&value);
    let sha256 = sha256_hex(&canonical);
    let leaf_sha256 = leaf_sha256_hex(&canonical);

    Execution {
        value,
        canonical,
        conventional,
        sha256,
        leaf_sha256,
    }
}

fn artifact(execution: &Execution) -> serde_json::Value {
    let adapter = repo_root().join("conformance/canonical/jcs.rs");

    serde_json::json!({
        "fixture": FIXTURE,
        "implementation": "RI-RS",
        "repository": REPOSITORY,
        "commit": git(&["rev-parse", "HEAD"]),
        "worktree_clean": git(&["status", "--porcelain"]).is_empty(),
        "engine": ENGINE,
        "engine_version": locked_engine_version(),
        "canonical_bytes_hex": hex::encode(&execution.canonical),
        "canonical_bytes_len": execution.canonical.len(),
        "sha256": execution.sha256,
        "leaf_sha256": execution.leaf_sha256,
        "leaf_domain": "0x00",
        "canonicalization": "RFC8785",
        "discrimination": {
            "note": "Evidence only. The conventional serialization is never hashed, \
                     never becomes a protocol value, and never replaces RFC 8785.",
            "conventional_serializer": "serde_json::to_vec (BTreeMap key order, serde_json float formatting)",
            "conventional_bytes_hex": hex::encode(&execution.conventional),
            "conventional_bytes_len": execution.conventional.len(),
            "differs_from_jcs": execution.conventional != execution.canonical,
        },
        "provenance": {
            "input_path": "conformance/corpus/r1-jcs-discriminating/input.json",
            "input_sha256": file_sha256_hex(&input_path()),
            "adapter_path": "conformance/canonical/jcs.rs",
            "adapter_sha256": file_sha256_hex(&adapter),
            "execution_command": EXECUTION_COMMAND,
            "lockfile_path": "Cargo.lock",
            "rust_version": rustc_version(),
            "os": std::env::consts::OS,
            "target": std::env::consts::ARCH,
        },
    })
}

fn rustc_version() -> String {
    let out = Command::new("rustc")
        .arg("--version")
        .output()
        .expect("rustc must be runnable");
    String::from_utf8(out.stdout)
        .expect("rustc output must be UTF-8")
        .trim()
        .to_string()
}

fn write_artifact(artifact: &serde_json::Value) {
    let text = serde_json::to_string_pretty(artifact).expect("artifact is serializable");
    std::fs::write(artifact_path(), text + "\n").expect("artifact must be writable");
}

/// Position of `"key"` inside a serialized object, for ordering assertions.
fn key_position(data: &[u8], key: char) -> usize {
    let text = std::str::from_utf8(data).expect("output must be UTF-8");
    let needle = format!("\"{key}\"");
    text.find(&needle)
        .unwrap_or_else(|| panic!("key {key:?} must appear in {text}"))
}

// ---------------------------------------------------------------------------
// Fixture integrity — R1 only means something if the input really is the one
// the module docs describe.
// ---------------------------------------------------------------------------

/// The fixture must carry the intended discriminating keys, and the UTF-16 /
/// code-point orderings must genuinely be inverted for that key pair.
#[test]
fn r1_fixture_keys_invert_utf16_and_codepoint_ordering() {
    let execution = execute();
    let obj = execution
        .value
        .as_object()
        .expect("R1 input must be an object");

    let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
    keys.sort_unstable();
    let mut expected = vec![
        KEY_ASCII_A.to_string(),
        KEY_FULLWIDTH_Z.to_string(),
        KEY_GRINNING_FACE.to_string(),
    ];
    expected.sort();
    assert_eq!(keys, expected, "unexpected R1 fixture keys");

    // The supplementary-plane key encodes to a surrogate pair.
    let units: Vec<u16> = KEY_GRINNING_FACE.encode_utf16(&mut [0u16; 2]).to_vec();
    assert_eq!(units.len(), 2, "key must be outside the BMP");
    let high = units[0];
    assert!(
        (0xD800..=0xDBFF).contains(&high),
        "first UTF-16 unit must be a high surrogate, got {high:#06X}"
    );

    // The inversion: the BMP key outranks the high surrogate, but is outranked
    // by the supplementary code point.
    assert!(u32::from(KEY_FULLWIDTH_Z) > u32::from(high));
    assert!(u32::from(KEY_FULLWIDTH_Z) < u32::from(KEY_GRINNING_FACE));
}

/// The fixture's numbers must be floats that expose ES6 formatting, not the
/// plain integers CANONICAL-001 used.
#[test]
fn r1_fixture_numbers_are_es6_discriminating() {
    let execution = execute();
    let obj = execution
        .value
        .as_object()
        .expect("R1 input must be an object");

    for (key, value) in obj {
        assert!(
            value.as_f64().is_some() && !value.is_i64() && !value.is_u64(),
            "R1 value for {key} must be a float, got {value}"
        );
    }
    assert_eq!(obj[&KEY_ASCII_A.to_string()].as_f64(), Some(1.0));
    assert_eq!(obj[&KEY_GRINNING_FACE.to_string()].as_f64(), Some(1e-7f64));

    let minus_zero = obj[&KEY_FULLWIDTH_Z.to_string()]
        .as_f64()
        .expect("value must be a float");
    assert_eq!(minus_zero, 0.0);
    assert!(
        minus_zero.is_sign_negative(),
        "fixture value must be negative zero, not positive zero"
    );
}

// ---------------------------------------------------------------------------
// D1 — UTF-16 code-unit key ordering
// ---------------------------------------------------------------------------

/// RFC 8785 must place the supplementary-plane key *before* `U+FF3A`.
#[test]
fn d1_jcs_orders_keys_by_utf16_code_unit() {
    let execution = execute();
    let text = String::from_utf8_lossy(&execution.canonical).into_owned();

    assert!(
        key_position(&execution.canonical, KEY_ASCII_A)
            < key_position(&execution.canonical, KEY_GRINNING_FACE),
        "got {text}"
    );
    assert!(
        key_position(&execution.canonical, KEY_GRINNING_FACE)
            < key_position(&execution.canonical, KEY_FULLWIDTH_Z),
        "RFC 8785 must order U+1F600 before U+FF3A; got {text}"
    );
}

/// The conventional serializer must place `U+FF3A` first — the inverse.
#[test]
fn d1_conventional_orders_keys_by_code_point() {
    let execution = execute();
    let text = String::from_utf8_lossy(&execution.conventional).into_owned();

    assert!(
        key_position(&execution.conventional, KEY_FULLWIDTH_Z)
            < key_position(&execution.conventional, KEY_GRINNING_FACE),
        "code-point ordering must place U+FF3A before U+1F600; got {text}"
    );
}

// ---------------------------------------------------------------------------
// D2 — ECMAScript number serialization
// ---------------------------------------------------------------------------

/// `1.0 -> 1` and `-0.0 -> 0` under RFC 8785, and neither under `serde_json`.
#[test]
fn d2_number_forms_disagree() {
    for (src, jcs_form) in [("1.0", "1"), ("-0.0", "0"), ("1e-7", "1e-7")] {
        let value: serde_json::Value = serde_json::from_str(src).expect("valid JSON number");
        let canonical = jcs::canonical_bytes(&value).expect("canonicalization must succeed");
        assert_eq!(
            std::str::from_utf8(&canonical).expect("utf-8"),
            jcs_form,
            "RFC 8785 form of {src}"
        );
    }

    // The two that actually differ from serde_json's own formatting.
    for src in ["1.0", "-0.0"] {
        let value: serde_json::Value = serde_json::from_str(src).expect("valid JSON number");
        assert_ne!(
            jcs::canonical_bytes(&value).expect("canonicalization must succeed"),
            conventional_bytes(&value),
            "RFC 8785 and serde_json must disagree on {src}"
        );
    }
}

// ---------------------------------------------------------------------------
// The R1 headline claim
// ---------------------------------------------------------------------------

/// RFC 8785 output MUST differ from the conventional serializer's output.
///
/// If this ever passes trivially — the two agreeing — R1 has stopped being a
/// discriminating fixture and MUST be redesigned. Weakening this assertion is
/// never an acceptable repair.
#[test]
fn r1_is_discriminating() {
    let execution = execute();
    assert_ne!(
        execution.canonical,
        execution.conventional,
        "R1 is NOT discriminating: RFC 8785 and serde_json::to_vec agree\n  jcs  = {}\n  conv = {}",
        String::from_utf8_lossy(&execution.canonical),
        String::from_utf8_lossy(&execution.conventional),
    );
}

/// Characterisation: the CANONICAL-001 fixture is **not** discriminating.
/// This is the gap R1 closes, asserted so it cannot silently stop being true.
#[test]
fn canonical_001_fixture_would_not_have_caught_a_non_jcs_engine() {
    let raw = std::fs::read_to_string(repo_root().join("conformance/canonical/CANONICAL-001.json"))
        .expect("CANONICAL-001 input must be readable");
    let value: serde_json::Value = serde_json::from_str(&raw).expect("valid JSON");

    assert_eq!(
        jcs::canonical_bytes(&value).expect("canonicalization must succeed"),
        conventional_bytes(&value),
        "CANONICAL-001 was expected to be non-discriminating for serde_json",
    );
}

// ---------------------------------------------------------------------------
// Leaf domain
// ---------------------------------------------------------------------------

/// The leaf preimage must be the raw octet `0x00` followed by the raw canonical
/// bytes — not the ASCII text `"0x00"`, not a hex string, not re-serialized JSON.
#[test]
fn r1_leaf_uses_raw_0x00_prefix() {
    let execution = execute();

    let mut preimage = Vec::with_capacity(1 + execution.canonical.len());
    preimage.push(LEAF_DOMAIN);
    preimage.extend_from_slice(&execution.canonical);

    assert_eq!(preimage[0], 0x00);
    assert_eq!(&preimage[1..], &execution.canonical[..]);
    assert_eq!(preimage.len(), execution.canonical.len() + 1);
    assert_eq!(
        hex::encode(Sha256::digest(&preimage)),
        execution.leaf_sha256
    );
}

/// The shipping `aura_guard::merkle::leaf_hash` must already implement
/// `SHA-256(0x00 || data)`. This **observes** production code; a mismatch is
/// reported, never repaired here.
#[test]
fn r1_merkle_leaf_domain_matches_rfc6962() {
    let execution = execute();
    let from_production = aura_guard::merkle::leaf_hash(&execution.canonical);
    assert_eq!(hex::encode(from_production), execution.leaf_sha256);
}

// ---------------------------------------------------------------------------
// Execution + emission — running this test IS the RI-RS evidence
// ---------------------------------------------------------------------------

/// Drive the frozen JCS boundary over the R1 fixture, persist the observed
/// values, and only then assert internal consistency and the engine pin.
#[test]
fn r1_execute_and_emit_artifact() {
    let execution = execute();
    let artifact = artifact(&execution);

    // Evidence is persisted before any expectation is checked.
    write_artifact(&artifact);

    eprintln!(
        "RI-RS R1-JCS-DISCRIMINATING execution\n{}",
        serde_json::to_string_pretty(&artifact).expect("artifact is serializable")
    );

    assert_eq!(
        artifact["canonical_bytes_hex"]
            .as_str()
            .expect("hex string"),
        hex::encode(&execution.canonical),
    );
    assert_eq!(
        artifact["canonical_bytes_len"].as_u64().expect("length"),
        execution.canonical.len() as u64,
    );
    assert_eq!(
        artifact["sha256"].as_str().expect("sha string"),
        sha256_hex(&execution.canonical),
    );
    assert_eq!(
        artifact["leaf_sha256"].as_str().expect("leaf string"),
        leaf_sha256_hex(&execution.canonical),
    );
    assert_eq!(artifact["engine"].as_str().expect("engine"), ENGINE);
    assert_eq!(
        artifact["engine_version"].as_str().expect("version"),
        ENGINE_VERSION,
        "frozen protocol contract pins the RI-RS JCS engine to {ENGINE_VERSION}",
    );
    assert!(
        artifact["discrimination"]["differs_from_jcs"]
            .as_bool()
            .expect("bool"),
        "the emitted artifact must record a real discrimination",
    );
    assert_eq!(
        artifact["provenance"]["input_sha256"]
            .as_str()
            .expect("input sha"),
        file_sha256_hex(&input_path()),
    );
}

/// Reproducibility: two executions in the same process must agree byte-for-byte.
#[test]
fn r1_execution_is_reproducible() {
    let first = execute();
    let second = execute();

    assert_eq!(first.canonical, second.canonical);
    assert_eq!(first.sha256, second.sha256);
    assert_eq!(first.leaf_sha256, second.leaf_sha256);
}
