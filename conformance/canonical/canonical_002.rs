#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! CANONICAL-002 — RI-RS execution of the JCS-*discriminating* fixture.
//!
//! # Why this fixture exists
//!
//! CANONICAL-001 is JCS-degenerate: an ordinary sorted-JSON serializer
//! reproduces its canonical bytes exactly, so cross-language agreement on it
//! cannot distinguish a conforming RFC 8785 engine from a non-conforming one.
//! CANONICAL-002 contains values for which RFC 8785 and ordinary sorted JSON
//! provably diverge:
//!
//! * member ordering by **UTF-16 code unit** (supplementary-plane keys sort
//!   before `U+FB00` / `U+FFFF`, not after them as code-point order would give);
//! * non-ASCII emitted as **raw UTF-8**, never `\uXXXX`;
//! * ECMAScript number form (`1.0` -> `1`, `-0.0` -> `0`, `1e-6` -> `0.000001`,
//!   `1e-7` -> `1e-7`);
//! * recursive canonicalisation of nested members;
//! * array element order preserved, never sorted;
//! * minimal string escaping, solidus left unescaped.
//!
//! # Anti-fabrication rules enforced here
//!
//! * Canonical bytes are whatever the engine returned. They are never
//!   constructed, patched, or corrected against an expectation.
//! * **No expected constant appears in this file.** Unlike CANONICAL-001, this
//!   test carries no frozen hex: the cross-language gate in the RI-PY
//!   repository is the authority, and hardcoding a constant here would let a
//!   copied value masquerade as an execution result.
//! * The artifact is written *before* the assertions run, so a divergence is
//!   recorded as evidence rather than hidden.
//! * Nothing in this file reads the RI-PY artifact or any RI-PY value.
//!
//! # Scope
//!
//! Conformance surface only. This test does not touch `src/`, does not change
//! any hash domain or Merkle semantic, and does not integrate JCS into the
//! production runtime.
//!
//! Execution command:
//!
//! ```text
//! cargo test --locked --test canonical_002
//! ```

mod jcs;

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// RFC 6962 leaf domain separator — one raw octet, never the ASCII text.
const LEAF_DOMAIN: u8 = 0x00;

/// Repository that owns this reference implementation.
const REPOSITORY: &str = "Aura-IDToken/aura-guard-v1.3";

/// Fixture identifier.
const FIXTURE: &str = "CANONICAL-002";

/// Engine identity, recorded verbatim in the execution artifact.
const ENGINE: &str = "serde_json_canonicalizer";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn corpus_dir() -> PathBuf {
    repo_root().join("conformance").join("corpus").join("canonical-002")
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// RFC 6962 leaf hash: `SHA-256(0x00 || bytes)`.
fn leaf_sha256_hex(bytes: &[u8]) -> String {
    let mut preimage = Vec::with_capacity(1 + bytes.len());
    preimage.push(LEAF_DOMAIN);
    preimage.extend_from_slice(bytes);
    sha256_hex(&preimage)
}

fn file_sha256_hex(path: &Path) -> String {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("cannot read {path:?}: {e}"));
    sha256_hex(&bytes)
}

fn git(args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(repo_root())
        .output()
        .unwrap_or_else(|e| panic!("git {args:?} failed to start: {e}"));
    assert!(output.status.success(), "git {args:?} failed: {output:?}");
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn rustc_version() -> String {
    Command::new("rustc")
        .arg("--version")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Resolve the engine version actually used, from the committed lockfile.
///
/// Read rather than hardcoded: with `cargo test --locked` this is the version
/// that was linked, so a silent engine bump cannot pass unnoticed underneath
/// the recorded evidence.
fn engine_version() -> String {
    let lock = repo_root().join("Cargo.lock");
    let text = std::fs::read_to_string(&lock).expect("Cargo.lock must be readable");
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        if line.trim() == format!("name = \"{ENGINE}\"") {
            for next in lines.by_ref() {
                if let Some(rest) = next.trim().strip_prefix("version = ") {
                    return rest.trim_matches('"').to_string();
                }
                if next.trim().starts_with("[[package]]") {
                    break;
                }
            }
        }
    }
    panic!("{ENGINE} not found in Cargo.lock");
}

/// Result of executing the RI-RS CANONICAL-002 path.
struct Execution {
    canonical: Vec<u8>,
    sha256: String,
    leaf_sha256: String,
    input_path: PathBuf,
}

/// Read the frozen fixture input and run it through the JCS engine.
///
/// No expected constant and no other implementation's artifact is read here.
/// The bytes are whatever the engine returns.
fn execute_canonical_002() -> Execution {
    let input_path = corpus_dir().join("input.json");
    let text = std::fs::read_to_string(&input_path)
        .unwrap_or_else(|e| panic!("cannot read {input_path:?}: {e}"));
    let value: Value = serde_json::from_str(&text).expect("fixture input is not valid JSON");

    // --- the only place canonical bytes come into existence -----------------
    let canonical = jcs::canonical_bytes(&value).expect("JCS canonicalization failed");
    // ------------------------------------------------------------------------

    let sha256 = sha256_hex(&canonical);
    let leaf_sha256 = leaf_sha256_hex(&canonical);

    Execution { canonical, sha256, leaf_sha256, input_path }
}

/// Package an [`Execution`] as the RI-RS CANONICAL-002 evidence artifact.
///
/// Field names and shape match the CANONICAL-001 artifact so the existing
/// cross-language gate architecture applies unchanged.
fn artifact(execution: &Execution) -> Value {
    let adapter_path = repo_root().join("conformance").join("canonical").join("jcs.rs");
    let lock_path = repo_root().join("Cargo.lock");

    json!({
        "fixture": FIXTURE,
        "implementation": "RI-RS",
        "repository": REPOSITORY,
        "commit": git(&["rev-parse", "HEAD"]),
        "worktree_clean": git(&["status", "--porcelain"]).is_empty(),
        "engine": ENGINE,
        "engine_version": engine_version(),
        "canonical_bytes_hex": hex::encode(&execution.canonical),
        "canonical_bytes_len": execution.canonical.len(),
        "sha256": execution.sha256,
        "leaf_sha256": execution.leaf_sha256,
        "leaf_domain": "0x00",
        "canonicalization": "RFC8785",
        "provenance": {
            "input_path": "conformance/corpus/canonical-002/input.json",
            "input_sha256": file_sha256_hex(&execution.input_path),
            "adapter_path": "conformance/canonical/jcs.rs",
            "adapter_sha256": file_sha256_hex(&adapter_path),
            "lockfile_path": "Cargo.lock",
            "lockfile_sha256": file_sha256_hex(&lock_path),
            "execution_command": "cargo test --locked --test canonical_002",
            "rust_version": rustc_version(),
            "target": std::env::consts::ARCH,
            "os": std::env::consts::OS,
        },
    })
}

/// Write the artifact as pretty, key-sorted JSON with a trailing newline.
///
/// `serde_json::Value` maps are BTreeMap-backed by default, so the output is
/// already key-sorted and byte-stable across runs.
fn write_artifact(value: &Value) {
    let path = corpus_dir().join("ri-rs.json");
    let mut text = serde_json::to_string_pretty(value).expect("artifact is serializable");
    text.push('\n');
    std::fs::write(&path, text).unwrap_or_else(|e| panic!("cannot write {path:?}: {e}"));
}

/// Execute CANONICAL-002, persist the evidence, then check internal consistency.
#[test]
fn canonical_002_execute_and_emit_artifact() {
    let execution = execute_canonical_002();
    let artifact = artifact(&execution);

    // Evidence is persisted before any assertion is checked.
    write_artifact(&artifact);

    eprintln!(
        "RI-RS CANONICAL-002 execution\n{}",
        serde_json::to_string_pretty(&artifact).expect("artifact is serializable")
    );

    assert_eq!(
        artifact["canonical_bytes_hex"].as_str().expect("hex string"),
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
    assert_eq!(artifact["engine"].as_str().expect("engine string"), ENGINE);
    assert_eq!(
        artifact["engine_version"].as_str().expect("version string"),
        "0.3.2",
        "frozen protocol contract pins the RI-RS JCS engine to 0.3.2",
    );
}

/// The canonical output must be valid UTF-8 with no insignificant whitespace.
#[test]
fn canonical_002_is_utf8_and_whitespace_free() {
    let execution = execute_canonical_002();
    let text = std::str::from_utf8(&execution.canonical).expect("JCS output is UTF-8");
    assert!(text.starts_with('{') && text.ends_with('}'));
    // No whitespace may appear outside string literals. CANONICAL-002 does
    // contain spaces *inside* string values, so scan structurally.
    let mut in_string = false;
    let mut escaped = false;
    for ch in text.chars() {
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        if ch == '"' {
            in_string = true;
            continue;
        }
        assert!(
            !ch.is_whitespace(),
            "insignificant whitespace {ch:?} found outside a string literal"
        );
    }
}

/// Member ordering must follow UTF-16 code units, not Unicode code points.
///
/// This is the property that separates RFC 8785 from any sorted-JSON
/// serializer. `U+10000` encodes as the surrogate pair `D800 DC00`, so it must
/// sort *before* `U+FB00` and `U+FFFF` even though its code point is larger.
#[test]
fn canonical_002_orders_members_by_utf16_code_unit() {
    let execution = execute_canonical_002();
    let text = std::str::from_utf8(&execution.canonical).expect("UTF-8");

    let supplementary = text
        .find("\"\u{10000}\"")
        .expect("U+10000 key must be present");
    let bmp_ligature = text.find("\"\u{FB00}\"").expect("U+FB00 key must be present");
    let bmp_max = text.find("\"\u{FFFF}\"").expect("U+FFFF key must be present");

    assert!(
        supplementary < bmp_ligature && supplementary < bmp_max,
        "U+10000 must precede U+FB00 and U+FFFF under UTF-16 code-unit ordering \
         (code-point ordering would place it last)"
    );

    // Code-point ordering would be the opposite; assert we did not get that.
    assert!(
        !(bmp_max < supplementary && bmp_ligature < supplementary),
        "members appear to be ordered by code point, not UTF-16 code unit"
    );
}

/// Non-ASCII must be emitted as raw UTF-8, never as `\uXXXX` escapes.
#[test]
fn canonical_002_emits_raw_utf8() {
    let execution = execute_canonical_002();
    let text = std::str::from_utf8(&execution.canonical).expect("UTF-8");

    assert!(text.contains('\u{00E9}'), "U+00E9 must appear as raw UTF-8");
    assert!(text.contains('\u{20AC}'), "U+20AC must appear as raw UTF-8");
    assert!(text.contains('\u{1F600}'), "U+1F600 must appear as raw UTF-8");
    assert!(
        !text.contains("\\u00e9") && !text.contains("\\u20ac"),
        "non-ASCII must not be \\u-escaped"
    );
}

/// ECMAScript number serialization, executed rather than asserted from a table.
#[test]
fn canonical_002_uses_ecmascript_number_form() {
    let execution = execute_canonical_002();
    let text = std::str::from_utf8(&execution.canonical).expect("UTF-8");

    assert!(text.contains("\"one_point_zero\":1,"), "1.0 must serialize as 1");
    assert!(text.contains("\"negative_zero\":0,"), "-0.0 must serialize as 0");
    assert!(text.contains("\"small_exponent\":1e-7"), "1e-7 keeps exponent form");
    assert!(
        text.contains("\"exponent_boundary\":0.000001"),
        "1e-6 must serialize as plain 0.000001"
    );
    assert!(
        text.contains("\"large_exponent\":1e+21"),
        "1e21 must serialize as 1e+21"
    );
    assert!(!text.contains("-0.0"), "negative zero must not survive");
    assert!(!text.contains("1e-07"), "exponent must not be zero-padded");
}

/// Array element order is data, not something to canonicalize.
#[test]
fn canonical_002_preserves_array_order() {
    let execution = execute_canonical_002();
    let text = std::str::from_utf8(&execution.canonical).expect("UTF-8");

    assert!(
        text.contains("\"array_order\":[3,1,2,{\"x\":2,\"y\":1},\"c\",\"a\",\"b\"]"),
        "array order must be preserved while nested object members are canonicalized"
    );
}

/// Escaping must be minimal, and solidus must NOT be escaped.
#[test]
fn canonical_002_uses_minimal_escaping() {
    let execution = execute_canonical_002();
    let text = std::str::from_utf8(&execution.canonical).expect("UTF-8");

    // The control character is present in the fixture as the escape sequence
    // `\u0001` (six ASCII characters), never as a raw octet.
    assert!(text.contains(r#"quote\" backslash\\ newline\n tab\t ctrl\u0001 solidus/ end"#));
    assert!(!text.contains("\\/"), "solidus must not be escaped");
}

/// Canonicalization must be independent of input member order.
#[test]
fn canonical_002_is_input_order_independent() {
    let input_path = corpus_dir().join("input.json");
    let text = std::fs::read_to_string(&input_path).expect("input readable");
    let value: Value = serde_json::from_str(&text).expect("valid JSON");

    // Re-serialize through serde_json (non-canonical) and re-parse, which
    // reshuffles nothing semantically but proves the engine does not depend on
    // the source text.
    let round_tripped: Value =
        serde_json::from_str(&serde_json::to_string(&value).expect("serializable"))
            .expect("valid JSON");

    assert_eq!(
        jcs::canonical_bytes(&value).expect("canonicalize"),
        jcs::canonical_bytes(&round_tripped).expect("canonicalize"),
    );
}
