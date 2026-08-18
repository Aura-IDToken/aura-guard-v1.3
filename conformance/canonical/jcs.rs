//! Isolated RFC 8785 JCS adapter for protocol conformance only (RI-RS).
//!
//! This module deliberately does not touch the production `aura-guard` crate:
//! it lives in a separate package with its own lockfile, so the production
//! hashing path, Merkle core and dependency graph are unaffected.
//!
//! Engine binding is frozen by the CANONICAL-001 protocol contract: RI-RS
//! canonical bytes are produced by `serde_json_canonicalizer` 0.3.2 and by
//! nothing else. [`canonical_bytes`] is a direct delegation — it performs no
//! pre-normalisation, no post-processing and no byte construction of its own.

use std::path::Path;
use std::process::Command;

use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Engine identity, recorded verbatim in CANONICAL-001 execution artifacts.
pub const ENGINE: &str = "serde_json_canonicalizer";

/// Engine version, taken from the resolved lockfile at build time.
pub const ENGINE_VERSION: &str = env!("SJC_RESOLVED_VERSION");

/// RFC 6962 leaf domain separator.
pub const LEAF_DOMAIN: u8 = 0x00;

/// Repository that owns this reference implementation.
pub const REPOSITORY: &str = "Aura-IDToken/aura-guard-v1.3";

/// Fixture identifier.
pub const FIXTURE: &str = "CANONICAL-001";

/// Return RFC 8785 JCS UTF-8 bytes for a serializable value.
///
/// This is the sole point at which RI-RS canonical bytes come into existence.
pub fn canonical_bytes<S: Serialize>(value: &S) -> serde_json::Result<Vec<u8>> {
    serde_json_canonicalizer::to_vec(value)
}

/// SHA-256 over the given bytes.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// RFC 6962 leaf hash: `SHA-256(0x00 || bytes)`.
pub fn leaf_sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_DOMAIN]);
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Absolute path of the conformance package root.
pub fn package_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// Absolute path of the repository root (parent of the conformance package).
pub fn repo_root() -> &'static Path {
    match package_root().parent() {
        Some(parent) => parent,
        None => panic!("conformance package has no parent directory"),
    }
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

fn file_sha256_hex(path: &Path) -> String {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("cannot read {path:?}: {e}"));
    sha256_hex(&bytes)
}

fn rustc_version() -> String {
    Command::new("rustc")
        .arg("--version")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Result of executing the RI-RS CANONICAL-001 path.
pub struct Execution {
    /// Bytes as returned by the JCS engine.
    pub canonical: Vec<u8>,
    /// `SHA-256(canonical)`.
    pub sha256: String,
    /// `SHA-256(0x00 || canonical)`.
    pub leaf_sha256: String,
    /// The parsed fixture input, retained for provenance only.
    pub input_path: std::path::PathBuf,
}

/// Read the frozen fixture input and run it through the JCS engine.
///
/// No frozen reference constant and no other implementation's artifact is read
/// here. The bytes are whatever the engine returns.
pub fn execute_canonical_001() -> Execution {
    let input_path = package_root()
        .join("corpus")
        .join("canonical-001")
        .join("input.json");
    let text = std::fs::read_to_string(&input_path)
        .unwrap_or_else(|e| panic!("cannot read {input_path:?}: {e}"));
    let value: Value = serde_json::from_str(&text).expect("fixture input is not valid JSON");

    // --- the only place canonical bytes come into existence -----------------
    let canonical = canonical_bytes(&value).expect("JCS canonicalization failed");
    // ------------------------------------------------------------------------

    let sha256 = sha256_hex(&canonical);
    let leaf_sha256 = leaf_sha256_hex(&canonical);

    Execution {
        canonical,
        sha256,
        leaf_sha256,
        input_path,
    }
}

/// Package an [`Execution`] as the RI-RS CANONICAL-001 evidence artifact.
pub fn artifact(execution: &Execution) -> Value {
    let adapter_path = package_root().join("canonical").join("jcs.rs");
    let lock_path = package_root().join("Cargo.lock");

    json!({
        "fixture": FIXTURE,
        "implementation": "RI-RS",
        "repository": REPOSITORY,
        "commit": git(&["rev-parse", "HEAD"]),
        "worktree_clean": git(&["status", "--porcelain"]).is_empty(),
        "engine": ENGINE,
        "engine_version": ENGINE_VERSION,
        "canonical_bytes_hex": hex::encode(&execution.canonical),
        "canonical_bytes_len": execution.canonical.len(),
        "sha256": execution.sha256,
        "leaf_sha256": execution.leaf_sha256,
        "leaf_domain": "0x00",
        "canonicalization": "RFC8785",
        "provenance": {
            "input_path": "conformance/corpus/canonical-001/input.json",
            "input_sha256": file_sha256_hex(&execution.input_path),
            "adapter_path": "conformance/canonical/jcs.rs",
            "adapter_sha256": file_sha256_hex(&adapter_path),
            "lockfile_path": "conformance/Cargo.lock",
            "lockfile_sha256": file_sha256_hex(&lock_path),
            "execution_command": "cargo test --locked --test canonical_001",
            "rust_version": rustc_version(),
            "target": std::env::consts::ARCH,
            "os": std::env::consts::OS,
        },
    })
}

/// Where the RI-RS artifact is written.
pub fn artifact_path() -> std::path::PathBuf {
    package_root()
        .join("corpus")
        .join("canonical-001")
        .join("ri-rs.json")
}

/// Write the artifact as pretty, key-sorted JSON with a trailing newline.
pub fn write_artifact(value: &Value) {
    let path = artifact_path();
    // `serde_json::Value` maps are BTreeMap-backed by default, so the output is
    // already key-sorted and byte-stable across runs.
    let mut text = serde_json::to_string_pretty(value).expect("artifact is serializable");
    text.push('\n');
    std::fs::write(&path, text).unwrap_or_else(|e| panic!("cannot write {path:?}: {e}"));
}
