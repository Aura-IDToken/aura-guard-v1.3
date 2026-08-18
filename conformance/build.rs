//! Extracts the resolved JCS engine version from `Cargo.lock` and exposes it
//! to the conformance code as the `SJC_RESOLVED_VERSION` compile-time env var.
//!
//! The engine version recorded in a CANONICAL-001 execution artifact must come
//! from the resolved dependency graph, not from a hand-written constant.

use std::path::Path;

fn main() {
    let lock_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock");
    println!("cargo:rerun-if-changed={}", lock_path.display());

    let lock = std::fs::read_to_string(&lock_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", lock_path.display()));

    let version = resolved_version(&lock, "serde_json_canonicalizer").unwrap_or_else(|| {
        panic!(
            "serde_json_canonicalizer not present in {}",
            lock_path.display()
        )
    });

    println!("cargo:rustc-env=SJC_RESOLVED_VERSION={version}");
}

/// Parse `[[package]]` blocks of a Cargo lockfile for the version of `wanted`.
fn resolved_version(lock: &str, wanted: &str) -> Option<String> {
    let mut in_block = false;
    let mut is_match = false;

    for line in lock.lines() {
        let line = line.trim();
        if line == "[[package]]" {
            in_block = true;
            is_match = false;
            continue;
        }
        if line.starts_with('[') {
            in_block = false;
            continue;
        }
        if !in_block {
            continue;
        }
        if let Some(rest) = line.strip_prefix("name = ") {
            is_match = rest.trim().trim_matches('"') == wanted;
        } else if let Some(rest) = line.strip_prefix("version = ") {
            if is_match {
                return Some(rest.trim().trim_matches('"').to_string());
            }
        }
    }
    None
}
