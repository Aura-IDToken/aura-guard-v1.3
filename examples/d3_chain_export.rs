//! D-3 evidence exporter.
//!
//! Drives the **existing** production chain implementation against
//! `D3_REAL_CHAIN_SEMANTIC_FIXTURE.json` and exports the canonical preimage,
//! its raw UTF-8 bytes and the resulting `chain_hash`.
//!
//! This binary implements no canonicalization and no hashing of its own. Every
//! value it reports is produced by calling:
//!
//! * [`aura_guard::chain::chain_preimage`]
//! * [`aura_guard::chain::compute_chain_hash`]
//! * [`aura_guard::crypto::sha256_hex`] / [`sha256_bytes_hex`]
//! * [`aura_guard::crypto::genesis_hash`]
//! * [`aura_guard::normalizer::shadow_normalize`]
//!
//! Usage: `cargo run --example d3_chain_export`

use aura_guard::chain::{chain_preimage, compute_chain_hash};
use aura_guard::crypto::{genesis_hash, sha256_bytes_hex, sha256_hex};
use aura_guard::normalizer::shadow_normalize;
use serde_json::{json, Value};

type Err = Box<dyn std::error::Error>;

const FIXTURE_PATH: &str = "D3_REAL_CHAIN_SEMANTIC_FIXTURE.json";
const OUTPUT_PATH: &str = "D3_REAL_CHAIN_RUST_OUTPUT.json";
const CANONICAL_BIN: &str = "D3_REAL_CHAIN_CANONICAL.bin";

fn field<'a>(v: &'a Value, path: &str, key: &str) -> Result<&'a Value, Err> {
    v.get(path)
        .and_then(|s| s.get(key))
        .ok_or_else(|| -> Err { format!("fixture missing {path}.{key}").into() })
}

fn text(v: &Value, path: &str, key: &str) -> Result<String, Err> {
    field(v, path, key)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| -> Err { format!("fixture {path}.{key} is not a string").into() })
}

fn env_or(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| "unavailable".to_owned())
}

fn main() -> Result<(), Err> {
    // --- Fixture identity ------------------------------------------------
    let fixture_bytes = std::fs::read(FIXTURE_PATH)?;
    let fixture_sha256 = sha256_bytes_hex(&fixture_bytes);
    let fixture: Value = serde_json::from_slice(&fixture_bytes)?;

    // --- The nine chain-preimage fields, supplied by the fixture ---------
    let p = "chain_preimage_fields";
    let prev_hash = text(&fixture, p, "prev_hash")?;
    let decision = text(&fixture, p, "decision")?;
    let policy_set = text(&fixture, p, "policy_set")?;
    let policy_hash = text(&fixture, p, "policy_hash")?;
    let context = text(&fixture, p, "context")?;
    let input_hash = text(&fixture, p, "input_hash")?;
    let shadow_hash = text(&fixture, p, "shadow_hash")?;
    let timestamp = text(&fixture, p, "timestamp")?;
    let seq: u64 = field(&fixture, p, "seq")?
        .as_u64()
        .ok_or_else(|| -> Err { "fixture chain_preimage_fields.seq is not a u64".into() })?;

    // --- Cross-checks against the real production derivations ------------
    // These confirm the pinned fixture values are consistent with what the
    // existing implementation produces. They do not feed the digest.
    let original = text(&fixture, "input_state", "original")?;
    let policy_file = text(&fixture, "input_state", "policy_file")?;

    let observed_genesis = genesis_hash();
    let observed_input_hash = sha256_hex(&original);
    let observed_shadow = shadow_normalize(&original);
    let observed_shadow_hash = sha256_hex(&observed_shadow);
    let observed_policy_hash = match std::fs::read(&policy_file) {
        Ok(b) => sha256_bytes_hex(&b),
        Err(e) => format!("unreadable: {e}"),
    };

    let cross_checks = json!({
        "prev_hash_equals_genesis": prev_hash == observed_genesis,
        "input_hash_equals_sha256_of_original": input_hash == observed_input_hash,
        "shadow_hash_equals_sha256_of_shadow": shadow_hash == observed_shadow_hash,
        "policy_hash_equals_policy_file": policy_hash == observed_policy_hash,
        "observed": {
            "genesis_hash": observed_genesis,
            "shadow_normalized": observed_shadow,
            "input_hash": observed_input_hash,
            "shadow_hash": observed_shadow_hash,
            "policy_hash": observed_policy_hash,
        }
    });

    // --- THE EXPERIMENT: existing implementation, called directly --------
    let canonical_string = chain_preimage(
        &prev_hash,
        &decision,
        &policy_set,
        &policy_hash,
        &context,
        &input_hash,
        &shadow_hash,
        seq,
        &timestamp,
    );
    let chain_hash = compute_chain_hash(
        &prev_hash,
        &decision,
        &policy_set,
        &policy_hash,
        &context,
        &input_hash,
        &shadow_hash,
        seq,
        &timestamp,
    );

    let canonical_bytes = canonical_string.as_bytes();
    let canonical_bytes_hex = hex::encode(canonical_bytes);
    let canonical_bytes_length = canonical_bytes.len();

    // --- Section 11: hash independence check -----------------------------
    // Re-hash the exported bytes through the byte-oriented entry point and
    // confirm it reproduces the digest the chain implementation returned.
    let recomputed = sha256_bytes_hex(canonical_bytes);
    let hash_independence_check = recomputed == chain_hash;

    // --- Section 14: before/after regression control ---------------------
    let expected_before = fixture
        .get("expected")
        .and_then(|e| e.get("chain_hash_before_instrumentation"))
        .and_then(Value::as_str)
        .unwrap_or("absent");
    let hash_unchanged_by_instrumentation = expected_before == chain_hash;

    let output = json!({
        "experiment": "D-3 real Rust chain execution",
        "repository": env_or("GITHUB_REPOSITORY"),
        "commit_sha": env_or("GITHUB_SHA"),
        "workflow_run_id": env_or("GITHUB_RUN_ID"),
        "runner_os": env_or("RUNNER_OS"),
        "runner_arch": env_or("RUNNER_ARCH"),
        "rust_version": env_or("D3_RUST_VERSION"),
        "cargo_version": env_or("D3_CARGO_VERSION"),
        "fixture_path": FIXTURE_PATH,
        "fixture_sha256": fixture_sha256,
        "entrypoint": {
            "preimage": "aura_guard::chain::chain_preimage (src/chain.rs)",
            "digest": "aura_guard::chain::compute_chain_hash -> aura_guard::crypto::sha256_hex",
        },
        "rust_canonical_string": canonical_string,
        "rust_canonical_bytes_hex": canonical_bytes_hex,
        "rust_canonical_bytes_length": canonical_bytes_length,
        "rust_chain_hash": chain_hash,
        "hash_independence_check": {
            "sha256_of_exported_bytes": recomputed,
            "matches_chain_hash": hash_independence_check,
        },
        "instrumentation_control": {
            "chain_hash_before_instrumentation": expected_before,
            "chain_hash_after_instrumentation": chain_hash,
            "identical": hash_unchanged_by_instrumentation,
        },
        "cross_checks": cross_checks,
    });

    std::fs::write(CANONICAL_BIN, canonical_bytes)?;
    let rendered = serde_json::to_string_pretty(&output)?;
    std::fs::write(OUTPUT_PATH, format!("{rendered}\n"))?;

    println!("{rendered}");

    if !hash_independence_check {
        return Err("FAIL: SHA-256 of exported bytes != chain_hash".into());
    }
    if !hash_unchanged_by_instrumentation {
        return Err("STOP: chain_hash changed relative to the pre-instrumentation baseline".into());
    }
    Ok(())
}
