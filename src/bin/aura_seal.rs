//! `aura-seal` — offline verifier and proof-generator for Merkle segment
//! manifests.
//!
//! Subcommands:
//!
//! * `verify` — Verify every manifest's Merkle root, head pointer, and
//!   segment-chain linkage against the audit log.
//! * `verify-chain` — Verify segment-chain linkage only (no audit log).
//! * `proof` — Emit a Merkle inclusion proof for a single audit entry,
//!   terminating at the segment that contains it.
//!
//! Exit codes:
//!
//! | code | meaning                                                       |
//! | ---- | ------------------------------------------------------------- |
//! | 0    | OK                                                            |
//! | 1    | I/O or argument error                                         |
//! | 4    | segment-chain break (linkage / self-hash / id gap)            |
//! | 5    | manifest <-> audit-log mismatch                               |

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use aura_guard::log_writer::read_all_entries;
use aura_guard::merkle::{audit_path, leaf_hash, verify_audit_path};
use aura_guard::rfc3161::contains_imprint;
use aura_guard::segment::{
    entry_leaf_hash, load_manifests, verify_manifest_against_entries, verify_segment_chain,
    SegmentManifest,
};
use sha2::{Digest, Sha256};

const EX_CHAIN_BREAK: u8 = 4;
const EX_LOG_MISMATCH: u8 = 5;
const EX_TST_INVALID: u8 = 6;

#[derive(Parser, Debug)]
#[command(
    name = "aura-seal",
    about = "Aura-Guard Merkle segment verifier and proof generator",
    version = env!("CARGO_PKG_VERSION")
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Verify every segment manifest against the audit log + its segment-chain.
    Verify {
        /// Path to the audit log (JSONL).
        #[arg(long, default_value = "logs/audit.jsonl")]
        log: PathBuf,
        /// Directory containing `*.manifest.json` files.
        #[arg(long, default_value = "logs/segments")]
        segments: PathBuf,
        /// Emit machine-readable JSON only.
        #[arg(long)]
        json: bool,
    },
    /// Verify only the segment-chain linkage (no audit-log access required).
    VerifyChain {
        /// Directory containing `*.manifest.json` files.
        #[arg(long, default_value = "logs/segments")]
        segments: PathBuf,
        /// Emit machine-readable JSON only.
        #[arg(long)]
        json: bool,
    },
    /// Generate a Merkle inclusion proof for a single audit entry.
    Proof {
        /// Path to the audit log (JSONL).
        #[arg(long, default_value = "logs/audit.jsonl")]
        log: PathBuf,
        /// Directory containing `*.manifest.json` files.
        #[arg(long, default_value = "logs/segments")]
        segments: PathBuf,
        /// Sequence number of the entry to prove.
        #[arg(long)]
        seq: u64,
    },
    /// Verify an RFC 3161 Time-Stamp Response (`NNNNNN.tsr`) by checking
    /// that its `messageImprint` field equals
    /// `SHA-256(segment_chain_preimage)` of the matching manifest.
    ///
    /// Note: v1.4 ships imprint verification only. Full PKIX/SignedData
    /// validation against an operator-pinned TSA root lands in v1.5.
    VerifyTst {
        /// Directory containing `*.manifest.json` and `*.tsr` files.
        #[arg(long, default_value = "logs/segments")]
        segments: PathBuf,
        /// Segment id to verify; omit to verify all `.tsr` files present.
        #[arg(long)]
        segment_id: Option<u64>,
        /// Emit machine-readable JSON only.
        #[arg(long)]
        json: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Verify {
            log,
            segments,
            json,
        } => cmd_verify(log, segments, json),
        Cmd::VerifyChain { segments, json } => cmd_verify_chain(segments, json),
        Cmd::Proof { log, segments, seq } => cmd_proof(log, segments, seq),
        Cmd::VerifyTst {
            segments,
            segment_id,
            json,
        } => cmd_verify_tst(segments, segment_id, json),
    }
}

fn cmd_verify(log: PathBuf, segments: PathBuf, json: bool) -> ExitCode {
    let entries = match read_all_entries(&log) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("error: failed to read audit log '{}': {e}", log.display());
            return ExitCode::from(1);
        }
    };
    let manifests = match load_manifests(&segments) {
        Ok(m) => m,
        Err(e) => {
            eprintln!(
                "error: failed to load segment manifests from '{}': {e}",
                segments.display()
            );
            return ExitCode::from(1);
        }
    };

    if !json {
        println!("aura-seal v{}", env!("CARGO_PKG_VERSION"));
        println!("audit-log: {} ({} entries)", log.display(), entries.len());
        println!(
            "segments : {} ({} manifests)",
            segments.display(),
            manifests.len()
        );
    }

    // 1. Segment-chain linkage.
    let chain_head = match verify_segment_chain(&manifests) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("FAIL: {e}");
            return ExitCode::from(EX_CHAIN_BREAK);
        }
    };

    // 2. Each manifest vs. audit-log entries it covers.
    for m in &manifests {
        let first = m.first_seq as usize;
        let last = m.last_seq as usize;
        if last >= entries.len() || first > last {
            eprintln!(
                "FAIL: segment {} references entry range [{first}, {last}] \
                 but log has {} entries",
                m.segment_id,
                entries.len()
            );
            return ExitCode::from(EX_LOG_MISMATCH);
        }
        let slice = &entries[first..=last];
        if let Err(e) = verify_manifest_against_entries(m, slice) {
            eprintln!("FAIL: {e}");
            return ExitCode::from(EX_LOG_MISMATCH);
        }
    }

    if json {
        let out = serde_json::json!({
            "status": "ok",
            "entries": entries.len(),
            "segments": manifests.len(),
            "head_segment_chain_hash": chain_head,
        });
        println!("{out}");
    } else {
        println!(
            "SEGMENTS OK — {} manifest(s), head_segment_chain_hash: {chain_head}",
            manifests.len()
        );
    }
    ExitCode::SUCCESS
}

fn cmd_verify_chain(segments: PathBuf, json: bool) -> ExitCode {
    let manifests = match load_manifests(&segments) {
        Ok(m) => m,
        Err(e) => {
            eprintln!(
                "error: failed to load segment manifests from '{}': {e}",
                segments.display()
            );
            return ExitCode::from(1);
        }
    };
    if !json {
        println!("aura-seal v{}", env!("CARGO_PKG_VERSION"));
        println!(
            "segments: {} ({} manifests)",
            segments.display(),
            manifests.len()
        );
    }
    match verify_segment_chain(&manifests) {
        Ok(head) => {
            if json {
                let out = serde_json::json!({
                    "status": "ok",
                    "segments": manifests.len(),
                    "head_segment_chain_hash": head,
                });
                println!("{out}");
            } else {
                println!("SEGMENT CHAIN OK — head_segment_chain_hash: {head}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("FAIL: {e}");
            ExitCode::from(EX_CHAIN_BREAK)
        }
    }
}

fn cmd_proof(log: PathBuf, segments: PathBuf, seq: u64) -> ExitCode {
    let entries = match read_all_entries(&log) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("error: failed to read audit log: {e}");
            return ExitCode::from(1);
        }
    };
    let manifests = match load_manifests(&segments) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: failed to load segment manifests: {e}");
            return ExitCode::from(1);
        }
    };
    let Some(manifest) = manifests
        .iter()
        .find(|m| seq >= m.first_seq && seq <= m.last_seq)
    else {
        eprintln!(
            "error: entry seq={seq} not covered by any sealed segment \
             (largest covered = {})",
            manifests.last().map(|m| m.last_seq as i64).unwrap_or(-1)
        );
        return ExitCode::from(1);
    };

    let first = manifest.first_seq as usize;
    let last = manifest.last_seq as usize;
    if last >= entries.len() {
        eprintln!(
            "error: segment {} references entries [{first}, {last}] but log \
             has only {} entries",
            manifest.segment_id,
            entries.len()
        );
        return ExitCode::from(EX_LOG_MISMATCH);
    }
    let slice = &entries[first..=last];
    let leaves: Vec<[u8; 32]> = match slice.iter().map(entry_leaf_hash).collect() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: cannot rebuild leaf hashes: {e}");
            return ExitCode::from(EX_LOG_MISMATCH);
        }
    };
    let local_index = (seq - manifest.first_seq) as usize;
    let path = audit_path(local_index, &leaves);

    // Sanity-check that the proof verifies against the manifest root.
    let raw_chain = match hex::decode(&entries[seq as usize].chain_hash) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: malformed chain_hash in log: {e}");
            return ExitCode::from(EX_LOG_MISMATCH);
        }
    };
    let leaf = leaf_hash(&raw_chain);
    let mut root = [0u8; 32];
    let _ = hex::decode_to_slice(&manifest.merkle_root, &mut root);
    if !verify_audit_path(&leaf, local_index, leaves.len(), &path, &root) {
        eprintln!(
            "FAIL: locally-generated proof does not verify against the sealed manifest \
             (segment {})",
            manifest.segment_id
        );
        return ExitCode::from(EX_LOG_MISMATCH);
    }

    let proof_hex: Vec<String> = path.iter().map(hex::encode).collect();
    let out = serde_json::json!({
        "schema": "aura-guard.merkle-proof.v1",
        "entry_seq": seq,
        "leaf_hash": hex::encode(leaf),
        "leaf_index": local_index,
        "tree_size": leaves.len(),
        "merkle_root": manifest.merkle_root,
        "segment_id": manifest.segment_id,
        "segment_chain_hash": manifest.segment_chain_hash,
        "audit_path": proof_hex,
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
    ExitCode::SUCCESS
}

fn cmd_verify_tst(segments: PathBuf, segment_id: Option<u64>, json: bool) -> ExitCode {
    let manifests = match load_manifests(&segments) {
        Ok(m) => m,
        Err(e) => {
            eprintln!(
                "error: cannot load manifests from '{}': {e}",
                segments.display()
            );
            return ExitCode::from(1);
        }
    };

    let mut checked = 0usize;
    let mut missing = 0usize;
    let mut results: Vec<serde_json::Value> = Vec::new();

    for m in &manifests {
        if let Some(want) = segment_id {
            if m.segment_id != want {
                continue;
            }
        }
        let tsr_path = segments.join(format!("{:06}.tsr", m.segment_id));
        if !tsr_path.exists() {
            missing += 1;
            if !json {
                println!(
                    "seg {:06}  TSR MISSING ({})",
                    m.segment_id,
                    tsr_path.display()
                );
            }
            results.push(serde_json::json!({
                "segment_id": m.segment_id,
                "status": "missing",
            }));
            continue;
        }
        match verify_one_tst(m, &tsr_path) {
            Ok(()) => {
                checked += 1;
                if !json {
                    println!(
                        "seg {:06}  TST OK   ({} bytes)",
                        m.segment_id,
                        std::fs::metadata(&tsr_path).map(|m| m.len()).unwrap_or(0)
                    );
                }
                results.push(serde_json::json!({
                    "segment_id": m.segment_id,
                    "status": "ok",
                }));
            }
            Err(e) => {
                if !json {
                    eprintln!("seg {:06}  TST FAIL: {e}", m.segment_id);
                }
                results.push(serde_json::json!({
                    "segment_id": m.segment_id,
                    "status": "fail",
                    "error": e,
                }));
                if json {
                    let out = serde_json::json!({
                        "status": "fail",
                        "checked": checked,
                        "missing": missing,
                        "results": results,
                    });
                    println!("{out}");
                }
                return ExitCode::from(EX_TST_INVALID);
            }
        }
    }

    if let Some(want) = segment_id {
        if !manifests.iter().any(|m| m.segment_id == want) {
            eprintln!("error: segment_id {want} not found");
            return ExitCode::from(1);
        }
    }

    if json {
        let out = serde_json::json!({
            "status": "ok",
            "checked": checked,
            "missing": missing,
            "results": results,
        });
        println!("{out}");
    } else {
        println!(
            "\nTST summary: {checked} OK, {missing} missing (out of {} manifest(s))",
            manifests.len()
        );
    }
    ExitCode::SUCCESS
}

fn verify_one_tst(m: &SegmentManifest, tsr_path: &std::path::Path) -> Result<(), String> {
    let tsr =
        std::fs::read(tsr_path).map_err(|e| format!("cannot read {}: {e}", tsr_path.display()))?;
    let preimage = SegmentManifest::segment_chain_preimage(
        &m.prev_segment_chain_hash,
        &m.merkle_root,
        m.first_seq,
        m.last_seq,
        &m.sealed_at,
    );
    let digest: [u8; 32] = Sha256::digest(preimage.as_bytes()).into();
    if !contains_imprint(&tsr, &digest) {
        return Err(format!(
            "TSR messageImprint does not match SHA-256(segment_chain_preimage); \
             expected imprint = {}",
            hex::encode(digest)
        ));
    }
    Ok(())
}
