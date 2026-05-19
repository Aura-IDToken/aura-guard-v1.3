//! `aura-replay` — offline audit-chain verification CLI.
//!
//! Usage:
//!
//! ```text
//! aura-replay --log logs/audit.jsonl
//! aura-replay --log logs/audit.jsonl --policies-dir policies --verify-lineage
//! ```
//!
//! Behaviour:
//!
//! * Always verifies the SHA-256 hash chain. A break aborts with exit code `2`
//!   and prints `CHAIN BREAK DETECTED at entry #N`.
//! * With `--verify-lineage`, the on-disk policy file referenced by each
//!   entry is reloaded and its SHA-256 is compared against the `policy_hash`
//!   stored in the log. Mismatches abort with exit code `3`
//!   (`LINEAGE MISMATCH`). This is **not** a full decision replay — the raw
//!   prompt/response never enters the log by design (privacy minimization).
//!   What it proves is *cryptographic continuity* between the policy that
//!   was evaluated at the time and the policy currently sitting on disk.
//! * `--recompute` is a deprecated alias for `--verify-lineage` and emits a
//!   one-time warning to stderr.
//! * On success prints a JSON summary to stdout and exits `0`.

#![forbid(unsafe_code)]

use clap::Parser;
use std::path::PathBuf;
use std::process::ExitCode;

use aura_guard::chain::verify_chain;
use aura_guard::log_writer::read_all_entries;
use aura_guard::policy::{load_policy, TrustedSigners};
use aura_guard::segment::{load_manifests, verify_manifest_against_entries, verify_segment_chain};

#[derive(Parser, Debug)]
#[command(
    name = "aura-replay",
    about = "Aura-Guard offline audit-chain verifier",
    version = env!("CARGO_PKG_VERSION")
)]
struct Args {
    /// Path to the JSONL audit log.
    #[arg(long, default_value = "logs/audit.jsonl")]
    log: PathBuf,

    /// Directory containing policy YAML files (required for --verify-lineage).
    #[arg(long, default_value = "policies")]
    policies_dir: PathBuf,

    /// Path to the trusted signers JSON file.
    #[arg(long, default_value = "policies/trusted_signers.json")]
    trusted_signers: PathBuf,

    /// Verify that the on-disk policy file for every entry still matches the
    /// `policy_hash` recorded at the time of evaluation.
    ///
    /// Requires the original policy files and a valid signer table (unless
    /// `--no-signature-verify` is also passed).
    #[arg(long)]
    verify_lineage: bool,

    /// Deprecated alias for `--verify-lineage`, kept for script compatibility.
    /// Emits a warning to stderr when used.
    #[arg(long, hide_short_help = true)]
    recompute: bool,

    /// Skip policy signature enforcement (useful for forensic inspection where
    /// the signer keys are unavailable).
    #[arg(long)]
    no_signature_verify: bool,

    /// Also verify Merkle segment manifests against the audit log.
    #[arg(long)]
    verify_segments: bool,

    /// Directory containing `*.manifest.json` files (used with `--verify-segments`).
    #[arg(long, default_value = "logs/segments")]
    segments_dir: PathBuf,

    /// Emit machine-readable JSON only (no human-readable banner).
    #[arg(long)]
    json: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();

    // Resolve the deprecated alias.
    let verify_lineage = args.verify_lineage || args.recompute;
    if args.recompute && !args.verify_lineage {
        eprintln!(
            "warning: --recompute is deprecated; use --verify-lineage. \
             (--recompute never re-evaluated decisions — the raw prompt is \
             not logged by design — it only verified policy-hash continuity.)"
        );
    }

    let entries = match read_all_entries(&args.log) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("error: failed to read log: {e}");
            return ExitCode::from(1);
        }
    };

    if !args.json {
        println!("aura-replay v{}", env!("CARGO_PKG_VERSION"));
        println!("log: {}", args.log.display());
        println!("entries: {}", entries.len());
    }

    let head = match verify_chain(&entries) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("FAIL: {e}");
            return ExitCode::from(2);
        }
    };

    if verify_lineage {
        let signers = if args.no_signature_verify {
            TrustedSigners::empty()
        } else {
            match TrustedSigners::load(&args.trusted_signers) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("FAIL: cannot load trusted signers: {e}");
                    return ExitCode::from(1);
                }
            }
        };
        for (i, entry) in entries.iter().enumerate() {
            let policy = match load_policy(
                &entry.policy_set,
                &args.policies_dir,
                &signers,
                !args.no_signature_verify,
            ) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!(
                        "FAIL: cannot load policy '{}' for entry #{i}: {e}",
                        entry.policy_set
                    );
                    return ExitCode::from(1);
                }
            };
            if policy.policy_hash != entry.policy_hash {
                eprintln!(
                    "FAIL: LINEAGE MISMATCH at entry #{i}: policy '{}' on disk \
                     (hash={}) differs from logged provenance (hash={}).",
                    entry.policy_set, policy.policy_hash, entry.policy_hash
                );
                return ExitCode::from(3);
            }
        }
    }

    // Optional Merkle segment verification.
    let mut segments_head: Option<String> = None;
    let mut segment_count = 0usize;
    if args.verify_segments {
        let manifests = match load_manifests(&args.segments_dir) {
            Ok(m) => m,
            Err(e) => {
                eprintln!(
                    "FAIL: cannot load segment manifests from '{}': {e}",
                    args.segments_dir.display()
                );
                return ExitCode::from(1);
            }
        };
        segment_count = manifests.len();
        match verify_segment_chain(&manifests) {
            Ok(h) => segments_head = Some(h),
            Err(e) => {
                eprintln!("FAIL: SEGMENT CHAIN BREAK: {e}");
                return ExitCode::from(4);
            }
        }
        for m in &manifests {
            let first = m.first_seq as usize;
            let last = m.last_seq as usize;
            if last >= entries.len() {
                eprintln!(
                    "FAIL: segment {} references entries [{first}, {last}] \
                     but log has only {} entries",
                    m.segment_id,
                    entries.len()
                );
                return ExitCode::from(5);
            }
            if let Err(e) = verify_manifest_against_entries(m, &entries[first..=last]) {
                eprintln!("FAIL: {e}");
                return ExitCode::from(5);
            }
        }
    }

    if args.json {
        let out = serde_json::json!({
            "status": "ok",
            "entries": entries.len(),
            "head_chain_hash": head,
            "verified_lineage": verify_lineage,
            "verified_segments": args.verify_segments,
            "segments": segment_count,
            "head_segment_chain_hash": segments_head,
        });
        println!("{}", out);
    } else {
        println!("CHAIN OK — head_chain_hash: {head}");
        if verify_lineage {
            println!("LINEAGE OK — every policy_hash on disk matches the logged provenance");
        }
        if args.verify_segments {
            match segments_head {
                Some(ref h) => println!(
                    "SEGMENTS OK — {segment_count} manifest(s), head_segment_chain_hash: {h}"
                ),
                None => println!("SEGMENTS OK — 0 manifest(s) on disk"),
            }
        }
    }
    ExitCode::SUCCESS
}
