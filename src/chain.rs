//! Hash-chain construction and verification.
//!
//! Each audit entry computes:
//!
//! ```text
//! chain_hash = SHA-256( prev_hash || decision || policy_set || policy_hash
//!                      || context || input_hash || shadow_hash
//!                      || seq || timestamp )
//! ```
//!
//! Field separator is `|` so the input is unambiguous. Tampering with any
//! field — *or with the order of records* — breaks the chain.

use crate::crypto::{genesis_hash, sha256_hex};
use crate::models::AuditEntry;
use crate::{AuraError, Result};

/// Field separator used inside the chain digest. Must never overlap with hex,
/// base64 or any timestamp character.
const SEP: &str = "|";

/// Compute `chain_hash` for an in-progress entry.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn compute_chain_hash(
    prev_hash: &str,
    decision: &str,
    policy_set: &str,
    policy_hash: &str,
    context: &str,
    input_hash: &str,
    shadow_hash: &str,
    seq: u64,
    timestamp: &str,
) -> String {
    let canonical = [
        prev_hash,
        decision,
        policy_set,
        policy_hash,
        context,
        input_hash,
        shadow_hash,
        &seq.to_string(),
        timestamp,
    ]
    .join(SEP);
    sha256_hex(&canonical)
}

/// Recompute the chain digest for an existing entry (used by the replay CLI).
#[must_use]
pub fn recompute_for_entry(entry: &AuditEntry) -> String {
    compute_chain_hash(
        &entry.prev_hash,
        &entry.decision,
        &entry.policy_set,
        &entry.policy_hash,
        &entry.context,
        &entry.input_hash,
        &entry.shadow_hash,
        entry.seq,
        &entry.timestamp,
    )
}

/// Walk the chain and fail on the first broken link.
///
/// On success returns the final `chain_hash` so callers can also pin
/// "head-of-chain" digests in offline registries.
pub fn verify_chain(entries: &[AuditEntry]) -> Result<String> {
    let mut expected_prev = genesis_hash();
    for (i, entry) in entries.iter().enumerate() {
        if entry.prev_hash != expected_prev {
            return Err(AuraError::ChainBreak {
                index: i,
                expected: expected_prev,
                actual: entry.prev_hash.clone(),
            });
        }
        let recomputed = recompute_for_entry(entry);
        if recomputed != entry.chain_hash {
            return Err(AuraError::ChainBreak {
                index: i,
                expected: entry.chain_hash.clone(),
                actual: recomputed,
            });
        }
        expected_prev = entry.chain_hash.clone();
    }
    Ok(expected_prev)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn entry(seq: u64, prev: &str, decision: &str) -> AuditEntry {
        let mut e = AuditEntry {
            schema: "aura-guard.audit.v1".into(),
            seq,
            audit_id: format!("{:08}", seq),
            timestamp: "2026-05-12T00:00:00+00:00".into(),
            decision: decision.into(),
            policy_set: "finance-v1".into(),
            policy_hash: "deadbeef".into(),
            context: "ctx".into(),
            input_hash: format!("input-{seq}"),
            shadow_hash: format!("shadow-{seq}"),
            violations: vec![],
            prev_hash: prev.into(),
            chain_hash: String::new(),
        };
        e.chain_hash = recompute_for_entry(&e);
        e
    }

    #[test]
    fn verify_chain_succeeds_on_clean_log() {
        let e0 = entry(0, &genesis_hash(), "ALLOW");
        let e1 = entry(1, &e0.chain_hash, "DENY");
        let e2 = entry(2, &e1.chain_hash, "REVIEW");
        let head = verify_chain(&[e0, e1, e2]).expect("clean chain verifies");
        assert_eq!(head.len(), 64);
    }

    #[test]
    fn verify_chain_detects_field_tamper() {
        let e0 = entry(0, &genesis_hash(), "DENY");
        let mut e1 = entry(1, &e0.chain_hash, "DENY");
        // Tamper with the decision but leave chain_hash intact.
        e1.decision = "ALLOW".into();
        let err = verify_chain(&[e0, e1]).expect_err("must detect tamper");
        match err {
            AuraError::ChainBreak { index, .. } => assert_eq!(index, 1),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn verify_chain_detects_prev_hash_break() {
        let e0 = entry(0, &genesis_hash(), "DENY");
        let mut e1 = entry(1, &e0.chain_hash, "ALLOW");
        // Manually corrupt the link.
        e1.prev_hash = "0".repeat(64);
        e1.chain_hash = recompute_for_entry(&e1);
        let err = verify_chain(&[e0, e1]).expect_err("must detect prev_hash break");
        match err {
            AuraError::ChainBreak { index, .. } => assert_eq!(index, 1),
            other => panic!("unexpected error: {other}"),
        }
    }
}
