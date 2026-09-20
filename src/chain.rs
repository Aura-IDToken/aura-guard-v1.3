//! Hash-chain construction and verification.
//!
//! Production `AuditEntry` hashing uses RFC 8785 JCS over every
//! evidence-bearing field except `chain_hash`. The legacy pipe-joined helpers
//! remain available for D3 observational tooling only.

use crate::canonical::canonical_evidence_bytes;
use crate::crypto::{genesis_hash, sha256_hex};
use crate::models::AuditEntry;
use crate::{AuraError, Result};

/// Legacy observational field separator used by the D3 chain export helpers.
const SEP: &str = "|";

/// Build the legacy nine-field chain preimage used by D3 observational
/// fixtures. This function is not the production `AuditEntry` hash domain.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn chain_preimage(
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
    [
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
    .join(SEP)
}

/// Compute the legacy nine-field chain hash used by observational D3 tooling.
/// Production code must use [`compute_chain_hash_for_entry`].
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
    sha256_hex(&chain_preimage(
        prev_hash,
        decision,
        policy_set,
        policy_hash,
        context,
        input_hash,
        shadow_hash,
        seq,
        timestamp,
    ))
}

/// Compute the production chain hash for a complete `AuditEntry`.
///
/// `chain_hash` is excluded from the canonical byte domain. All other
/// evidence-bearing fields, including `schema`, `audit_id`, `request_id`, and
/// `violations`, are canonicalized by RFC 8785 JCS.
pub fn compute_chain_hash_for_entry(entry: &AuditEntry) -> Result<String> {
    let bytes = canonical_evidence_bytes(entry)
        .map_err(|e| AuraError::Config(format!("canonical AuditEntry serialization failed: {e}")))?;
    Ok(sha256_hex(&bytes))
}

/// Recompute the production chain digest for an existing entry.
///
/// This remains total for replay callers. A malformed evidence value yields
/// an empty digest, which causes `verify_chain` to reject the entry.
#[must_use]
pub fn recompute_for_entry(entry: &AuditEntry) -> String {
    compute_chain_hash_for_entry(entry).unwrap_or_default()
}

/// Walk the chain and fail on the first broken link.
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
    use crate::models::Violation;

    fn entry(seq: u64, prev: &str, decision: &str) -> AuditEntry {
        let mut e = AuditEntry {
            schema: "aura-guard.audit.v1".into(),
            seq,
            audit_id: format!("audit-{seq:08}"),
            request_id: Some(format!("req-{seq}")),
            timestamp: "2026-05-12T00:00:00+00:00".into(),
            decision: decision.into(),
            policy_set: "finance-v1".into(),
            policy_hash: "deadbeef".into(),
            context: "ctx".into(),
            input_hash: format!("input-{seq}"),
            shadow_hash: format!("shadow-{seq}"),
            violations: vec![Violation {
                rule: "R-001".into(),
                action: "review".into(),
                confidence: 0.95,
                validator: Some("validator".into()),
            }],
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
        e1.prev_hash = "0".repeat(64);
        e1.chain_hash = recompute_for_entry(&e1);
        let err = verify_chain(&[e0, e1]).expect_err("must detect prev_hash break");
        match err {
            AuraError::ChainBreak { index, .. } => assert_eq!(index, 1),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn verify_chain_empty_chain_succeeds() {
        let head = verify_chain(&[]).expect("empty chain is valid");
        assert_eq!(head, genesis_hash());
    }

    #[test]
    fn verify_chain_single_entry() {
        let e0 = entry(0, &genesis_hash(), "ALLOW");
        let head = verify_chain(std::slice::from_ref(&e0)).expect("single entry chain");
        assert_eq!(head, e0.chain_hash);
    }

    #[test]
    fn verify_chain_long_chain() {
        let mut entries = Vec::new();
        let mut prev = genesis_hash();
        for i in 0..100 {
            let e = entry(i, &prev, "ALLOW");
            prev = e.chain_hash.clone();
            entries.push(e);
        }
        let head = verify_chain(&entries).expect("long chain verifies");
        assert_eq!(head, entries.last().unwrap().chain_hash);
    }

    #[test]
    fn verify_chain_detects_tamper_in_middle() {
        let mut entries = Vec::new();
        let mut prev = genesis_hash();
        for i in 0..10 {
            let e = entry(i, &prev, "ALLOW");
            prev = e.chain_hash.clone();
            entries.push(e);
        }
        entries[5].decision = "DENY".into();
        let err = verify_chain(&entries).expect_err("must detect mid-chain tamper");
        match err {
            AuraError::ChainBreak { index, .. } => assert_eq!(index, 5),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn verify_chain_detects_reordered_entries() {
        let e0 = entry(0, &genesis_hash(), "ALLOW");
        let e1 = entry(1, &e0.chain_hash, "DENY");
        let e2 = entry(2, &e1.chain_hash, "REVIEW");
        let err = verify_chain(&[e0, e2, e1]).expect_err("must detect reorder");
        match err {
            AuraError::ChainBreak { index, .. } => assert_eq!(index, 1),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn verify_chain_detects_skipped_entry() {
        let e0 = entry(0, &genesis_hash(), "ALLOW");
        let e1 = entry(1, &e0.chain_hash, "DENY");
        let e2 = entry(2, &e1.chain_hash, "REVIEW");
        let err = verify_chain(&[e0, e2]).expect_err("must detect skip");
        match err {
            AuraError::ChainBreak { index, .. } => assert_eq!(index, 1),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn verify_chain_detects_duplicate_entry() {
        let e0 = entry(0, &genesis_hash(), "ALLOW");
        let err = verify_chain(&[e0.clone(), e0.clone()]).expect_err("must detect duplicate");
        match err {
            AuraError::ChainBreak { index, .. } => assert_eq!(index, 1),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn verify_chain_detects_wrong_genesis() {
        let mut e0 = entry(0, &genesis_hash(), "ALLOW");
        e0.prev_hash = "wrong".repeat(16);
        e0.chain_hash = recompute_for_entry(&e0);
        let err = verify_chain(&[e0]).expect_err("must detect wrong genesis");
        match err {
            AuraError::ChainBreak { index, .. } => assert_eq!(index, 0),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn compute_chain_hash_deterministic() {
        let h1 = compute_chain_hash("prev", "DENY", "finance-v1", "policy_hash", "ctx", "input_hash", "shadow_hash", 42, "2026-01-01T00:00:00Z");
        let h2 = compute_chain_hash("prev", "DENY", "finance-v1", "policy_hash", "ctx", "input_hash", "shadow_hash", 42, "2026-01-01T00:00:00Z");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn compute_chain_hash_different_for_different_inputs() {
        let h1 = compute_chain_hash("prev", "DENY", "finance-v1", "policy", "ctx", "input", "shadow", 42, "2026-01-01T00:00:00Z");
        let h2 = compute_chain_hash("prev", "ALLOW", "finance-v1", "policy", "ctx", "input", "shadow", 42, "2026-01-01T00:00:00Z");
        assert_ne!(h1, h2);
    }

    #[test]
    fn compute_chain_hash_sensitive_to_seq() {
        let h1 = compute_chain_hash("prev", "DENY", "finance-v1", "policy", "ctx", "input", "shadow", 42, "2026-01-01T00:00:00Z");
        let h2 = compute_chain_hash("prev", "DENY", "finance-v1", "policy", "ctx", "input", "shadow", 43, "2026-01-01T00:00:00Z");
        assert_ne!(h1, h2);
    }

    #[test]
    fn compute_chain_hash_sensitive_to_all_fields() {
        let base = ("prev", "DENY", "policy", "phash", "ctx", "ihash", "shash", 42u64, "ts");
        let h_base = compute_chain_hash(base.0, base.1, base.2, base.3, base.4, base.5, base.6, base.7, base.8);
        let field_tests = [
            ("prev", compute_chain_hash("X", base.1, base.2, base.3, base.4, base.5, base.6, base.7, base.8)),
            ("decision", compute_chain_hash(base.0, "X", base.2, base.3, base.4, base.5, base.6, base.7, base.8)),
            ("policy", compute_chain_hash(base.0, base.1, "X", base.3, base.4, base.5, base.6, base.7, base.8)),
            ("phash", compute_chain_hash(base.0, base.1, base.2, "X", base.4, base.5, base.6, base.7, base.8)),
            ("ctx", compute_chain_hash(base.0, base.1, base.2, base.3, "X", base.5, base.6, base.7, base.8)),
            ("ihash", compute_chain_hash(base.0, base.1, base.2, base.3, base.4, "X", base.6, base.7, base.8)),
            ("shash", compute_chain_hash(base.0, base.1, base.2, base.3, base.4, base.5, "X", base.7, base.8)),
            ("seq", compute_chain_hash(base.0, base.1, base.2, base.3, base.4, base.5, base.6, 999, base.8)),
            ("ts", compute_chain_hash(base.0, base.1, base.2, base.3, base.4, base.5, base.6, base.7, "X")),
        ];
        for (field_name, changed_hash) in &field_tests {
            assert_ne!(h_base, *changed_hash, "Field '{}' should affect hash", field_name);
        }
    }

    #[test]
    fn recompute_for_entry_matches_original() {
        let e = entry(5, "prevhash", "DENY");
        let original_hash = e.chain_hash.clone();
        let recomputed = recompute_for_entry(&e);
        assert_eq!(original_hash, recomputed);
    }

    #[test]
    fn chain_hash_is_hex() {
        let h = compute_chain_hash("p", "d", "ps", "ph", "c", "ih", "sh", 0, "ts");
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(h.len(), 64);
    }

    #[test]
    fn production_hash_binds_request_id() {
        let e = entry(0, &genesis_hash(), "ALLOW");
        let mut mutated = e.clone();
        mutated.request_id = Some("different".into());
        assert_ne!(compute_chain_hash_for_entry(&e).unwrap(), compute_chain_hash_for_entry(&mutated).unwrap());
    }

    #[test]
    fn production_hash_binds_schema_audit_id_and_violations() {
        let e = entry(0, &genesis_hash(), "ALLOW");
        let base = compute_chain_hash_for_entry(&e).unwrap();
        let mut schema = e.clone(); schema.schema.push('x');
        let mut audit = e.clone(); audit.audit_id.push('x');
        let mut violation = e.clone(); violation.violations[0].rule = "R-999".into();
        assert_ne!(base, compute_chain_hash_for_entry(&schema).unwrap());
        assert_ne!(base, compute_chain_hash_for_entry(&audit).unwrap());
        assert_ne!(base, compute_chain_hash_for_entry(&violation).unwrap());
    }

    #[test]
    fn production_hash_rejects_invalid_confidence() {
        let mut e = entry(0, &genesis_hash(), "ALLOW");
        e.violations[0].confidence = f32::NAN;
        assert!(compute_chain_hash_for_entry(&e).is_err());
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_compute_chain_hash_is_hex(
            prev in "[a-f0-9]{64}",
            decision in "(ALLOW|DENY|REVIEW)",
            seq in 0u64..1000000
        ) {
            let h = compute_chain_hash(&prev, &decision, "policy", "phash", "ctx", "ihash", "shash", seq, "timestamp");
            prop_assert_eq!(h.len(), 64);
            prop_assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        }

        #[test]
        fn prop_verify_chain_accepts_valid_chains(n in 1usize..20) {
            let mut entries = Vec::new();
            let mut prev = genesis_hash();
            for i in 0..n {
                let e = entry(i as u64, &prev, "ALLOW");
                prev = e.chain_hash.clone();
                entries.push(e);
            }
            let result = verify_chain(&entries);
            prop_assert!(result.is_ok());
        }

        #[test]
        fn prop_recompute_is_idempotent(seq in 0u64..1000) {
            let e = entry(seq, &genesis_hash(), "ALLOW");
            let h1 = recompute_for_entry(&e);
            let h2 = recompute_for_entry(&e);
            prop_assert_eq!(h1, h2);
        }
    }
}
