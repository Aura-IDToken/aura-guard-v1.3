//! Hash-chain construction and verification.
//!
//! The production `AuditEntry` hash domain is RFC 8785 JCS over every
//! evidence-bearing field except `chain_hash` itself. The older nine-field
//! pipe-joined helpers remain available for D3 observational tooling only;
//! runtime construction and verification use `*_for_entry` below.

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
///
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
#[must_use]
pub fn recompute_for_entry(entry: &AuditEntry) -> Result<String> {
    compute_chain_hash_for_entry(entry)
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
        let recomputed = recompute_for_entry(entry)?;
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
        AuditEntry {
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
        }
    }

    fn sealed_entry(seq: u64, prev: &str, decision: &str) -> AuditEntry {
        let mut e = entry(seq, prev, decision);
        e.chain_hash = recompute_for_entry(&e).expect("valid entry canonicalizes");
        e
    }

    #[test]
    fn clean_chain_verifies() {
        let e0 = sealed_entry(0, &genesis_hash(), "ALLOW");
        let e1 = sealed_entry(1, &e0.chain_hash, "DENY");
        let e2 = sealed_entry(2, &e1.chain_hash, "REVIEW");
        let head = verify_chain(&[e0, e1, e2]).expect("clean chain verifies");
        assert_eq!(head.len(), 64);
    }

    #[test]
    fn whole_evidence_boundary_detects_mutations() {
        let base = sealed_entry(0, &genesis_hash(), "ALLOW");
        let mut cases = Vec::new();

        let mut e = base.clone(); e.schema = "aura-guard.audit.v2".into(); cases.push(e);
        let mut e = base.clone(); e.audit_id.push('x'); cases.push(e);
        let mut e = base.clone(); e.request_id = Some("req-mutated".into()); cases.push(e);
        let mut e = base.clone(); e.request_id = None; cases.push(e);
        let mut e = base.clone(); e.timestamp.push('x'); cases.push(e);
        let mut e = base.clone(); e.decision = "DENY".into(); cases.push(e);
        let mut e = base.clone(); e.policy_set.push('x'); cases.push(e);
        let mut e = base.clone(); e.policy_hash.push('x'); cases.push(e);
        let mut e = base.clone(); e.context.push('x'); cases.push(e);
        let mut e = base.clone(); e.input_hash.push('x'); cases.push(e);
        let mut e = base.clone(); e.shadow_hash.push('x'); cases.push(e);
        let mut e = base.clone(); e.seq += 1; cases.push(e);
        let mut e = base.clone(); e.violations[0].rule = "R-999".into(); cases.push(e);
        let mut e = base.clone(); e.violations[0].action = "deny".into(); cases.push(e);
        let mut e = base.clone(); e.violations[0].confidence = 0.5; cases.push(e);
        let mut e = base.clone(); e.violations[0].validator = None; cases.push(e);

        for mut mutated in cases {
            assert!(verify_chain(&[mutated.clone()]).is_err());
            mutated.chain_hash = recompute_for_entry(&mutated).expect("mutation is still valid evidence");
            assert_ne!(mutated.chain_hash, base.chain_hash);
        }
    }

    #[test]
    fn separator_injection_cannot_collide() {
        let mut a = sealed_entry(0, &genesis_hash(), "ALLOW");
        let mut b = a.clone();
        a.context = "value1|value2".into();
        b.context = "value1".into();
        b.input_hash = "value2|hash".into();
        let ha = recompute_for_entry(&a).unwrap();
        let hb = recompute_for_entry(&b).unwrap();
        assert_ne!(ha, hb);
    }

    #[test]
    fn violation_order_is_hash_semantic() {
        let mut a = sealed_entry(0, &genesis_hash(), "ALLOW");
        let mut b = a.clone();
        b.violations.insert(
            0,
            Violation {
                rule: "R-002".into(),
                action: "deny".into(),
                confidence: 0.5,
                validator: None,
            },
        );
        a.violations.push(b.violations[0].clone());
        assert_ne!(recompute_for_entry(&a).unwrap(), recompute_for_entry(&b).unwrap());
    }

    #[test]
    fn legacy_observational_helper_remains_deterministic() {
        let h1 = compute_chain_hash("prev", "DENY", "policy", "phash", "ctx", "ihash", "shash", 42, "ts");
        let h2 = compute_chain_hash("prev", "DENY", "policy", "phash", "ctx", "ihash", "shash", 42, "ts");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }
}
