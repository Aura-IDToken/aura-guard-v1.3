use aura_guard::chain::{compute_chain_hash_for_entry, recompute_for_entry, verify_chain};
use aura_guard::crypto::genesis_hash;
use aura_guard::models::{AuditEntry, Violation};

fn base_entry() -> AuditEntry {
    AuditEntry {
        schema: "aura-guard.audit.v1".into(),
        seq: 0,
        audit_id: "audit-00000000".into(),
        request_id: Some("req-1".into()),
        timestamp: "2026-05-12T00:00:00+00:00".into(),
        decision: "REVIEW".into(),
        policy_set: "finance-v1".into(),
        policy_hash: "deadbeef".into(),
        context: "Finance Bot".into(),
        input_hash: "input-hash".into(),
        shadow_hash: "shadow-hash".into(),
        violations: vec![Violation {
            rule: "R-001".into(),
            action: "review".into(),
            confidence: 0.95,
            validator: Some("validator".into()),
        }],
        prev_hash: genesis_hash(),
        chain_hash: String::new(),
    }
}

fn sealed(mut entry: AuditEntry) -> AuditEntry {
    entry.chain_hash = compute_chain_hash_for_entry(&entry).expect("fixture must canonicalize");
    entry
}

#[test]
fn every_evidence_field_is_integrity_bound() {
    let clean = sealed(base_entry());

    let mut mutations: Vec<(&str, Box<dyn Fn(&mut AuditEntry)>)> = vec![
        ("schema", Box::new(|e| e.schema.push_str("-tampered"))),
        ("audit_id", Box::new(|e| e.audit_id.push('x'))),
        ("request_id", Box::new(|e| e.request_id = Some("req-2".into()))),
        ("timestamp", Box::new(|e| e.timestamp.push('x'))),
        ("decision", Box::new(|e| e.decision = "ALLOW".into())),
        ("policy_set", Box::new(|e| e.policy_set.push('x'))),
        ("policy_hash", Box::new(|e| e.policy_hash.push('x'))),
        ("context", Box::new(|e| e.context.push('x'))),
        ("input_hash", Box::new(|e| e.input_hash.push('x'))),
        ("shadow_hash", Box::new(|e| e.shadow_hash.push('x'))),
        ("seq", Box::new(|e| e.seq += 1)),
        ("prev_hash", Box::new(|e| e.prev_hash = "0".repeat(64))),
        ("violation.rule", Box::new(|e| e.violations[0].rule = "R-999".into())),
        ("violation.action", Box::new(|e| e.violations[0].action = "deny".into())),
        ("violation.confidence", Box::new(|e| e.violations[0].confidence = 0.5)),
        ("violation.validator", Box::new(|e| e.violations[0].validator = None)),
    ];

    for (name, mutate) in mutations.drain(..) {
        let mut candidate = clean.clone();
        mutate(&mut candidate);
        assert!(
            verify_chain(std::slice::from_ref(&candidate)).is_err(),
            "mutation {name} must invalidate the original chain_hash"
        );
    }
}

#[test]
fn request_id_none_and_empty_are_distinct() {
    let mut none = base_entry();
    none.request_id = None;
    let mut empty = base_entry();
    empty.request_id = Some(String::new());
    assert_ne!(
        compute_chain_hash_for_entry(&none).unwrap(),
        compute_chain_hash_for_entry(&empty).unwrap()
    );
}

#[test]
fn validator_none_and_empty_are_distinct() {
    let mut none = base_entry();
    none.violations[0].validator = None;
    let mut empty = base_entry();
    empty.violations[0].validator = Some(String::new());
    assert_ne!(
        compute_chain_hash_for_entry(&none).unwrap(),
        compute_chain_hash_for_entry(&empty).unwrap()
    );
}

#[test]
fn violation_order_is_semantic() {
    let mut a = base_entry();
    let mut b = base_entry();
    let second = Violation {
        rule: "R-002".into(),
        action: "deny".into(),
        confidence: 0.5,
        validator: None,
    };
    a.violations.push(second.clone());
    b.violations.insert(0, second);
    assert_ne!(recompute_for_entry(&a), recompute_for_entry(&b));
}

#[test]
fn separator_injection_is_not_ambiguous() {
    let mut a = base_entry();
    let mut b = base_entry();
    a.context = "value1|value2".into();
    a.input_hash = "hash".into();
    b.context = "value1".into();
    b.input_hash = "value2|hash".into();
    assert_ne!(
        compute_chain_hash_for_entry(&a).unwrap(),
        compute_chain_hash_for_entry(&b).unwrap()
    );
}

#[test]
fn json_string_escaping_is_stable() {
    for context in ["\"", "\\", "\n", "\r", "\t", "{", "}", "😀"] {
        let mut entry = base_entry();
        entry.context = context.into();
        let first = compute_chain_hash_for_entry(&entry).unwrap();
        let second = compute_chain_hash_for_entry(&entry).unwrap();
        assert_eq!(first, second, "context must canonicalize deterministically");
    }
}

#[test]
fn invalid_confidence_cannot_produce_valid_evidence_hash() {
    for value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY, -0.1, 1.1] {
        let mut entry = base_entry();
        entry.violations[0].confidence = value;
        assert!(compute_chain_hash_for_entry(&entry).is_err());
    }
}

#[test]
fn portable_fixture_matches_rust_canonical_hash() {
    let entry = base_entry();
    let canonical = compute_chain_hash_for_entry(&entry).unwrap();
    let expected = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/auditentry/AE-001.sha256"
    ))
    .trim();
    assert_eq!(canonical, expected);
}
