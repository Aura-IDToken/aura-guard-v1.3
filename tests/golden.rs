#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Golden tests: every shipped policy must produce a known decision for a
//! representative payload. Failures here mean a regression in the engine,
//! the validators, or a policy file.

use aura_guard::engine::evaluate;
use aura_guard::normalizer::shadow_normalize;
use aura_guard::policy::{load_policy, TrustedSigners};
use std::path::PathBuf;

fn policies_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("policies")
}

fn run(policy: &str, context: &str, prompt: &str, response: &str) -> String {
    let signers = TrustedSigners::empty();
    let p = load_policy(policy, &policies_dir(), &signers, false)
        .expect("policy loads under enforce_signatures=false");
    let combined = format!("{context} {prompt} {response}");
    let shadow = shadow_normalize(&combined);
    let (decision, _) = evaluate(&shadow, context, &p.rules);
    decision
}

#[test]
fn finance_valid_credit_card_denies() {
    let d = run(
        "finance-v1",
        "Finance Bot",
        "Card 4111-1111-1111-1111 please",
        "ok",
    );
    assert_eq!(d, "DENY");
}

#[test]
fn finance_invalid_credit_card_allowed() {
    // 16 digits but fails Luhn (last digit flipped).
    let d = run(
        "finance-v1",
        "Finance Bot",
        "Reference 4111-1111-1111-1112 please",
        "ok",
    );
    assert_eq!(d, "ALLOW");
}

#[test]
fn finance_valid_iban_denies() {
    let d = run(
        "finance-v1",
        "Finance Compliance",
        "Send EUR 100 to PL61109010140000071219812874",
        "ok",
    );
    assert_eq!(d, "DENY");
}

#[test]
fn finance_swift_only_for_finance_context() {
    let support = run(
        "finance-v1",
        "Support Bot",
        "Code DEUTDEFF appeared in the docs.",
        "ok",
    );
    assert_eq!(support, "ALLOW");

    let finance = run(
        "finance-v1",
        "Finance Compliance",
        "Code DEUTDEFF for the wire.",
        "ok",
    );
    assert_eq!(finance, "REVIEW");
}

#[test]
fn medtech_valid_pesel_denies() {
    let d = run(
        "medtech-v1",
        "MedTech Clinic Assistant",
        "Patient 44051401359 diagnosis kardiologiczna 25 mg.",
        "ok",
    );
    assert_eq!(d, "DENY");
}

#[test]
fn medtech_random_11_digits_allowed() {
    let d = run(
        "medtech-v1",
        "MedTech Clinic Assistant",
        "Transaction 12345678901 confirmed.",
        "ok",
    );
    // Random 11-digit sequence fails PESEL checksum -> no DENY.
    // It might still pass other rules (diagnosis/medication) so we accept
    // either ALLOW or REVIEW, just not DENY.
    assert_ne!(d, "DENY");
}

#[test]
fn hr_bias_age_denies() {
    let d = run(
        "hr-bias-v1",
        "HR Screening Bot",
        "She is too old for the role.",
        "ack",
    );
    assert_eq!(d, "DENY");
}

#[test]
fn clean_request_allows() {
    let d = run(
        "finance-v1",
        "General Support",
        "How do I reset my password?",
        "Use the link.",
    );
    assert_eq!(d, "ALLOW");
}

#[test]
fn zwsp_bypass_blocked() {
    // Zero-width spaces injected between digits must NOT defeat the credit-card
    // detection — the shadow normalizer strips them before regex evaluation.
    let prompt = "Card 4111\u{200B}-1111\u{200B}-1111\u{200B}-1111";
    let d = run("finance-v1", "Finance Bot", prompt, "ok");
    assert_eq!(d, "DENY");
}

#[test]
fn cyrillic_homoglyph_blocked() {
    // SWIFT pattern in Finance context with Cyrillic homoglyph for the first
    // letter. Confusable folding maps Cyrillic А → ASCII a, the (?i) regex
    // still matches.
    let prompt = "Code \u{0410}EUTDEFF appeared.";
    let d = run("finance-v1", "Finance Compliance", prompt, "ok");
    assert_eq!(d, "REVIEW");
}
