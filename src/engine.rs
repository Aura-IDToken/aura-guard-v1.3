//! Deterministic decision engine.
//!
//! Inputs:
//! * `shadow`  — SHADOW_SPEC v1.0 normalized text (regex evaluation surface).
//! * `context` — original request context (used for conditional rules).
//! * `rules`   — compiled policy rules in declaration order.
//!
//! Output: `(decision, violations)` where `decision ∈ {DENY, REVIEW, ALLOW}`.

use crate::models::Violation;
use crate::policy::{run_validator, CompiledRule};

/// Evaluate a single audit request against a policy.
pub fn evaluate(shadow: &str, context: &str, rules: &[CompiledRule]) -> (String, Vec<Violation>) {
    let mut has_deny = false;
    let mut has_review = false;
    let mut violations: Vec<Violation> = Vec::new();

    for rule in rules {
        // Conditional gate.
        if let Some(ctx_pat) = &rule.context_pattern {
            if !ctx_pat.is_match(context) {
                continue;
            }
        }

        // Regex match.
        let Some(m) = rule.pattern.find(shadow) else {
            continue;
        };

        // Optional semantic validation (Luhn / PESEL / IBAN).
        let (validator_passed, validator_label) = match rule.validator {
            Some(v) => {
                let (ok, label) = run_validator(v, m.as_str());
                (ok, Some(label.to_string()))
            }
            None => (true, None),
        };
        if !validator_passed {
            continue;
        }

        match rule.action.to_ascii_lowercase().as_str() {
            "deny" => has_deny = true,
            "review" => has_review = true,
            _ => {} // 'allow' or unknown — no decision contribution.
        }

        violations.push(Violation {
            rule: rule.id.clone(),
            action: rule.action.clone(),
            confidence: rule.score,
            validator: validator_label,
        });
    }

    let decision = if has_deny {
        "DENY"
    } else if has_review {
        "REVIEW"
    } else {
        "ALLOW"
    }
    .to_string();

    (decision, violations)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use regex::Regex;

    fn rule(id: &str, pattern: &str, action: &str, score: f32) -> CompiledRule {
        CompiledRule {
            id: id.into(),
            pattern: Regex::new(&format!("(?i){pattern}")).expect("valid regex"),
            action: action.into(),
            score,
            validator: None,
            context_pattern: None,
        }
    }

    #[test]
    fn deny_wins_over_review() {
        let rules = vec![
            rule("a", "foo", "deny", 1.0),
            rule("b", "bar", "review", 0.5),
        ];
        let (d, v) = evaluate("foo bar", "ctx", &rules);
        assert_eq!(d, "DENY");
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn allow_when_nothing_matches() {
        let rules = vec![rule("a", "foo", "deny", 1.0)];
        let (d, v) = evaluate("nothing here", "ctx", &rules);
        assert_eq!(d, "ALLOW");
        assert!(v.is_empty());
    }

    #[test]
    fn conditional_rule_skipped_for_wrong_context() {
        let mut r = rule("a", "swift", "review", 0.5);
        r.context_pattern = Some(Regex::new("(?i)Finance").expect("valid context regex"));
        let rules = vec![r];
        let (d, v) = evaluate("swift code", "Support Bot", &rules);
        assert_eq!(d, "ALLOW");
        assert!(v.is_empty());
    }

    // Additional tests for evaluate function
    #[test]
    fn multiple_deny_rules_all_recorded() {
        let rules = vec![
            rule("deny1", "foo", "deny", 1.0),
            rule("deny2", "bar", "deny", 0.9),
        ];
        let (d, v) = evaluate("foo bar", "ctx", &rules);
        assert_eq!(d, "DENY");
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].action, "deny");
        assert_eq!(v[1].action, "deny");
    }

    #[test]
    fn multiple_review_rules_all_recorded() {
        let rules = vec![
            rule("review1", "alpha", "review", 0.8),
            rule("review2", "beta", "review", 0.7),
        ];
        let (d, v) = evaluate("alpha beta", "ctx", &rules);
        assert_eq!(d, "REVIEW");
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn mixed_actions_deny_wins() {
        let rules = vec![
            rule("allow1", "aaa", "allow", 0.1),
            rule("review1", "bbb", "review", 0.5),
            rule("deny1", "ccc", "deny", 0.9),
            rule("review2", "ddd", "review", 0.6),
        ];
        let (d, v) = evaluate("aaa bbb ccc ddd", "ctx", &rules);
        assert_eq!(d, "DENY");
        assert_eq!(v.len(), 4);
    }

    #[test]
    fn review_wins_over_allow() {
        let rules = vec![
            rule("allow1", "aaa", "allow", 0.1),
            rule("review1", "bbb", "review", 0.5),
            rule("allow2", "ccc", "allow", 0.2),
        ];
        let (d, v) = evaluate("aaa bbb ccc", "ctx", &rules);
        assert_eq!(d, "REVIEW");
        assert_eq!(v.len(), 3);
    }

    #[test]
    fn only_allow_rules() {
        let rules = vec![
            rule("allow1", "aaa", "allow", 0.1),
            rule("allow2", "bbb", "allow", 0.2),
        ];
        let (d, v) = evaluate("aaa bbb", "ctx", &rules);
        assert_eq!(d, "ALLOW");
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn unknown_action_treated_as_allow() {
        let rules = vec![rule("unknown", "foo", "unknown_action", 0.5)];
        let (d, v) = evaluate("foo", "ctx", &rules);
        assert_eq!(d, "ALLOW");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].action, "unknown_action");
    }

    #[test]
    fn case_insensitive_action_matching() {
        let rules = vec![
            rule("upper_deny", "aaa", "DENY", 1.0),
            rule("mixed_review", "bbb", "ReView", 0.5),
        ];
        let (d, v) = evaluate("aaa bbb", "ctx", &rules);
        assert_eq!(d, "DENY");
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn empty_shadow_no_matches() {
        let rules = vec![rule("a", "foo", "deny", 1.0)];
        let (d, v) = evaluate("", "ctx", &rules);
        assert_eq!(d, "ALLOW");
        assert!(v.is_empty());
    }

    #[test]
    fn empty_rules_always_allow() {
        let rules = vec![];
        let (d, v) = evaluate("anything here", "ctx", &rules);
        assert_eq!(d, "ALLOW");
        assert!(v.is_empty());
    }

    #[test]
    fn regex_partial_match_succeeds() {
        let rules = vec![rule("partial", "bar", "deny", 1.0)];
        let (d, v) = evaluate("foo bar baz", "ctx", &rules);
        assert_eq!(d, "DENY");
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn regex_case_insensitive_flag() {
        let rules = vec![rule("case", "TEST", "deny", 1.0)];
        let (d, v) = evaluate("test", "ctx", &rules);
        assert_eq!(d, "DENY");
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn multiple_context_patterns() {
        let mut r1 = rule("ctx1", "swift", "review", 0.5);
        r1.context_pattern = Some(Regex::new("(?i)Finance").unwrap());

        let mut r2 = rule("ctx2", "swift", "deny", 0.9);
        r2.context_pattern = Some(Regex::new("(?i)Banking").unwrap());

        let rules = vec![r1, r2];

        // Finance context: only r1 should match
        let (d, v) = evaluate("swift code", "Finance Bot", &rules);
        assert_eq!(d, "REVIEW");
        assert_eq!(v.len(), 1);

        // Banking context: only r2 should match
        let (d, v) = evaluate("swift code", "Banking System", &rules);
        assert_eq!(d, "DENY");
        assert_eq!(v.len(), 1);

        // Support context: neither should match
        let (d, v) = evaluate("swift code", "Support Team", &rules);
        assert_eq!(d, "ALLOW");
        assert!(v.is_empty());
    }

    #[test]
    fn violation_preserves_rule_metadata() {
        let rules = vec![rule("test-rule-id", "pattern", "deny", 0.85)];
        let (_, v) = evaluate("pattern match", "ctx", &rules);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, "test-rule-id");
        assert_eq!(v[0].action, "deny");
        assert_eq!(v[0].confidence, 0.85);
        assert_eq!(v[0].validator, None);
    }

    #[test]
    fn no_match_returns_empty_violations() {
        let rules = vec![
            rule("a", "notfound", "deny", 1.0),
            rule("b", "missing", "review", 0.5),
        ];
        let (d, v) = evaluate("completely different text", "ctx", &rules);
        assert_eq!(d, "ALLOW");
        assert!(v.is_empty());
    }

    #[test]
    fn whitespace_only_shadow_no_matches() {
        let rules = vec![rule("a", "foo", "deny", 1.0)];
        let (d, v) = evaluate("   ", "ctx", &rules);
        assert_eq!(d, "ALLOW");
        assert!(v.is_empty());
    }

    #[test]
    fn very_long_shadow_matches() {
        let long_shadow = "a".repeat(10000) + " pattern " + &"b".repeat(10000);
        let rules = vec![rule("long", "pattern", "deny", 1.0)];
        let (d, v) = evaluate(&long_shadow, "ctx", &rules);
        assert_eq!(d, "DENY");
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn unicode_shadow_matches() {
        let rules = vec![rule("unicode", "тест", "deny", 1.0)];
        let (d, v) = evaluate("This is тест string", "ctx", &rules);
        assert_eq!(d, "DENY");
        assert_eq!(v.len(), 1);
    }

    // Property-based tests for engine
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_evaluate_never_panics(shadow in ".{0,500}", context in ".{0,100}") {
            let rules = vec![rule("test", "foo", "deny", 1.0)];
            let _ = evaluate(&shadow, &context, &rules);
        }

        #[test]
        fn prop_empty_rules_always_allow(shadow in ".*", context in ".*") {
            let rules = vec![];
            let (decision, violations) = evaluate(&shadow, &context, &rules);
            prop_assert_eq!(decision, "ALLOW".to_string());
            prop_assert!(violations.is_empty());
        }

        #[test]
        fn prop_deny_rule_never_gives_review_without_review_rule(shadow in ".*") {
            let rules = vec![rule("only_deny", ".*", "deny", 1.0)];
            let (decision, _) = evaluate(&shadow, "ctx", &rules);
            // Should be DENY or ALLOW, never REVIEW (no review rules)
            prop_assert_ne!(decision, "REVIEW");
        }

        #[test]
        fn prop_violations_count_never_exceeds_rules(shadow in ".{0,100}") {
            let rules = vec![
                rule("r1", "a", "deny", 1.0),
                rule("r2", "b", "review", 0.5),
                rule("r3", "c", "allow", 0.3),
            ];
            let (_, violations) = evaluate(&shadow, "ctx", &rules);
            prop_assert!(violations.len() <= rules.len());
        }
    }
}
