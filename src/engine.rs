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
}
