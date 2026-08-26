//! Internal canonicalization of evidence-bearing [`AuditEntry`] fields.
//!
//! The public wire model in `models.rs` is intentionally unchanged. This
//! module defines the byte domain used by the production audit-entry hash:
//! RFC 8785 JCS over an explicit evidence object, with `confidence` converted
//! from `f32` to a deterministic fixed-point integer in basis points of 1/10000.

use serde_json::{Map, Value};
use thiserror::Error;

use crate::models::{AuditEntry, Violation};

/// Errors raised while constructing the canonical evidence byte domain.
#[derive(Debug, Error)]
pub enum CanonicalError {
    /// The supplied confidence value is not a finite value in `[0, 1]`.
    #[error("invalid violation confidence {0:?}; expected finite value in [0, 1]")]
    InvalidConfidence(f32),
    /// The JCS serializer rejected the constructed JSON value.
    #[error("RFC 8785 JCS serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}

/// Serialize an `AuditEntry` into the production canonical evidence byte
/// domain using RFC 8785 JSON Canonicalization Scheme (JCS).
///
/// `chain_hash` is deliberately excluded because it is the digest produced
/// from this byte domain. Every other evidence-bearing field is included.
/// Optional fields follow the public model's `skip_serializing_if` semantics:
/// `None` is absent while `Some("")` remains an explicit empty string.
/// Array order for `violations` is preserved exactly.
pub fn canonical_evidence_bytes(entry: &AuditEntry) -> Result<Vec<u8>, CanonicalError> {
    let mut object = Map::new();
    object.insert("audit_id".into(), Value::String(entry.audit_id.clone()));
    object.insert("context".into(), Value::String(entry.context.clone()));
    object.insert("decision".into(), Value::String(entry.decision.clone()));
    object.insert("input_hash".into(), Value::String(entry.input_hash.clone()));
    object.insert("policy_hash".into(), Value::String(entry.policy_hash.clone()));
    object.insert("policy_set".into(), Value::String(entry.policy_set.clone()));
    object.insert("prev_hash".into(), Value::String(entry.prev_hash.clone()));
    if let Some(request_id) = &entry.request_id {
        object.insert("request_id".into(), Value::String(request_id.clone()));
    }
    object.insert("schema".into(), Value::String(entry.schema.clone()));
    object.insert("seq".into(), Value::Number(entry.seq.into()));
    object.insert("shadow_hash".into(), Value::String(entry.shadow_hash.clone()));
    object.insert("timestamp".into(), Value::String(entry.timestamp.clone()));

    let violations = entry
        .violations
        .iter()
        .map(violation_to_value)
        .collect::<Result<Vec<_>, _>>()?;
    object.insert("violations".into(), Value::Array(violations));

    Ok(serde_json_canonicalizer::to_vec(&Value::Object(object))?)
}

fn violation_to_value(violation: &Violation) -> Result<Value, CanonicalError> {
    let mut object = Map::new();
    object.insert("action".into(), Value::String(violation.action.clone()));
    object.insert(
        "confidence".into(),
        Value::Number(confidence_to_fixed_point(violation.confidence)?.into()),
    );
    object.insert("rule".into(), Value::String(violation.rule.clone()));
    if let Some(validator) = &violation.validator {
        object.insert("validator".into(), Value::String(validator.clone()));
    }
    Ok(Value::Object(object))
}

/// Convert IEEE-754 binary32 to an exact, rounded fixed-point integer.
///
/// The result is `round(value * 10000)` using integer arithmetic over the
/// decoded binary32 mantissa/exponent. This avoids depending on a language's
/// float-to-decimal formatting or on a runtime floating-point multiplication.
fn confidence_to_fixed_point(value: f32) -> Result<u64, CanonicalError> {
    let bits = value.to_bits();
    let sign = bits >> 31;
    let exponent = (bits >> 23) & 0xff;
    let fraction = bits & 0x7f_ffff;

    if sign != 0 || exponent == 0xff || value > 1.0 {
        return Err(CanonicalError::InvalidConfidence(value));
    }

    let (mantissa, power) = if exponent == 0 {
        // Subnormal: value = fraction * 2^-149.
        (fraction as u64, -149i32)
    } else {
        // Normal: value = (2^23 + fraction) * 2^(exponent-127-23).
        (
            ((1u32 << 23) | fraction) as u64,
            exponent as i32 - 127 - 23,
        )
    };

    let numerator = mantissa * 10_000;
    let scaled = if power >= 0 {
        numerator << (power as u32)
    } else {
        let shift = (-power) as u32;
        if shift >= 64 {
            0
        } else {
            let divisor = 1u64 << shift;
            let quotient = numerator / divisor;
            let remainder = numerator % divisor;
            if remainder.saturating_mul(2) >= divisor {
                quotient + 1
            } else {
                quotient
            }
        }
    };

    Ok(scaled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::AuditEntry;

    fn entry(context: &str) -> AuditEntry {
        AuditEntry {
            schema: "aura-guard.audit.v1".into(),
            seq: 7,
            audit_id: "audit-7".into(),
            request_id: Some("req-1".into()),
            timestamp: "2026-05-12T00:00:00+00:00".into(),
            decision: "REVIEW".into(),
            policy_set: "finance-v1".into(),
            policy_hash: "deadbeef".into(),
            context: context.into(),
            input_hash: "input".into(),
            shadow_hash: "shadow".into(),
            violations: vec![Violation {
                rule: "R-001".into(),
                action: "review".into(),
                confidence: 0.95,
                validator: Some("pesel_checksum_ok".into()),
            }],
            prev_hash: "prev".into(),
            chain_hash: "ignored".into(),
        }
    }

    #[test]
    fn canonical_bytes_are_stable_and_exclude_chain_hash() {
        let a = canonical_evidence_bytes(&entry("ctx")).unwrap();
        let mut b_entry = entry("ctx");
        b_entry.chain_hash = "different".into();
        let b = canonical_evidence_bytes(&b_entry).unwrap();
        assert_eq!(a, b);
        assert_eq!(
            String::from_utf8(a).unwrap(),
            "{\"audit_id\":\"audit-7\",\"context\":\"ctx\",\"decision\":\"REVIEW\",\"input_hash\":\"input\",\"policy_hash\":\"deadbeef\",\"policy_set\":\"finance-v1\",\"prev_hash\":\"prev\",\"request_id\":\"req-1\",\"schema\":\"aura-guard.audit.v1\",\"seq\":7,\"shadow_hash\":\"shadow\",\"timestamp\":\"2026-05-12T00:00:00+00:00\",\"violations\":[{\"action\":\"review\",\"confidence\":9500,\"rule\":\"R-001\",\"validator\":\"pesel_checksum_ok\"}]}"
        );
    }

    #[test]
    fn option_none_is_absent_but_empty_string_is_present() {
        let mut none = entry("ctx");
        none.request_id = None;
        let mut empty = entry("ctx");
        empty.request_id = Some(String::new());
        assert_ne!(canonical_evidence_bytes(&none).unwrap(), canonical_evidence_bytes(&empty).unwrap());

        none.violations[0].validator = None;
        empty.violations[0].validator = Some(String::new());
        assert_ne!(canonical_evidence_bytes(&none).unwrap(), canonical_evidence_bytes(&empty).unwrap());
    }

    #[test]
    fn separator_and_json_injection_are_distinct() {
        let a = canonical_evidence_bytes(&entry("value1|value2")).unwrap();
        let b = canonical_evidence_bytes(&entry("value1")).unwrap();
        assert_ne!(a, b);
        for context in ["\"", "\\", "\n", "\r", "\t", "{", "}", "😀"] {
            let bytes = canonical_evidence_bytes(&entry(context)).unwrap();
            assert!(!bytes.contains(&b'\n'));
        }
    }

    #[test]
    fn confidence_fixed_point_is_deterministic() {
        assert_eq!(confidence_to_fixed_point(0.0).unwrap(), 0);
        assert_eq!(confidence_to_fixed_point(0.5).unwrap(), 5000);
        assert_eq!(confidence_to_fixed_point(0.95).unwrap(), 9500);
        assert_eq!(confidence_to_fixed_point(1.0).unwrap(), 10000);
    }

    #[test]
    fn invalid_confidence_is_rejected() {
        for value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY, -0.1, 1.1] {
            assert!(matches!(
                confidence_to_fixed_point(value),
                Err(CanonicalError::InvalidConfidence(_))
            ));
        }
    }

    #[test]
    fn violation_order_is_semantic() {
        let mut a = entry("ctx");
        let mut b = entry("ctx");
        a.violations.push(Violation {
            rule: "R-002".into(),
            action: "deny".into(),
            confidence: 0.5,
            validator: None,
        });
        b.violations.insert(
            0,
            Violation {
                rule: "R-002".into(),
                action: "deny".into(),
                confidence: 0.5,
                validator: None,
            },
        );
        assert_ne!(canonical_evidence_bytes(&a).unwrap(), canonical_evidence_bytes(&b).unwrap());
    }
}
