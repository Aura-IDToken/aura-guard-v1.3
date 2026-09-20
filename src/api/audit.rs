//! `/v1/audit` handler — the core decision endpoint.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use chrono::Utc;
use std::sync::Arc;
use std::time::Instant;
use uuid::Uuid;

use crate::api::AppState;
use crate::chain::compute_chain_hash_for_entry;
use crate::crypto::sha256_hex;
use crate::engine::evaluate;
use crate::models::{AuditEntry, AuditRequest};
use crate::normalizer::shadow_normalize;
use crate::policy::CompiledPolicy;

/// Maximum byte length accepted for an inbound `X-Request-ID` value.
pub(crate) const MAX_REQUEST_ID_LEN: usize = 128;

/// Extract a caller-supplied correlation id from `X-Request-ID`.
fn extract_request_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty() && s.len() <= MAX_REQUEST_ID_LEN)
        .map(|s| s.to_string())
}

/// HTTP handler for `POST /v1/audit`.
pub async fn handle_audit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<AuditRequest>,
) -> Result<Json<AuditEntry>, (StatusCode, String)> {
    let start = Instant::now();

    let request_id = extract_request_id(&headers);
    let audit_id = Uuid::new_v4().to_string();

    tracing::Span::current().record("audit_id", audit_id.as_str());
    if let Some(rid) = &request_id {
        tracing::Span::current().record("request_id", rid.as_str());
    }

    if state.log.is_halted() {
        metrics::counter!(
            "aura_guard_requests_total",
            "status" => "503",
            "decision" => "none",
            "policy_set" => "none",
        )
        .increment(1);
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "audit log halted (fail-closed posture)".into(),
        ));
    }

    let policy_set = req
        .policy_set
        .clone()
        .unwrap_or_else(|| state.config.default_policy_set.clone());

    let policy = resolve_policy(&state, &policy_set).map_err(|e| {
        tracing::warn!(
            error = %e,
            policy_set = %policy_set,
            audit_id = %audit_id,
            request_id = ?request_id,
            "unknown policy_set",
        );
        metrics::counter!(
            "aura_guard_requests_total",
            "status" => "400",
            "decision" => "none",
            "policy_set" => "unknown",
        )
        .increment(1);
        (StatusCode::BAD_REQUEST, e)
    })?;

    let original = format!(
        "{} {} {}",
        req.context, req.payload.prompt, req.payload.response
    );
    let shadow = shadow_normalize(&original);
    let input_hash = sha256_hex(&original);
    let shadow_hash = sha256_hex(&shadow);

    let (decision, violations) = evaluate(&shadow, &req.context, &policy.rules);

    // Construct the complete evidence object first. The production hash is
    // then derived from this object, excluding only its output `chain_hash`.
    let seq = state.log.next_seq();
    let timestamp = Utc::now().to_rfc3339();
    let prev_hash = state.log.current_head();
    let mut entry = AuditEntry {
        schema: "aura-guard.audit.v1".into(),
        seq,
        audit_id,
        request_id,
        timestamp,
        decision: decision.clone(),
        policy_set: policy.name.clone(),
        policy_hash: policy.policy_hash.clone(),
        context: req.context.clone(),
        input_hash,
        shadow_hash,
        violations: violations.clone(),
        prev_hash,
        chain_hash: String::new(),
    };

    entry.chain_hash = compute_chain_hash_for_entry(&entry).map_err(|e| {
        tracing::error!(
            error = %e,
            audit_id = %entry.audit_id,
            request_id = ?entry.request_id,
            seq = entry.seq,
            "canonical evidence serialization failed — fail-closed",
        );
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("cannot canonicalize audit evidence: {e}"),
        )
    })?;

    state.log.append(&entry).map_err(|e| {
        tracing::error!(
            error = %e,
            audit_id = %entry.audit_id,
            request_id = ?entry.request_id,
            seq = entry.seq,
            "audit log write failed — fail-closed",
        );
        metrics::counter!(
            "aura_guard_requests_total",
            "status" => "503",
            "decision" => decision.clone(),
            "policy_set" => policy.name.clone(),
        )
        .increment(1);
        (StatusCode::SERVICE_UNAVAILABLE, e.to_string())
    })?;

    if let Some(sealer) = &state.sealer {
        match sealer.observe(&entry) {
            Ok(crate::sealer::SealOutcome::Sealed {
                segment_id,
                entry_count,
                tsa_work,
            }) => {
                tracing::info!(segment_id, entry_count, "segment sealed (size threshold)");
                if let Some(work) = tsa_work {
                    crate::sealer::maybe_spawn_tsa_submission(&state.config, work);
                }
            }
            Ok(_) => {}
            Err(e) => {
                tracing::error!(error = %e, "segment sealer error");
                metrics::counter!("aura_segments_seal_errors_total").increment(1);
            }
        }
    }

    let elapsed_secs = start.elapsed().as_secs_f64();

    metrics::counter!(
        "aura_guard_decisions_total",
        "decision" => decision.clone(),
        "policy_set" => policy.name.clone(),
    )
    .increment(1);

    metrics::counter!(
        "aura_guard_requests_total",
        "status" => "200",
        "decision" => decision.clone(),
        "policy_set" => policy.name.clone(),
    )
    .increment(1);

    metrics::histogram!(
        "aura_guard_request_duration_seconds",
        "policy_set" => policy.name.clone(),
    )
    .record(elapsed_secs);

    for v in &entry.violations {
        metrics::counter!(
            "aura_guard_policy_violations_total",
            "rule_id" => v.rule.clone(),
            "action" => v.action.clone(),
            "policy_set" => policy.name.clone(),
        )
        .increment(1);
    }

    Ok(Json(entry))
}

/// Resolve a policy by name. Cache-only by design.
fn resolve_policy(state: &AppState, policy_set: &str) -> Result<Arc<CompiledPolicy>, String> {
    state
        .policies
        .get(policy_set)
        .map(|p| p.clone())
        .ok_or_else(|| {
            format!(
                "unknown policy_set {policy_set:?}: not pre-loaded at boot. \
                 Add the signed pack and restart the service."
            )
        })
}
