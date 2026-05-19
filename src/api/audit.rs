//! `/v1/audit` handler — the core decision endpoint.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use std::sync::Arc;
use uuid::Uuid;

use crate::api::AppState;
use crate::chain::compute_chain_hash;
use crate::crypto::sha256_hex;
use crate::engine::evaluate;
use crate::models::{AuditEntry, AuditRequest};
use crate::normalizer::shadow_normalize;
use crate::policy::CompiledPolicy;

/// HTTP handler for `POST /v1/audit`.
///
/// On success returns the canonical [`AuditEntry`] (same shape as the on-disk
/// log line). On policy / log failures returns `400` or `503` respectively.
pub async fn handle_audit(
    State(state): State<AppState>,
    Json(req): Json<AuditRequest>,
) -> Result<Json<AuditEntry>, (StatusCode, String)> {
    if state.log.is_halted() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "audit log halted (fail-closed posture)".into(),
        ));
    }

    let policy_set = req
        .policy_set
        .clone()
        .unwrap_or_else(|| state.config.default_policy_set.clone());

    // Resolve policy from the pre-warmed cache only — no lazy loads.
    let policy = resolve_policy(&state, &policy_set).map_err(|e| {
        tracing::warn!(error = %e, policy_set = %policy_set, "unknown policy_set");
        (StatusCode::BAD_REQUEST, e)
    })?;

    // Build canonical input + shadow.
    let original = format!(
        "{} {} {}",
        req.context, req.payload.prompt, req.payload.response
    );
    let shadow = shadow_normalize(&original);
    let input_hash = sha256_hex(&original);
    let shadow_hash = sha256_hex(&shadow);

    // Evaluate.
    let (decision, violations) = evaluate(&shadow, &req.context, &policy.rules);

    // Chain construction.
    let seq = state.log.next_seq();
    let timestamp = Utc::now().to_rfc3339();
    let prev_hash = state.log.current_head();
    let chain_hash = compute_chain_hash(
        &prev_hash,
        &decision,
        &policy.name,
        &policy.policy_hash,
        &req.context,
        &input_hash,
        &shadow_hash,
        seq,
        &timestamp,
    );

    let entry = AuditEntry {
        schema: "aura-guard.audit.v1".into(),
        seq,
        audit_id: Uuid::new_v4().to_string(),
        timestamp,
        decision: decision.clone(),
        policy_set: policy.name.clone(),
        policy_hash: policy.policy_hash.clone(),
        context: req.context.clone(),
        input_hash,
        shadow_hash,
        violations,
        prev_hash,
        chain_hash,
    };

    // Fail-closed: if the log refuses to write, return 503.
    state.log.append(&entry).map_err(|e| {
        tracing::error!(error = %e, "audit log write failed — fail-closed");
        (StatusCode::SERVICE_UNAVAILABLE, e.to_string())
    })?;

    // Notify the segment sealer (fail-open: a sealer error is logged but
    // does not poison the audit response — the entry itself is already
    // durably committed and the chain remains verifiable).
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

    // Metrics.
    metrics::counter!(
        "aura_guard_decisions_total",
        "decision" => decision.clone(),
        "policy_set" => policy.name.clone(),
    )
    .increment(1);

    Ok(Json(entry))
}

/// Resolve a policy by name. **Cache-only** by design: every policy that
/// the runtime is allowed to evaluate against must have been pre-loaded and
/// signature-verified at boot (see `main.rs` bootstrap fail-closed gate).
/// Refusing to lazy-load eliminates the temporal integrity gap in which a
/// fresh policy could be added to disk and evaluated against without ever
/// passing through the boot-time signer gate.
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
