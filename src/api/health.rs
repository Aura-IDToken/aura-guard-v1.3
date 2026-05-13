//! Health, readiness, version and Prometheus metrics endpoints.

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde_json::json;

use crate::api::AppState;
use crate::metrics;

/// Liveness — always returns 200 OK while the process is up.
pub async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, Json(json!({ "status": "ok" })))
}

/// Readiness — returns 503 when the audit log is halted.
pub async fn readyz(State(state): State<AppState>) -> impl IntoResponse {
    if state.log.is_halted() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "status": "halted",
                "reason": "audit log fail-closed posture engaged"
            })),
        );
    }
    (
        StatusCode::OK,
        Json(json!({
            "status": "ready",
            "policies_loaded": state.policies.len(),
            "signature_enforcement": state.enforce_signatures,
        })),
    )
}

/// Build / runtime version metadata.
pub async fn version(State(state): State<AppState>) -> impl IntoResponse {
    Json(json!({
        "name": "aura-guard",
        "version": env!("CARGO_PKG_VERSION"),
        "schema": "aura-guard.audit.v1",
        "genesis_hash": crate::crypto::genesis_hash(),
        "signature_enforcement": state.enforce_signatures,
    }))
}

/// Prometheus text exposition.
pub async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    if !state.config.metrics_enabled {
        return (StatusCode::NOT_FOUND, "metrics disabled".to_string()).into_response();
    }
    let body = metrics::render();
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        body,
    )
        .into_response()
}
