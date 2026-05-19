//! HTTP API surface (`/v1/audit`, `/health`, `/ready`, `/metrics`, `/version`).

pub mod audit;
pub mod health;

use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderValue, StatusCode};
use axum::middleware;
use axum::routing::{get, post};
use axum::Router;
use dashmap::DashMap;
use std::sync::Arc;
use std::time::Duration;
use tower_http::cors::CorsLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::auth::require_api_key;
use crate::config::Config;
use crate::log_writer::LogWriter;
use crate::policy::{CompiledPolicy, TrustedSigners};
use crate::sealer::SegmentSealer;

/// Canonical list of policy packs that **must** load successfully at boot.
///
/// Changing this list is a protocol-level decision: every entry here becomes
/// part of the bootstrap fail-closed gate (see `main.rs`). Removing a pack
/// silently lets the runtime start without it; adding one forces every
/// deployment to ship the corresponding signed YAML.
pub const EXPECTED_POLICIES: &[&str] = &["finance-v1", "medtech-v1", "hr-bias-v1"];

/// Shared application state injected into every handler.
#[derive(Clone)]
pub struct AppState {
    /// Server configuration (read-only at request time).
    pub config: Arc<Config>,
    /// Compiled policies, keyed by `policy_set` name.
    pub policies: Arc<DashMap<String, Arc<CompiledPolicy>>>,
    /// Append-only audit log writer.
    pub log: LogWriter,
    /// Trusted Ed25519 signer table (used on cache-miss reloads).
    pub signers: Arc<TrustedSigners>,
    /// Whether policy-signature enforcement is active.
    pub enforce_signatures: bool,
    /// Optional segment sealer. `None` only when both size-based and time-
    /// based sealing are disabled in configuration.
    pub sealer: Option<SegmentSealer>,
}

/// Build the public Axum router with all middleware layers attached.
pub fn build_router(state: AppState) -> Router {
    let cfg = state.config.clone();
    let timeout = Duration::from_millis(cfg.request_timeout_ms);
    let body_limit = cfg.max_body_bytes;
    let allowed_origins = cfg.allowed_origins.clone();

    // Authenticated audit endpoint.
    let authed = Router::new()
        .route("/v1/audit", post(audit::handle_audit))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_api_key,
        ));

    // Public endpoints (health/ready/version/metrics).
    let public = Router::new()
        .route("/health", get(health::healthz))
        .route("/ready", get(health::readyz))
        .route("/version", get(health::version))
        .route("/metrics", get(health::metrics));

    let mut router = Router::new()
        .merge(authed)
        .merge(public)
        .with_state(state)
        .layer(DefaultBodyLimit::max(body_limit))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            timeout,
        ))
        .layer(TraceLayer::new_for_http());

    // CORS defaults to deny: no `Access-Control-Allow-Origin` header is
    // emitted unless `AURA_ALLOWED_ORIGINS` is set, in which case only the
    // listed origins are allowed. Wildcards are intentionally unsupported.
    if let Some(layer) = build_cors_layer(&allowed_origins) {
        router = router.layer(layer);
    }
    router
}

fn build_cors_layer(origins: &[String]) -> Option<CorsLayer> {
    if origins.is_empty() {
        return None;
    }
    let parsed: Vec<HeaderValue> = origins
        .iter()
        .filter_map(|o| HeaderValue::from_str(o).ok())
        .collect();
    if parsed.is_empty() {
        return None;
    }
    Some(
        CorsLayer::new()
            .allow_origin(parsed)
            .allow_methods([axum::http::Method::POST, axum::http::Method::GET])
            .allow_headers([
                axum::http::header::CONTENT_TYPE,
                axum::http::header::AUTHORIZATION,
                axum::http::HeaderName::from_static("x-api-key"),
            ]),
    )
}
