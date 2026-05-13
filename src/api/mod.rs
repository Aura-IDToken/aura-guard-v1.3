//! HTTP API surface (`/v1/audit`, `/health`, `/ready`, `/metrics`, `/version`).

pub mod audit;
pub mod health;

use axum::extract::DefaultBodyLimit;
use axum::http::StatusCode;
use axum::middleware;
use axum::routing::{get, post};
use axum::Router;
use dashmap::DashMap;
use std::sync::Arc;
use std::time::Duration;
use tower_http::cors::{Any, CorsLayer};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::auth::require_api_key;
use crate::config::Config;
use crate::log_writer::LogWriter;
use crate::policy::{CompiledPolicy, TrustedSigners};

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
}

/// Build the public Axum router with all middleware layers attached.
pub fn build_router(state: AppState) -> Router {
    let cfg = state.config.clone();
    let timeout = Duration::from_millis(cfg.request_timeout_ms);
    let body_limit = cfg.max_body_bytes;

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

    Router::new()
        .merge(authed)
        .merge(public)
        .with_state(state)
        .layer(DefaultBodyLimit::max(body_limit))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            timeout,
        ))
        .layer(TraceLayer::new_for_http())
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
}
