//! API key authentication middleware.
//!
//! Accepts the key on **either** of the following headers:
//!
//! * `X-API-Key: <key>`
//! * `Authorization: Bearer <key>`
//!
//! When `auth_disabled = true` in [`crate::config::Config`], the middleware
//! becomes a no-op (development convenience only).

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;

use crate::api::AppState;

/// Constant-time string comparison to avoid timing leaks on the API key.
fn ct_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Axum middleware that enforces the `X-API-Key` / `Bearer` header.
pub async fn require_api_key(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, (StatusCode, &'static str)> {
    if state.config.auth_disabled {
        return Ok(next.run(req).await);
    }

    let Some(expected) = state.config.api_key.as_deref() else {
        tracing::error!("API key not configured but auth is enabled");
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "API key not configured"));
    };

    let headers = req.headers();
    let supplied = headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .or_else(|| {
            headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
        });

    match supplied {
        Some(key) if ct_eq(key, expected) => Ok(next.run(req).await),
        _ => {
            let request_id = headers
                .get("x-request-id")
                .and_then(|v| v.to_str().ok())
                .filter(|s| !s.is_empty() && s.len() <= crate::api::audit::MAX_REQUEST_ID_LEN)
                .unwrap_or("-");
            tracing::warn!(
                request_id = %request_id,
                "authentication failed: missing or invalid API key",
            );
            metrics::counter!("aura_guard_auth_failures_total").increment(1);
            Err((StatusCode::UNAUTHORIZED, "missing or invalid API key"))
        }
    }
}
