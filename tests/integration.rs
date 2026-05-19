#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! End-to-end HTTP test via `tower::ServiceExt::oneshot`.
//!
//! Spins up the Axum router in-process (no real TCP socket) and exercises the
//! audit endpoint with API key authentication enabled. The audit log is
//! written into a `tempfile::TempDir` so tests are hermetic.

use aura_guard::api::{build_router, AppState};
use aura_guard::config::Config;
use aura_guard::crypto::genesis_hash;
use aura_guard::log_writer::LogWriter;
use aura_guard::policy::{load_policy, CompiledPolicy, TrustedSigners};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use dashmap::DashMap;
use http_body_util::BodyExt;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::TempDir;
use tower::ServiceExt;

fn manifest_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn build_state() -> (AppState, TempDir) {
    let tmp = TempDir::new().expect("tempdir");
    let cfg = Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        api_key: Some("test-key".to_string()),
        auth_disabled: false,
        policies_dir: manifest_root().join("policies"),
        trusted_signers_file: manifest_root().join("policies/trusted_signers.json"),
        default_policy_set: "finance-v1".to_string(),
        audit_log_path: tmp.path().join("audit.jsonl"),
        max_body_bytes: 64 * 1024,
        request_timeout_ms: 2_000,
        metrics_enabled: true,
        allowed_origins: Vec::new(),
        segments_dir: tmp.path().join("segments"),
        segment_size: 0,
        segment_interval_seconds: 0,
        tsa_url: None,
        tsa_timeout_seconds: 10,
    };

    let signers = Arc::new(TrustedSigners::empty());
    let log =
        LogWriter::open(cfg.audit_log_path.clone(), &genesis_hash()).expect("opens fresh log");

    let policies: DashMap<String, Arc<CompiledPolicy>> = DashMap::new();
    for name in ["finance-v1", "medtech-v1", "hr-bias-v1"] {
        let p = load_policy(name, &cfg.policies_dir, &signers, false)
            .expect("policy loads under enforce_signatures=false");
        policies.insert(name.to_string(), Arc::new(p));
    }

    let state = AppState {
        config: Arc::new(cfg),
        policies: Arc::new(policies),
        log,
        signers,
        enforce_signatures: false,
        sealer: None,
    };
    (state, tmp)
}

async fn post_json(
    app: axum::Router,
    path: &str,
    api_key: Option<&str>,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let mut req = Request::builder()
        .method("POST")
        .uri(path)
        .header("Content-Type", "application/json");
    if let Some(k) = api_key {
        req = req.header("X-API-Key", k);
    }
    let req = req
        .body(Body::from(body.to_string()))
        .expect("request builds");
    let resp = app.oneshot(req).await.expect("router responds");
    let status = resp.status();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("collect")
        .to_bytes();
    let body = serde_json::from_slice::<serde_json::Value>(&bytes)
        .unwrap_or_else(|_| serde_json::Value::String(String::from_utf8_lossy(&bytes).into()));
    (status, body)
}

#[tokio::test]
async fn audit_denies_credit_card() {
    let (state, _tmp) = build_state();
    let app = build_router(state);

    let (status, body) = post_json(
        app,
        "/v1/audit",
        Some("test-key"),
        serde_json::json!({
            "context": "Finance Bot",
            "policy_set": "finance-v1",
            "payload": {
                "prompt": "Card 4111-1111-1111-1111 please.",
                "response": "ack"
            }
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body={body}");
    assert_eq!(body["decision"], "DENY");
    assert_eq!(body["seq"], 0);
    assert_eq!(body["prev_hash"], genesis_hash());
    assert_eq!(body["chain_hash"].as_str().unwrap().len(), 64);
}

#[tokio::test]
async fn audit_rejects_unknown_policy() {
    let (state, _tmp) = build_state();
    let app = build_router(state);

    let (status, _body) = post_json(
        app,
        "/v1/audit",
        Some("test-key"),
        serde_json::json!({
            "context": "x",
            "policy_set": "does-not-exist",
            "payload": { "prompt": "x", "response": "y" }
        }),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn audit_requires_api_key() {
    let (state, _tmp) = build_state();
    let app = build_router(state);

    let (status, _) = post_json(
        app,
        "/v1/audit",
        None,
        serde_json::json!({ "context": "x", "payload": { "prompt": "x", "response": "y" } }),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn audit_rejects_wrong_api_key() {
    let (state, _tmp) = build_state();
    let app = build_router(state);

    let (status, _) = post_json(
        app,
        "/v1/audit",
        Some("wrong-key"),
        serde_json::json!({ "context": "x", "payload": { "prompt": "x", "response": "y" } }),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn chain_grows_monotonically() {
    let (state, _tmp) = build_state();
    let app = build_router(state.clone());

    // First entry.
    let (_, e0) = post_json(
        app.clone(),
        "/v1/audit",
        Some("test-key"),
        serde_json::json!({
            "context": "Finance Bot",
            "payload": { "prompt": "hello", "response": "world" }
        }),
    )
    .await;

    // Second entry.
    let (_, e1) = post_json(
        app,
        "/v1/audit",
        Some("test-key"),
        serde_json::json!({
            "context": "Finance Bot",
            "payload": { "prompt": "test 4111-1111-1111-1111", "response": "ack" }
        }),
    )
    .await;

    assert_eq!(e0["seq"], 0);
    assert_eq!(e1["seq"], 1);
    assert_eq!(e1["prev_hash"], e0["chain_hash"]);
    assert_ne!(e0["chain_hash"], e1["chain_hash"]);
}

#[tokio::test]
async fn health_and_ready_are_public() {
    let (state, _tmp) = build_state();
    let app = build_router(state);

    for path in ["/health", "/ready", "/version"] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(resp.status(), StatusCode::OK, "{path} should be public");
    }
}

#[tokio::test]
async fn cors_is_denied_by_default() {
    // Default config has an empty allow-list, so the runtime must NOT
    // emit Access-Control-Allow-Origin for cross-origin requests.
    let (state, _tmp) = build_state();
    let app = build_router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health")
                .header("Origin", "https://evil.example")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers().get("access-control-allow-origin").is_none(),
        "CORS must default to deny — no allow-origin header expected, \
         got: {:?}",
        resp.headers().get("access-control-allow-origin"),
    );
}

#[tokio::test]
async fn cors_allows_only_listed_origins() {
    let (mut state, _tmp) = build_state();
    let cfg = Config {
        allowed_origins: vec!["https://app.example.com".to_string()],
        ..(*state.config).clone()
    };
    state.config = Arc::new(cfg);
    let app = build_router(state);

    // Allowed origin is echoed back.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health")
                .header("Origin", "https://app.example.com")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(
        resp.headers()
            .get("access-control-allow-origin")
            .map(|v| v.to_str().unwrap().to_string()),
        Some("https://app.example.com".to_string())
    );

    // Untrusted origin gets no allow-origin header — the browser will block.
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health")
                .header("Origin", "https://evil.example")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert!(
        resp.headers().get("access-control-allow-origin").is_none(),
        "untrusted origin must not get an allow-origin header",
    );
}

#[tokio::test]
async fn segments_are_sealed_and_verifiable_end_to_end() {
    // Build router with sealing enabled at size=2 and time=disabled, so two
    // POSTs deterministically close a segment.
    let tmp = TempDir::new().expect("tempdir");
    let segments_dir = tmp.path().join("segments");
    let cfg = Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        api_key: Some("test-key".to_string()),
        auth_disabled: false,
        policies_dir: manifest_root().join("policies"),
        trusted_signers_file: manifest_root().join("policies/trusted_signers.json"),
        default_policy_set: "finance-v1".to_string(),
        audit_log_path: tmp.path().join("audit.jsonl"),
        max_body_bytes: 64 * 1024,
        request_timeout_ms: 2_000,
        metrics_enabled: true,
        allowed_origins: Vec::new(),
        segments_dir: segments_dir.clone(),
        segment_size: 2,
        segment_interval_seconds: 0,
        tsa_url: None,
        tsa_timeout_seconds: 10,
    };

    let signers = Arc::new(TrustedSigners::empty());
    let log =
        LogWriter::open(cfg.audit_log_path.clone(), &genesis_hash()).expect("opens fresh log");

    let policies: DashMap<String, Arc<CompiledPolicy>> = DashMap::new();
    for name in ["finance-v1", "medtech-v1", "hr-bias-v1"] {
        let p = load_policy(name, &cfg.policies_dir, &signers, false).expect("policy loads");
        policies.insert(name.to_string(), Arc::new(p));
    }

    let sealer = aura_guard::sealer::SegmentSealer::new(
        segments_dir.clone(),
        cfg.segment_size,
        std::time::Duration::ZERO,
    )
    .expect("sealer builds");

    let state = AppState {
        config: Arc::new(cfg),
        policies: Arc::new(policies),
        log,
        signers,
        enforce_signatures: false,
        sealer: Some(sealer),
    };
    let app = build_router(state);

    for i in 0..4 {
        let body = serde_json::json!({
            "context": "test",
            "payload": {"prompt": format!("p-{i}"), "response": format!("r-{i}")},
        });
        let (status, _) = post_json(app.clone(), "/v1/audit", Some("test-key"), body).await;
        assert_eq!(status, StatusCode::OK);
    }

    let manifests = aura_guard::segment::load_manifests(&segments_dir).expect("load manifests");
    assert_eq!(
        manifests.len(),
        2,
        "two segments should be sealed by size threshold"
    );
    aura_guard::segment::verify_segment_chain(&manifests).expect("segment chain verifies");

    let log_path = manifests[0].clone();
    let _ = log_path; // dead-line tip: avoid clippy::unused

    let entries = aura_guard::log_writer::read_all_entries(std::path::Path::new(&format!(
        "{}/audit.jsonl",
        tmp.path().display()
    )))
    .expect("read entries");
    assert_eq!(entries.len(), 4);
    for m in &manifests {
        let first = m.first_seq as usize;
        let last = m.last_seq as usize;
        aura_guard::segment::verify_manifest_against_entries(m, &entries[first..=last])
            .expect("manifest matches entries");
    }
}
