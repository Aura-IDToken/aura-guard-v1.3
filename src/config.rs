//! Runtime configuration loaded from environment variables and optional files.
//!
//! All keys are prefixed `AURA_` so they can be set via systemd `EnvironmentFile=`
//! or Kubernetes `envFrom`. Defaults are safe for local development but force
//! authentication in production-like environments.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

/// Top-level runtime configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    /// Address the HTTP server will bind to.
    #[serde(default = "default_bind")]
    pub bind: SocketAddr,

    /// API key required on the `X-API-Key` (or `Authorization: Bearer ...`) header.
    ///
    /// If `auth_disabled` is `false` (the default) and this is `None`, the server
    /// refuses to start.
    pub api_key: Option<String>,

    /// Disable API key enforcement entirely.
    ///
    /// Intended only for local development and the integration test-suite.
    /// In production set `AURA_AUTH_DISABLED=false` (the default).
    #[serde(default)]
    pub auth_disabled: bool,

    /// Directory containing `*.yaml` policy files and their `.sig` signatures.
    #[serde(default = "default_policies_dir")]
    pub policies_dir: PathBuf,

    /// Trusted Ed25519 verifier public keys, one per signer ID.
    ///
    /// File format: JSON `{ "signer_id": "<hex-encoded 32-byte pubkey>" }`.
    /// If the file is missing the server refuses to start.
    #[serde(default = "default_trusted_signers")]
    pub trusted_signers_file: PathBuf,

    /// Default policy used when a request omits `policy_set`.
    #[serde(default = "default_policy_set")]
    pub default_policy_set: String,

    /// Path to the append-only JSONL audit log.
    #[serde(default = "default_audit_log")]
    pub audit_log_path: PathBuf,

    /// Maximum HTTP request body size in bytes.
    #[serde(default = "default_body_limit")]
    pub max_body_bytes: usize,

    /// HTTP request timeout in milliseconds.
    #[serde(default = "default_timeout_ms")]
    pub request_timeout_ms: u64,

    /// Enable the `/metrics` Prometheus endpoint.
    #[serde(default = "default_true")]
    pub metrics_enabled: bool,
}

fn default_bind() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8080))
}
fn default_policies_dir() -> PathBuf {
    PathBuf::from("policies")
}
fn default_trusted_signers() -> PathBuf {
    PathBuf::from("policies/trusted_signers.json")
}
fn default_policy_set() -> String {
    "finance-v1".to_string()
}
fn default_audit_log() -> PathBuf {
    PathBuf::from("logs/audit.jsonl")
}
fn default_body_limit() -> usize {
    64 * 1024
}
fn default_timeout_ms() -> u64 {
    5_000
}
fn default_true() -> bool {
    true
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            api_key: None,
            auth_disabled: false,
            policies_dir: default_policies_dir(),
            trusted_signers_file: default_trusted_signers(),
            default_policy_set: default_policy_set(),
            audit_log_path: default_audit_log(),
            max_body_bytes: default_body_limit(),
            request_timeout_ms: default_timeout_ms(),
            metrics_enabled: true,
        }
    }
}

impl Config {
    /// Load configuration from `AURA_*` environment variables, falling back to defaults.
    pub fn from_env() -> Result<Self, crate::AuraError> {
        use figment::providers::{Env, Serialized};
        use figment::Figment;

        let cfg: Config = Figment::from(Serialized::defaults(Config::default()))
            .merge(Env::prefixed("AURA_"))
            .extract()
            .map_err(|e| crate::AuraError::Config(e.to_string()))?;

        if !cfg.auth_disabled && cfg.api_key.is_none() {
            return Err(crate::AuraError::Config(
                "AURA_API_KEY is required (or set AURA_AUTH_DISABLED=true for local dev)".into(),
            ));
        }

        Ok(cfg)
    }
}
