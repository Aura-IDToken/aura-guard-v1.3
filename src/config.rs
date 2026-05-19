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

    /// Allowed CORS origins.
    ///
    /// Empty by default — no `Access-Control-Allow-Origin` header is emitted
    /// and browsers will block cross-origin requests under the same-origin
    /// policy. Set `AURA_ALLOWED_ORIGINS="https://app.example.com,https://ops.example.com"`
    /// to opt into a strict allow-list. Wildcards are not supported on purpose.
    #[serde(default, deserialize_with = "deserialize_origins")]
    pub allowed_origins: Vec<String>,

    /// Directory holding segment manifests (`NNNNNN.manifest.json`) and any
    /// accompanying RFC 3161 Time-Stamp Responses (`NNNNNN.tsr`).
    #[serde(default = "default_segments_dir")]
    pub segments_dir: PathBuf,

    /// Maximum number of audit entries per Merkle segment.
    ///
    /// Set to `0` to disable size-based sealing (time-based sealing still
    /// applies). Default: 1000.
    #[serde(default = "default_segment_size")]
    pub segment_size: u64,

    /// Maximum time, in seconds, a segment may stay open before being sealed.
    ///
    /// Set to `0` to disable time-based sealing (size-based sealing still
    /// applies). Default: 60 seconds.
    #[serde(default = "default_segment_interval_seconds")]
    pub segment_interval_seconds: u64,

    /// Optional RFC 3161 Time-Stamp Authority URL. When set, every sealed
    /// segment manifest will be timestamped via HTTP POST; failures are
    /// logged and counted but **do not halt** the service.
    #[serde(default)]
    pub tsa_url: Option<String>,

    /// HTTP timeout for TSA requests, in seconds. Default: 10.
    #[serde(default = "default_tsa_timeout_seconds")]
    pub tsa_timeout_seconds: u64,
}

/// Accept either a JSON array (`["a", "b"]`) or a comma-separated string
/// (`"a,b"`) for `AURA_ALLOWED_ORIGINS`. The env-var path always provides a
/// string, so the second branch is the common one in production.
fn deserialize_origins<'de, D>(de: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }
    Ok(match OneOrMany::deserialize(de)? {
        OneOrMany::One(s) => s
            .split(',')
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect(),
        OneOrMany::Many(v) => v.into_iter().filter(|p| !p.is_empty()).collect(),
    })
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
fn default_segments_dir() -> PathBuf {
    PathBuf::from("logs/segments")
}
fn default_segment_size() -> u64 {
    1_000
}
fn default_segment_interval_seconds() -> u64 {
    60
}
fn default_tsa_timeout_seconds() -> u64 {
    10
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
            allowed_origins: Vec::new(),
            segments_dir: default_segments_dir(),
            segment_size: default_segment_size(),
            segment_interval_seconds: default_segment_interval_seconds(),
            tsa_url: None,
            tsa_timeout_seconds: default_tsa_timeout_seconds(),
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
