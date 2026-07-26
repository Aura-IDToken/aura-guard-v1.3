//! Runtime configuration loaded from environment variables and optional files.
//!
//! All keys are prefixed `AURA_` so they can be set via systemd `EnvironmentFile=`
//! or Kubernetes `envFrom`. Defaults are safe for local development but force
//! authentication in production-like environments.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

/// Minimum number of bytes required for a production API key
/// (`AURA_AUTH_DISABLED=false`).
///
/// Length is measured with [`str::len`], which returns **byte count**.  For
/// the recommended ASCII/hex format (`openssl rand -hex 32` → 64 hex chars)
/// byte count equals character count.
///
/// Keys shorter than this limit are trivially brute-forceable and are rejected
/// by [`Config::validate`].  Generate a key with:
/// ```text
/// openssl rand -hex 32   # 64 hex chars = 256 bits of entropy
/// ```
pub const MIN_API_KEY_LEN: usize = 32;

/// Well-known placeholder values that are never accepted as production API keys.
///
/// Checked case-insensitively by [`Config::validate`].  All values are intentionally
/// kept < [`MIN_API_KEY_LEN`] characters so the length guard fires first; the
/// denylist provides an additional, human-readable error for the most common
/// mistakes.
const WEAK_API_KEYS: &[&str] = &[
    "changeme",
    "secret",
    "password",
    "test",
    "default",
    "admin",
    "key",
    "apikey",
    "api-key",
    "aura",
    "insecure",
    "placeholder",
];

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

        cfg.validate()?;
        Ok(cfg)
    }

    /// Validate security constraints on the loaded configuration.
    ///
    /// Called automatically by [`Config::from_env`]. Exposed as a public method
    /// so that manually-constructed [`Config`] values can be validated in tests
    /// and operator tooling without going through environment variable loading.
    ///
    /// # Errors
    ///
    /// Returns [`crate::AuraError::Config`] when any of the following are true:
    ///
    /// * `auth_disabled = true` and the bind address is **not** a loopback
    ///   address — disabling authentication while listening on a network-reachable
    ///   interface is a production-unsafe configuration.
    /// * `auth_disabled = false` (the default) and `api_key` is `None` — the
    ///   server cannot enforce authentication without a key.
    /// * `auth_disabled = false` and the API key is shorter than
    ///   [`MIN_API_KEY_LEN`] bytes.
    /// * `auth_disabled = false` and the API key matches a well-known
    ///   placeholder value (case-insensitive).
    pub fn validate(&self) -> Result<(), crate::AuraError> {
        // Guard 1: auth_disabled must not be set when listening on a non-loopback interface.
        if self.auth_disabled && !self.bind.ip().is_loopback() {
            return Err(crate::AuraError::Config(format!(
                "AURA_AUTH_DISABLED=true is not permitted when binding to a \
                 non-loopback address ({}). \
                 Remove AURA_AUTH_DISABLED or restrict AURA_BIND to 127.0.0.1.",
                self.bind
            )));
        }

        // Guard 2: API key checks only apply when authentication is enabled.
        if !self.auth_disabled {
            if self.api_key.is_none() {
                return Err(crate::AuraError::Config(
                    "AURA_API_KEY is required (or set AURA_AUTH_DISABLED=true for local dev)"
                        .into(),
                ));
            }
            if let Some(key) = &self.api_key {
                if key.len() < MIN_API_KEY_LEN {
                    return Err(crate::AuraError::Config(format!(
                        "AURA_API_KEY must be at least {MIN_API_KEY_LEN} characters \
                         long (got {}). \
                         Generate a strong key with: openssl rand -hex 32",
                        key.len()
                    )));
                }
                if WEAK_API_KEYS.iter().any(|&w| key.eq_ignore_ascii_case(w)) {
                    return Err(crate::AuraError::Config(
                        "AURA_API_KEY is a well-known placeholder value. \
                         Generate a strong random key with: openssl rand -hex 32"
                            .into(),
                    ));
                }
            }
        }

        Ok(())
    }
}
