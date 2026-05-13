//! Strongly-typed errors emitted by the Aura-Guard runtime and CLIs.

use thiserror::Error;

/// Crate-wide result alias.
pub type Result<T, E = AuraError> = std::result::Result<T, E>;

/// All recoverable and fatal errors produced by Aura-Guard.
#[derive(Error, Debug)]
pub enum AuraError {
    /// Policy file could not be read from disk.
    #[error("cannot read policy '{path}': {source}")]
    PolicyRead {
        /// Filesystem path of the policy file.
        path: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Policy YAML failed to parse.
    #[error("invalid YAML in policy '{path}': {message}")]
    PolicyParse {
        /// Filesystem path of the policy file.
        path: String,
        /// Human-readable error message.
        message: String,
    },

    /// A regex inside a policy rule failed to compile.
    #[error("bad regex in rule '{rule_id}': {message}")]
    BadRegex {
        /// Rule identifier from the YAML file.
        rule_id: String,
        /// Compilation error message.
        message: String,
    },

    /// Policy signature verification failed.
    #[error("policy signature verification failed: {0}")]
    PolicySignature(String),

    /// Audit log could not be opened or written to.
    ///
    /// Following the v1.3 "halt-on-log-failure" posture, this error is fatal
    /// and the server returns HTTP 503 + halts the process.
    #[error("audit log write failed: {0}")]
    LogWrite(String),

    /// Hash-chain verification detected a broken link.
    #[error("CHAIN BREAK DETECTED at entry #{index}: expected prev_hash={expected}, got {actual}")]
    ChainBreak {
        /// Zero-based index of the entry whose `prev_hash` does not match.
        index: usize,
        /// Expected `prev_hash` (i.e. the previous entry's `chain_hash`).
        expected: String,
        /// `prev_hash` actually stored on the offending entry.
        actual: String,
    },

    /// Replay verification recomputed a different decision.
    #[error(
        "REPLAY MISMATCH at entry #{index}: stored decision={stored}, recomputed={recomputed}"
    )]
    ReplayMismatch {
        /// Zero-based index of the mismatched entry.
        index: usize,
        /// Decision stored in the log.
        stored: String,
        /// Decision recomputed during replay.
        recomputed: String,
    },

    /// Replay verification recomputed a different SHA-256 hash.
    #[error("HASH MISMATCH at entry #{index}: stored hash={stored}, recomputed={recomputed}")]
    HashMismatch {
        /// Zero-based index of the mismatched entry.
        index: usize,
        /// SHA-256 stored in the log.
        stored: String,
        /// SHA-256 recomputed during replay.
        recomputed: String,
    },

    /// Authentication failed (missing or wrong API key).
    #[error("authentication failed")]
    Unauthenticated,

    /// Configuration is invalid or missing a required value.
    #[error("invalid configuration: {0}")]
    Config(String),

    /// Catch-all I/O wrapper.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Catch-all JSON error.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}
