//! Request / response data transfer objects (DTOs) shared by the HTTP API
//! and the audit log file format.

use serde::{Deserialize, Serialize};

/// Inbound `/v1/audit` request body.
#[derive(Debug, Clone, Deserialize)]
pub struct AuditRequest {
    /// Free-form context string (e.g. "Finance Bot", "MedTech Assistant").
    /// Used both in the evidence hash and to gate conditional rules.
    pub context: String,

    /// Optional policy pack to evaluate against. When omitted the server uses
    /// the `default_policy_set` from configuration.
    pub policy_set: Option<String>,

    /// The actual AI interaction being audited.
    pub payload: Payload,
}

/// Prompt / response pair being audited.
#[derive(Debug, Clone, Deserialize)]
pub struct Payload {
    /// Prompt sent to the LLM by the user / upstream system.
    pub prompt: String,
    /// Response returned by the LLM.
    pub response: String,
}

/// A single rule match recorded against an audit decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Violation {
    /// Rule identifier from the policy YAML.
    pub rule: String,
    /// Action declared by the rule (`deny`, `review`, `allow`).
    pub action: String,
    /// Confidence score (0.0–1.0) reported for compliance triage.
    pub confidence: f32,
    /// Optional semantic validator outcome (e.g. `"pesel_checksum_ok"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validator: Option<String>,
}

/// Outbound `/v1/audit` response body and the canonical audit log entry.
///
/// The on-disk JSONL log uses the exact same shape, with the only addition of
/// `prev_hash` and `chain_hash` (both already present here). This guarantees
/// 1:1 replayability between the response and the log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Stable schema version of this entry.
    pub schema: String,

    /// Monotonic sequence number assigned by the server (0-based).
    pub seq: u64,

    /// Unique per-request UUIDv4.
    pub audit_id: String,

    /// RFC 3339 timestamp (UTC) when the decision was produced.
    pub timestamp: String,

    /// Final decision: `DENY`, `REVIEW`, or `ALLOW`.
    pub decision: String,

    /// Policy pack that was evaluated.
    pub policy_set: String,

    /// Hex-encoded SHA-256 of the loaded policy file (provenance pin).
    pub policy_hash: String,

    /// Echo of the request context (verbatim).
    pub context: String,

    /// SHA-256 of the original input (`context + prompt + response`).
    pub input_hash: String,

    /// SHA-256 of the SHADOW_SPEC-normalized input (regex evaluation surface).
    pub shadow_hash: String,

    /// Rule matches that contributed to the decision.
    pub violations: Vec<Violation>,

    /// `chain_hash` of the previous entry (or the genesis hash for entry #0).
    pub prev_hash: String,

    /// `SHA-256(prev_hash || decision || policy_set || input_hash || shadow_hash || seq || timestamp)`.
    pub chain_hash: String,
}
