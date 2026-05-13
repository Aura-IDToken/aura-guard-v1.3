//! Policy loader with Ed25519 signature verification (fail-closed).
//!
//! Each policy is a YAML file accompanied by:
//! * `<name>.yaml.sig` — hex-encoded Ed25519 signature over the policy bytes.
//! * `<name>.yaml.signer` — signer ID matching an entry in `trusted_signers.json`.
//!
//! The signer file is optional in dev mode (`AURA_AUTH_DISABLED=true` skips
//! signature enforcement). In production the policy fails to load if either
//! file is missing or the signature does not verify.

use ed25519_dalek::VerifyingKey;
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

use crate::crypto::{parse_pubkey_hex, sha256_bytes_hex, verify_signature};
use crate::{AuraError, Result};

/// YAML root document (mirrors the on-disk policy schema).
#[derive(Debug, Deserialize)]
pub struct PolicyConfig {
    /// Policy pack name (must match the filename stem).
    pub name: String,
    /// Policy version string.
    pub version: String,
    /// List of evaluation rules.
    pub rules: Vec<YamlRule>,
}

/// Single rule entry as stored in YAML (pre-compilation).
#[derive(Debug, Deserialize)]
pub struct YamlRule {
    /// Unique rule identifier.
    pub id: String,
    /// Regex pattern evaluated against the SHADOW-normalized input.
    pub pattern: String,
    /// Action contributed by this rule (`deny`, `review`, or `allow`).
    pub action: String,
    /// Confidence score reported in the audit entry (0.0–1.0).
    pub score: f32,
    /// Optional semantic validator applied after the regex match.
    ///
    /// Supported values: `"luhn"`, `"pesel"`, `"iban"`. Unknown validators
    /// abort policy loading.
    #[serde(default)]
    pub validator: Option<String>,
    /// Optional regex pattern that must match `context` for this rule to fire.
    #[serde(default)]
    pub conditions: Option<YamlConditions>,
}

/// Conditional gate (`conditions.context`) from the YAML rule.
#[derive(Debug, Deserialize, Clone)]
pub struct YamlConditions {
    /// Regex matched against the request `context` string (non-normalized).
    pub context: Option<String>,
}

/// Loaded + compiled policy (held in the runtime cache).
#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    /// Original pack name.
    pub name: String,
    /// Policy version string.
    pub version: String,
    /// Hex-encoded SHA-256 of the raw policy file (provenance pin in the audit log).
    pub policy_hash: String,
    /// Compiled rules (regex pre-compiled, validators resolved).
    pub rules: Vec<CompiledRule>,
}

/// Validator hook that may run after a regex match.
#[derive(Debug, Clone, Copy)]
pub enum Validator {
    /// Luhn modulus-10 check (credit cards / IMEI).
    Luhn,
    /// Polish PESEL checksum + month/day sanity.
    Pesel,
    /// IBAN mod-97 check.
    Iban,
}

/// A rule after YAML deserialization + regex compilation.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    /// Rule identifier.
    pub id: String,
    /// Case-insensitive regex compiled with `(?i)`.
    pub pattern: Regex,
    /// Action (`deny`, `review`, `allow`).
    pub action: String,
    /// Reported confidence score.
    pub score: f32,
    /// Optional semantic validator.
    pub validator: Option<Validator>,
    /// Optional context gate regex (also case-insensitive).
    pub context_pattern: Option<Regex>,
}

/// In-memory cache of trusted Ed25519 signer keys.
#[derive(Debug, Default, Clone)]
pub struct TrustedSigners {
    keys: HashMap<String, VerifyingKey>,
}

impl TrustedSigners {
    /// Load `trusted_signers.json` from disk.
    ///
    /// The file maps `signer_id` strings to hex-encoded 32-byte public keys.
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path).map_err(|e| AuraError::PolicyRead {
            path: path.display().to_string(),
            source: e,
        })?;
        let raw_map: HashMap<String, String> =
            serde_json::from_str(&raw).map_err(|e| AuraError::Config(e.to_string()))?;

        let mut keys = HashMap::new();
        for (signer, hex_pk) in raw_map {
            // Keys starting with `_` are reserved for inline JSON comments / metadata.
            if signer.starts_with('_') {
                continue;
            }
            let pk = parse_pubkey_hex(&hex_pk).map_err(AuraError::PolicySignature)?;
            keys.insert(signer, pk);
        }
        Ok(Self { keys })
    }

    /// Construct an empty trusted-signers cache (dev/test mode only).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    /// Resolve a signer ID to its verifier public key.
    #[must_use]
    pub fn get(&self, signer_id: &str) -> Option<&VerifyingKey> {
        self.keys.get(signer_id)
    }

    /// Number of configured signers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the cache contains zero signers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// Resolve `validator: "..."` from YAML to a typed enum.
fn parse_validator(raw: Option<&str>) -> Result<Option<Validator>> {
    match raw {
        None => Ok(None),
        Some("luhn") => Ok(Some(Validator::Luhn)),
        Some("pesel") => Ok(Some(Validator::Pesel)),
        Some("iban") => Ok(Some(Validator::Iban)),
        Some(other) => Err(AuraError::BadRegex {
            rule_id: "?".into(),
            message: format!("unknown validator '{other}' (allowed: luhn, pesel, iban)"),
        }),
    }
}

/// Load a policy by name. Verifies the Ed25519 signature (fail-closed)
/// unless `enforce_signatures` is false.
pub fn load_policy(
    policy_set: &str,
    policies_dir: &Path,
    signers: &TrustedSigners,
    enforce_signatures: bool,
) -> Result<CompiledPolicy> {
    let yaml_path = policies_dir.join(format!("{policy_set}.yaml"));
    let sig_path = policies_dir.join(format!("{policy_set}.yaml.sig"));
    let signer_path = policies_dir.join(format!("{policy_set}.yaml.signer"));

    let policy_bytes = std::fs::read(&yaml_path).map_err(|e| AuraError::PolicyRead {
        path: yaml_path.display().to_string(),
        source: e,
    })?;
    let policy_hash = sha256_bytes_hex(&policy_bytes);

    // Fail-closed signature verification.
    if enforce_signatures {
        let signer_id = std::fs::read_to_string(&signer_path)
            .map_err(|e| {
                AuraError::PolicySignature(format!(
                    "missing signer file '{}': {e}",
                    signer_path.display()
                ))
            })?
            .trim()
            .to_string();
        let pubkey = signers
            .get(&signer_id)
            .ok_or_else(|| AuraError::PolicySignature(format!("unknown signer '{signer_id}'")))?;
        let sig_hex = std::fs::read_to_string(&sig_path).map_err(|e| {
            AuraError::PolicySignature(format!(
                "missing signature file '{}': {e}",
                sig_path.display()
            ))
        })?;
        verify_signature(pubkey, &policy_bytes, sig_hex.trim())
            .map_err(AuraError::PolicySignature)?;
    }

    let raw = std::str::from_utf8(&policy_bytes).map_err(|e| AuraError::PolicyParse {
        path: yaml_path.display().to_string(),
        message: format!("policy is not valid UTF-8: {e}"),
    })?;
    let config: PolicyConfig = serde_yaml::from_str(raw).map_err(|e| AuraError::PolicyParse {
        path: yaml_path.display().to_string(),
        message: e.to_string(),
    })?;

    if config.name != policy_set {
        return Err(AuraError::PolicyParse {
            path: yaml_path.display().to_string(),
            message: format!(
                "policy 'name' is '{}' but filename suggests '{}'",
                config.name, policy_set
            ),
        });
    }

    let rules = config
        .rules
        .into_iter()
        .map(compile_rule)
        .collect::<Result<Vec<_>>>()?;

    Ok(CompiledPolicy {
        name: config.name,
        version: config.version,
        policy_hash,
        rules,
    })
}

fn compile_rule(r: YamlRule) -> Result<CompiledRule> {
    // Always compile case-insensitive so policies remain "human-readable"
    // (e.g. `PL[0-9]{26}`) yet still match shadow-normalized lowercase input.
    let pattern = Regex::new(&format!("(?i){}", r.pattern)).map_err(|e| AuraError::BadRegex {
        rule_id: r.id.clone(),
        message: e.to_string(),
    })?;

    let context_pattern = r
        .conditions
        .as_ref()
        .and_then(|c| c.context.as_ref())
        .map(|pat| {
            Regex::new(&format!("(?i){pat}")).map_err(|e| AuraError::BadRegex {
                rule_id: r.id.clone(),
                message: format!("context regex: {e}"),
            })
        })
        .transpose()?;

    let validator = parse_validator(r.validator.as_deref()).map_err(|e| {
        // Attach the rule_id for clearer diagnostics.
        if let AuraError::BadRegex { message, .. } = e {
            AuraError::BadRegex {
                rule_id: r.id.clone(),
                message,
            }
        } else {
            e
        }
    })?;

    Ok(CompiledRule {
        id: r.id,
        pattern,
        action: r.action,
        score: r.score,
        validator,
        context_pattern,
    })
}

/// Apply a semantic validator to a regex match. Returns `(passed, label)`.
#[must_use]
pub fn run_validator(validator: Validator, matched: &str) -> (bool, &'static str) {
    match validator {
        Validator::Luhn => (crate::validators::luhn_check(matched), "luhn"),
        Validator::Pesel => (crate::validators::pesel_check(matched), "pesel"),
        Validator::Iban => (crate::validators::iban_check(matched), "iban"),
    }
}
