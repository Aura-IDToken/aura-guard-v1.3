#![allow(dead_code)]
//! INFRA-002 — generic byte-representation fixture framework.
//!
//! Shared test-support code for storing, replaying and comparing **byte
//! representations**. It is a measuring instrument, not a specification.
//!
//! # Governance boundary
//!
//! DQ-006 (canonical serialization) is **unresolved**. Nothing in this module
//! establishes, defines, approves or implies a canonical serialization
//! contract. The module deliberately provides no default encoding, no default
//! field order and no default separator: a fixture states what was *observed*
//! or what a synthetic comparison input *happens to use*, and nothing more.
//!
//! # Epistemic status is mandatory
//!
//! Every fixture carries a [`FixtureStatus`]. The three statuses are kept
//! distinct precisely so that an observation is never silently promoted into a
//! proposal, and a proposal is never silently promoted into a rule:
//!
//! * [`FixtureStatus::AsIsObserved`] — bytes read out of the current
//!   implementation.
//! * [`FixtureStatus::Proposed`] — synthetic bytes constructed for comparison.
//!   A synthetic fixture is **never** a proposed protocol serialization.
//! * [`FixtureStatus::Normative`] — representable so the model is complete.
//!   **No fixture in this repository carries it**, because no byte
//!   representation has normative standing.
//!
//! # Semantic identity versus byte representation
//!
//! One semantic object may have many byte representations. The framework keys
//! fixtures by `(construction_id, representation_id)` so that "same semantic
//! object" and "same bytes" cannot be confused. None of the representations of
//! an object is authoritative over the others.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Epistemic status of a fixture. Serialised verbatim into the fixture file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixtureStatus {
    /// Bytes observed in the current implementation.
    AsIsObserved,
    /// Synthetic bytes built for comparison. Not a proposed serialization.
    Proposed,
    /// Reserved. Unused in this repository — no bytes have normative standing.
    Normative,
}

impl FixtureStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AsIsObserved => "AS_IS_OBSERVED",
            Self::Proposed => "PROPOSED",
            Self::Normative => "NORMATIVE",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "AS_IS_OBSERVED" => Self::AsIsObserved,
            "PROPOSED" => Self::Proposed,
            "NORMATIVE" => Self::Normative,
            other => panic!("unrecognised fixture status {other:?}"),
        }
    }
}

/// A property that the source may or may not establish.
///
/// `Unknown` serialises as the literal `"UNKNOWN"`. Properties are never
/// inferred: if the source does not state one, it stays `Unknown`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Property {
    Known(String),
    Unknown,
}

impl Property {
    pub fn known(v: impl Into<String>) -> Self {
        Self::Known(v.into())
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Known(v) => v,
            Self::Unknown => "UNKNOWN",
        }
    }

    fn parse(s: &str) -> Self {
        if s == "UNKNOWN" {
            Self::Unknown
        } else {
            Self::Known(s.to_string())
        }
    }
}

/// One byte representation of one semantic object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByteFixture {
    pub fixture_id: String,
    pub status: FixtureStatus,
    /// Semantic identity. Shared by every representation of the same object.
    pub construction_id: String,
    /// Distinguishes representations of that same semantic object.
    pub representation_id: String,
    pub input_bytes_hex: String,
    pub input_length: usize,
    pub sha256: String,
    pub encoding: Property,
    pub field_order: Property,
    pub separator: Property,
    pub source: String,
    pub notes: String,
}

/// Builder arguments for [`ByteFixture::new`], kept as a struct so callers
/// cannot transpose the many string parameters.
pub struct FixtureSpec<'a> {
    pub fixture_id: &'a str,
    pub status: FixtureStatus,
    pub construction_id: &'a str,
    pub representation_id: &'a str,
    pub encoding: Property,
    pub field_order: Property,
    pub separator: Property,
    pub source: &'a str,
    pub notes: &'a str,
}

impl ByteFixture {
    /// Build a fixture from raw bytes. The digest is computed here, so a
    /// fixture cannot record a digest that disagrees with its own bytes.
    pub fn new(spec: FixtureSpec<'_>, bytes: &[u8]) -> Self {
        Self {
            fixture_id: spec.fixture_id.to_string(),
            status: spec.status,
            construction_id: spec.construction_id.to_string(),
            representation_id: spec.representation_id.to_string(),
            input_bytes_hex: hex::encode(bytes),
            input_length: bytes.len(),
            sha256: hex::encode(Sha256::digest(bytes)),
            encoding: spec.encoding,
            field_order: spec.field_order,
            separator: spec.separator,
            source: spec.source.to_string(),
            notes: spec.notes.to_string(),
        }
    }

    /// Raw bytes decoded from the hex field, which is authoritative.
    pub fn bytes(&self) -> Vec<u8> {
        hex::decode(&self.input_bytes_hex).expect("fixture hex decodes")
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "fixture_id": self.fixture_id,
            "status": self.status.as_str(),
            "construction_id": self.construction_id,
            "representation_id": self.representation_id,
            "input_bytes_hex": self.input_bytes_hex,
            "input_length": self.input_length,
            "sha256": self.sha256,
            "encoding": self.encoding.as_str(),
            "field_order": self.field_order.as_str(),
            "separator": self.separator.as_str(),
            "source": self.source,
            "notes": self.notes,
            "governance": "DQ-006 unresolved. This fixture does not establish canonical serialization.",
        })
    }

    pub fn from_json(v: &serde_json::Value) -> Self {
        let s = |k: &str| -> String {
            v[k].as_str()
                .unwrap_or_else(|| panic!("fixture field {k} missing or not a string"))
                .to_string()
        };
        Self {
            fixture_id: s("fixture_id"),
            status: FixtureStatus::parse(&s("status")),
            construction_id: s("construction_id"),
            representation_id: s("representation_id"),
            input_bytes_hex: s("input_bytes_hex"),
            input_length: usize::try_from(
                v["input_length"]
                    .as_u64()
                    .expect("input_length is a number"),
            )
            .expect("input_length fits usize"),
            sha256: s("sha256"),
            encoding: Property::parse(&s("encoding")),
            field_order: Property::parse(&s("field_order")),
            separator: Property::parse(&s("separator")),
            source: s("source"),
            notes: s("notes"),
        }
    }
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

/// Recording is opt-in, matching the INFRA-001 convention
/// (`HASH_DOMAINS_RECORD`), so a normal `cargo test` never rewrites fixtures.
pub fn recording() -> bool {
    std::env::var("BYTE_FIXTURES_RECORD").is_ok()
}

pub fn fixtures_dir(subdir: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(subdir)
}

/// Write when recording, then always read back and return the stored fixture.
pub fn persist_and_load(dir: &Path, observed: &ByteFixture) -> ByteFixture {
    let path = dir.join(format!("{}.json", observed.fixture_id));
    if recording() {
        std::fs::create_dir_all(dir).expect("create fixtures dir");
        let body = serde_json::to_string_pretty(&observed.to_json()).expect("serialise fixture");
        std::fs::write(&path, format!("{body}\n")).expect("write fixture");
    }
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "fixture {} missing ({e}). Regenerate with BYTE_FIXTURES_RECORD=1",
            path.display()
        )
    });
    let v: serde_json::Value = serde_json::from_str(&raw).expect("parse fixture");
    ByteFixture::from_json(&v)
}

// ---------------------------------------------------------------------------
// Replay
// ---------------------------------------------------------------------------

/// Outcome of replaying a fixture's stored bytes through SHA-256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayOutcome {
    pub fixture_id: String,
    pub expected_sha256: String,
    pub actual_sha256: String,
    pub matched: bool,
}

/// Replay: stored hex -> raw bytes -> SHA-256 -> compare to stored digest.
pub fn replay(fixture: &ByteFixture) -> ReplayOutcome {
    let actual = hex::encode(Sha256::digest(fixture.bytes()));
    ReplayOutcome {
        fixture_id: fixture.fixture_id.clone(),
        expected_sha256: fixture.sha256.clone(),
        matched: actual == fixture.sha256,
        actual_sha256: actual,
    }
}

/// Replay and fail with fixture id, expected digest and actual digest.
pub fn assert_replay(fixture: &ByteFixture) {
    let o = replay(fixture);
    assert!(
        o.matched,
        "replay failed for fixture {}: expected {}, actual {}",
        o.fixture_id, o.expected_sha256, o.actual_sha256
    );
}

/// Persist/load, verify the stored fixture still describes the observation,
/// then replay it.
pub fn assert_stored_and_replayed(dir: &Path, observed: &ByteFixture) -> ByteFixture {
    let stored = persist_and_load(dir, observed);
    assert_eq!(
        stored.input_bytes_hex, observed.input_bytes_hex,
        "fixture {} bytes changed since it was recorded",
        observed.fixture_id
    );
    assert_eq!(
        stored.input_length, observed.input_length,
        "fixture {} length changed since it was recorded",
        observed.fixture_id
    );
    assert_eq!(
        stored.status, observed.status,
        "fixture {} epistemic status changed since it was recorded",
        observed.fixture_id
    );
    assert_replay(&stored);
    assert_eq!(
        stored.sha256, observed.sha256,
        "fixture {} digest differs from the current observation",
        observed.fixture_id
    );
    stored
}

// ---------------------------------------------------------------------------
// Byte comparison
// ---------------------------------------------------------------------------

/// Result of comparing two byte sequences.
///
/// The comparison is over **raw bytes**. Decoded-string views are never the
/// authoritative comparison, because two byte sequences can decode to the same
/// text under different encodings and still hash differently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByteComparison {
    pub equal: bool,
    pub len_a: usize,
    pub len_b: usize,
    /// Offset of the first differing byte. When one input is a strict prefix
    /// of the other, this is the length of the shorter input.
    pub first_diff_offset: Option<usize>,
    pub byte_a_at_diff: Option<u8>,
    pub byte_b_at_diff: Option<u8>,
    pub sha256_a: String,
    pub sha256_b: String,
}

/// Compare two byte sequences deterministically.
pub fn compare_bytes(a: &[u8], b: &[u8]) -> ByteComparison {
    let first_diff = a
        .iter()
        .zip(b.iter())
        .position(|(x, y)| x != y)
        .or(if a.len() == b.len() {
            None
        } else {
            // One is a prefix of the other: the difference begins where the
            // shorter input ends.
            Some(a.len().min(b.len()))
        });

    ByteComparison {
        equal: a == b,
        len_a: a.len(),
        len_b: b.len(),
        first_diff_offset: first_diff,
        byte_a_at_diff: first_diff.and_then(|i| a.get(i).copied()),
        byte_b_at_diff: first_diff.and_then(|i| b.get(i).copied()),
        sha256_a: hex::encode(Sha256::digest(a)),
        sha256_b: hex::encode(Sha256::digest(b)),
    }
}

/// Compare two fixtures by their raw bytes.
pub fn compare_fixtures(a: &ByteFixture, b: &ByteFixture) -> ByteComparison {
    compare_bytes(&a.bytes(), &b.bytes())
}

impl ByteComparison {
    /// Human-readable summary for assertion messages.
    pub fn describe(&self) -> String {
        if self.equal {
            format!("equal ({} bytes), sha256 {}", self.len_a, self.sha256_a)
        } else {
            match (
                self.first_diff_offset,
                self.byte_a_at_diff,
                self.byte_b_at_diff,
            ) {
                (Some(i), Some(x), Some(y)) => format!(
                    "differ at offset {i}: 0x{x:02x} vs 0x{y:02x} (len {} vs {}); sha256 {} vs {}",
                    self.len_a, self.len_b, self.sha256_a, self.sha256_b
                ),
                (Some(i), _, _) => format!(
                    "differ from offset {i} (one is a prefix of the other; len {} vs {}); sha256 {} vs {}",
                    self.len_a, self.len_b, self.sha256_a, self.sha256_b
                ),
                _ => format!(
                    "differ (len {} vs {}); sha256 {} vs {}",
                    self.len_a, self.len_b, self.sha256_a, self.sha256_b
                ),
            }
        }
    }
}
