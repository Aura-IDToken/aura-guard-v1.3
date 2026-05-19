//! Segment manifests — Merkle-rooted, chain-linked checkpoints over the
//! append-only audit log.
//!
//! Every `AURA_SEGMENT_SIZE` entries (or every `AURA_SEGMENT_INTERVAL_SECONDS`,
//! whichever fires first) the running server closes a *segment*: it computes
//! the RFC 6962 Merkle root over the `chain_hash` values of the segment's
//! entries, writes a manifest to `logs/segments/NNNNNN.manifest.json`, and
//! advances a separate segment-chain digest (`prev_segment_chain_hash`).
//!
//! ## Why segments
//!
//! * **Coarse-grained tamper evidence.** Segment manifests can be distributed
//!   to external verifiers without exposing the raw audit log.
//! * **Inclusion proofs.** A single audit entry can be proven to have been
//!   present in a sealed segment via a logarithmic-size Merkle proof.
//! * **Anchoring.** An optional [RFC 3161] Time-Stamp Token can be requested
//!   per segment, providing an independent, offline-verifiable proof that the
//!   manifest existed at a specific point in time.
//!
//! ## File layout
//!
//! ```text
//! logs/
//! ├── audit.jsonl
//! └── segments/
//!     ├── 000001.manifest.json
//!     ├── 000001.tsr           (optional RFC 3161 Time-Stamp Response)
//!     ├── 000002.manifest.json
//!     └── ...
//! ```
//!
//! [RFC 3161]: https://www.rfc-editor.org/rfc/rfc3161

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::merkle::{leaf_hash, merkle_root};
use crate::models::AuditEntry;
use crate::{AuraError, Result};

/// On-disk manifest schema identifier. Bump on any format change.
pub const SEGMENT_SCHEMA: &str = "aura-guard.segment.v1";

/// Genesis value seeding the segment-chain digest.
pub fn segment_genesis_hash() -> String {
    let h = Sha256::digest(b"AURA-GUARD-SEGMENT-GENESIS-v1");
    hex::encode(h)
}

/// Sealed snapshot of a contiguous range of audit entries.
///
/// The on-disk file is the JSON serialization of this struct.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SegmentManifest {
    /// Schema discriminator. See [`SEGMENT_SCHEMA`].
    pub schema: String,
    /// Monotonic segment identifier, 1-based.
    pub segment_id: u64,
    /// `seq` of the first audit entry covered.
    pub first_seq: u64,
    /// `seq` of the last audit entry covered (inclusive).
    pub last_seq: u64,
    /// Number of entries covered (`last_seq - first_seq + 1`).
    pub entry_count: u64,
    /// RFC 6962 Merkle root over the segment's entry `chain_hash` values,
    /// hex-encoded.
    pub merkle_root: String,
    /// `merkle_root` of the previous segment, hex-encoded. Empty string for
    /// the first segment.
    pub prev_merkle_root: String,
    /// `segment_chain_hash` of the previous segment, hex-encoded. Genesis
    /// value for the first segment.
    pub prev_segment_chain_hash: String,
    /// `SHA-256(prev_segment_chain_hash || merkle_root || first_seq ||
    /// last_seq || sealed_at)`, hex-encoded. Pins this segment to the chain.
    pub segment_chain_hash: String,
    /// `chain_hash` of the last audit entry in the segment — the audit-log
    /// head at the moment of sealing.
    pub head_chain_hash_at_close: String,
    /// RFC 3339 UTC timestamp of when the segment was sealed.
    pub sealed_at: String,
    /// Filename (relative to the segments directory) of the accompanying
    /// RFC 3161 Time-Stamp Response, if one was obtained.
    pub tst_path: Option<String>,
}

impl SegmentManifest {
    /// Build the canonical input string used to derive `segment_chain_hash`.
    pub fn segment_chain_preimage(
        prev_segment_chain_hash: &str,
        merkle_root: &str,
        first_seq: u64,
        last_seq: u64,
        sealed_at: &str,
    ) -> String {
        [
            prev_segment_chain_hash,
            merkle_root,
            &first_seq.to_string(),
            &last_seq.to_string(),
            sealed_at,
        ]
        .join("|")
    }

    /// Recompute `segment_chain_hash` from the manifest's fields.
    pub fn recompute_segment_chain_hash(&self) -> String {
        let preimage = Self::segment_chain_preimage(
            &self.prev_segment_chain_hash,
            &self.merkle_root,
            self.first_seq,
            self.last_seq,
            &self.sealed_at,
        );
        hex::encode(Sha256::digest(preimage.as_bytes()))
    }

    /// Compute the canonical byte sequence that should be timestamped by an
    /// RFC 3161 TSA. We hash the same preimage that derives
    /// `segment_chain_hash`, so verification only requires the manifest.
    pub fn tsa_message_imprint(&self) -> [u8; 32] {
        let preimage = Self::segment_chain_preimage(
            &self.prev_segment_chain_hash,
            &self.merkle_root,
            self.first_seq,
            self.last_seq,
            &self.sealed_at,
        );
        Sha256::digest(preimage.as_bytes()).into()
    }
}

/// Build the leaf hash for an entry (`leaf_hash(chain_hash_bytes)`).
///
/// `chain_hash` is interpreted as a hex string and decoded to its 32 raw
/// bytes before hashing. This means external verifiers do not need to know
/// the hex encoding — only the canonical SHA-256 digest.
pub fn entry_leaf_hash(entry: &AuditEntry) -> Result<[u8; 32]> {
    let raw = hex::decode(&entry.chain_hash).map_err(|e| {
        AuraError::Config(format!(
            "audit entry seq={} has malformed chain_hash: {e}",
            entry.seq
        ))
    })?;
    Ok(leaf_hash(&raw))
}

/// Compute the Merkle root for a slice of audit entries.
pub fn segment_merkle_root(entries: &[AuditEntry]) -> Result<[u8; 32]> {
    let mut leaves = Vec::with_capacity(entries.len());
    for e in entries {
        leaves.push(entry_leaf_hash(e)?);
    }
    Ok(merkle_root(&leaves))
}

/// Seal a segment over `entries`, given the previous segment's manifest (or
/// `None` for the very first segment in the log).
pub fn build_manifest(
    segment_id: u64,
    entries: &[AuditEntry],
    prev: Option<&SegmentManifest>,
    sealed_at: &str,
) -> Result<SegmentManifest> {
    if entries.is_empty() {
        return Err(AuraError::Config(
            "cannot seal an empty segment".to_string(),
        ));
    }
    let first = &entries[0];
    let last = &entries[entries.len() - 1];
    let root = segment_merkle_root(entries)?;
    let merkle_root_hex = hex::encode(root);

    let (prev_root, prev_chain) = match prev {
        Some(m) => (m.merkle_root.clone(), m.segment_chain_hash.clone()),
        None => (String::new(), segment_genesis_hash()),
    };

    let preimage = SegmentManifest::segment_chain_preimage(
        &prev_chain,
        &merkle_root_hex,
        first.seq,
        last.seq,
        sealed_at,
    );
    let segment_chain_hash = hex::encode(Sha256::digest(preimage.as_bytes()));

    Ok(SegmentManifest {
        schema: SEGMENT_SCHEMA.to_string(),
        segment_id,
        first_seq: first.seq,
        last_seq: last.seq,
        entry_count: entries.len() as u64,
        merkle_root: merkle_root_hex,
        prev_merkle_root: prev_root,
        prev_segment_chain_hash: prev_chain,
        segment_chain_hash,
        head_chain_hash_at_close: last.chain_hash.clone(),
        sealed_at: sealed_at.to_string(),
        tst_path: None,
    })
}

/// Filename for the manifest covering segment `id` (e.g. `000042.manifest.json`).
#[must_use]
pub fn manifest_filename(segment_id: u64) -> String {
    format!("{segment_id:06}.manifest.json")
}

/// Filename for the Time-Stamp Response accompanying segment `id`
/// (e.g. `000042.tsr`).
#[must_use]
pub fn tsr_filename(segment_id: u64) -> String {
    format!("{segment_id:06}.tsr")
}

/// Atomically write the manifest as JSON + fsync.
pub fn write_manifest(dir: &Path, manifest: &SegmentManifest) -> Result<PathBuf> {
    std::fs::create_dir_all(dir).map_err(|e| {
        AuraError::LogWrite(format!(
            "cannot create segments dir '{}': {e}",
            dir.display()
        ))
    })?;
    let path = dir.join(manifest_filename(manifest.segment_id));
    let tmp = path.with_extension("json.tmp");
    let body = serde_json::to_vec_pretty(manifest).map_err(AuraError::Json)?;
    std::fs::write(&tmp, &body).map_err(|e| {
        AuraError::LogWrite(format!(
            "cannot write segment manifest '{}': {e}",
            tmp.display()
        ))
    })?;
    // Best-effort fsync of the data, then atomic rename into place.
    if let Ok(f) = std::fs::File::open(&tmp) {
        let _ = f.sync_all();
    }
    std::fs::rename(&tmp, &path).map_err(|e| {
        AuraError::LogWrite(format!(
            "cannot finalize segment manifest '{}': {e}",
            path.display()
        ))
    })?;
    Ok(path)
}

/// Load every `*.manifest.json` from `dir`, sorted by `segment_id`.
pub fn load_manifests(dir: &Path) -> Result<Vec<SegmentManifest>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let read = std::fs::read_dir(dir).map_err(|e| AuraError::PolicyRead {
        path: dir.display().to_string(),
        source: e,
    })?;
    for entry in read {
        let entry = entry.map_err(|e| AuraError::PolicyRead {
            path: dir.display().to_string(),
            source: e,
        })?;
        let path = entry.path();
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if !name.ends_with(".manifest.json") {
            continue;
        }
        let raw = std::fs::read_to_string(&path).map_err(|e| AuraError::PolicyRead {
            path: path.display().to_string(),
            source: e,
        })?;
        let manifest: SegmentManifest =
            serde_json::from_str(&raw).map_err(|e| AuraError::PolicyParse {
                path: path.display().to_string(),
                message: format!("invalid segment manifest: {e}"),
            })?;
        out.push(manifest);
    }
    out.sort_by_key(|m| m.segment_id);
    Ok(out)
}

/// Errors specific to segment-chain verification.
#[derive(Debug, thiserror::Error)]
pub enum SegmentError {
    /// `segment_id` values are not strictly increasing by 1.
    #[error("segment id gap: expected {expected}, got {actual}")]
    IdGap {
        /// Expected segment id (previous + 1, or 1 for the first segment).
        expected: u64,
        /// Actual segment id found on disk.
        actual: u64,
    },
    /// `prev_segment_chain_hash` does not match the previous segment's
    /// `segment_chain_hash` (or the genesis hash for the first segment).
    #[error("segment chain break at segment {segment_id}: expected prev={expected}, got {actual}")]
    PrevChainBreak {
        /// Segment whose `prev_segment_chain_hash` is wrong.
        segment_id: u64,
        /// Expected predecessor.
        expected: String,
        /// Actual predecessor on disk.
        actual: String,
    },
    /// `prev_merkle_root` does not match the previous segment's `merkle_root`.
    #[error("segment merkle break at segment {segment_id}: expected prev_merkle_root={expected}, got {actual}")]
    PrevRootBreak {
        /// Segment whose `prev_merkle_root` is wrong.
        segment_id: u64,
        /// Expected `prev_merkle_root`.
        expected: String,
        /// Actual `prev_merkle_root`.
        actual: String,
    },
    /// `segment_chain_hash` does not recompute from the recorded fields.
    #[error("segment {segment_id} self-hash mismatch: stored={stored}, recomputed={recomputed}")]
    SelfHashMismatch {
        /// Segment whose stored `segment_chain_hash` is wrong.
        segment_id: u64,
        /// Stored value.
        stored: String,
        /// Recomputed value.
        recomputed: String,
    },
    /// Schema discriminator unknown.
    #[error("unsupported segment manifest schema: {0}")]
    BadSchema(String),
}

/// Verify the segment chain — manifest self-hash + linkage + ordering.
///
/// Returns the `segment_chain_hash` of the most recent segment on success.
pub fn verify_segment_chain(manifests: &[SegmentManifest]) -> Result<String, SegmentError> {
    let mut expected_prev_chain = segment_genesis_hash();
    let mut expected_prev_root = String::new();
    let mut expected_id = 1u64;
    let mut head = expected_prev_chain.clone();
    for m in manifests {
        if m.schema != SEGMENT_SCHEMA {
            return Err(SegmentError::BadSchema(m.schema.clone()));
        }
        if m.segment_id != expected_id {
            return Err(SegmentError::IdGap {
                expected: expected_id,
                actual: m.segment_id,
            });
        }
        if m.prev_segment_chain_hash != expected_prev_chain {
            return Err(SegmentError::PrevChainBreak {
                segment_id: m.segment_id,
                expected: expected_prev_chain,
                actual: m.prev_segment_chain_hash.clone(),
            });
        }
        if m.prev_merkle_root != expected_prev_root {
            return Err(SegmentError::PrevRootBreak {
                segment_id: m.segment_id,
                expected: expected_prev_root,
                actual: m.prev_merkle_root.clone(),
            });
        }
        let recomputed = m.recompute_segment_chain_hash();
        if recomputed != m.segment_chain_hash {
            return Err(SegmentError::SelfHashMismatch {
                segment_id: m.segment_id,
                stored: m.segment_chain_hash.clone(),
                recomputed,
            });
        }
        expected_prev_chain = m.segment_chain_hash.clone();
        expected_prev_root = m.merkle_root.clone();
        expected_id = m.segment_id + 1;
        head = m.segment_chain_hash.clone();
    }
    Ok(head)
}

/// Verify a single manifest's Merkle root against the audit-log slice it
/// claims to cover. Caller is responsible for slicing the entries.
pub fn verify_manifest_against_entries(
    manifest: &SegmentManifest,
    entries: &[AuditEntry],
) -> Result<()> {
    if entries.len() as u64 != manifest.entry_count {
        return Err(AuraError::Config(format!(
            "segment {}: expected {} entries, got {}",
            manifest.segment_id,
            manifest.entry_count,
            entries.len()
        )));
    }
    let root = hex::encode(segment_merkle_root(entries)?);
    if root != manifest.merkle_root {
        return Err(AuraError::Config(format!(
            "segment {}: merkle root mismatch (stored={}, recomputed={})",
            manifest.segment_id, manifest.merkle_root, root
        )));
    }
    if entries[entries.len() - 1].chain_hash != manifest.head_chain_hash_at_close {
        return Err(AuraError::Config(format!(
            "segment {}: head_chain_hash mismatch (stored={}, recomputed={})",
            manifest.segment_id,
            manifest.head_chain_hash_at_close,
            entries[entries.len() - 1].chain_hash
        )));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::chain::recompute_for_entry;
    use crate::crypto::genesis_hash;

    fn make_entry(seq: u64, prev: &str) -> AuditEntry {
        let mut e = AuditEntry {
            schema: "aura-guard.audit.v1".into(),
            seq,
            audit_id: format!("audit-{seq:08}"),
            timestamp: format!("2026-05-12T00:00:{seq:02}+00:00"),
            decision: "ALLOW".into(),
            policy_set: "finance-v1".into(),
            policy_hash: "deadbeef".into(),
            context: "ctx".into(),
            input_hash: format!("input-{seq}"),
            shadow_hash: format!("shadow-{seq}"),
            violations: vec![],
            prev_hash: prev.into(),
            chain_hash: String::new(),
        };
        e.chain_hash = recompute_for_entry(&e);
        e
    }

    fn make_chain(n: u64) -> Vec<AuditEntry> {
        let mut prev = genesis_hash();
        let mut out = Vec::new();
        for i in 0..n {
            let e = make_entry(i, &prev);
            prev = e.chain_hash.clone();
            out.push(e);
        }
        out
    }

    #[test]
    fn segment_chain_links_two_segments() {
        let entries = make_chain(6);
        let m1 = build_manifest(1, &entries[..3], None, "2026-05-12T00:00:00Z").unwrap();
        let m2 = build_manifest(2, &entries[3..], Some(&m1), "2026-05-12T00:01:00Z").unwrap();
        let head = verify_segment_chain(&[m1.clone(), m2.clone()]).unwrap();
        assert_eq!(head, m2.segment_chain_hash);
        assert_eq!(m2.prev_segment_chain_hash, m1.segment_chain_hash);
        assert_eq!(m2.prev_merkle_root, m1.merkle_root);
    }

    #[test]
    fn merkle_root_matches_manifest() {
        let entries = make_chain(4);
        let m = build_manifest(1, &entries, None, "2026-05-12T00:00:00Z").unwrap();
        verify_manifest_against_entries(&m, &entries).unwrap();
    }

    #[test]
    fn tampered_entry_breaks_merkle_root() {
        let mut entries = make_chain(4);
        let m = build_manifest(1, &entries, None, "2026-05-12T00:00:00Z").unwrap();
        // Tamper with one entry's chain_hash to simulate a forged audit record.
        entries[2].chain_hash = "0".repeat(64);
        let err = verify_manifest_against_entries(&m, &entries).unwrap_err();
        assert!(err.to_string().contains("merkle root mismatch"));
    }

    #[test]
    fn tampered_segment_chain_break_is_detected() {
        let entries = make_chain(4);
        let m1 = build_manifest(1, &entries[..2], None, "2026-05-12T00:00:00Z").unwrap();
        let mut m2 = build_manifest(2, &entries[2..], Some(&m1), "2026-05-12T00:01:00Z").unwrap();
        // Drop the segment-chain link.
        m2.prev_segment_chain_hash = "0".repeat(64);
        let err = verify_segment_chain(&[m1, m2]).unwrap_err();
        assert!(matches!(err, SegmentError::PrevChainBreak { .. }));
    }

    #[test]
    fn self_hash_tamper_is_detected() {
        let entries = make_chain(2);
        let mut m = build_manifest(1, &entries, None, "2026-05-12T00:00:00Z").unwrap();
        m.segment_chain_hash = "0".repeat(64);
        let err = verify_segment_chain(&[m]).unwrap_err();
        assert!(matches!(err, SegmentError::SelfHashMismatch { .. }));
    }

    #[test]
    fn segment_id_gap_is_detected() {
        let entries = make_chain(4);
        let m1 = build_manifest(1, &entries[..2], None, "2026-05-12T00:00:00Z").unwrap();
        let m3 = build_manifest(3, &entries[2..], Some(&m1), "2026-05-12T00:01:00Z").unwrap();
        let err = verify_segment_chain(&[m1, m3]).unwrap_err();
        assert!(matches!(
            err,
            SegmentError::IdGap {
                expected: 2,
                actual: 3
            }
        ));
    }
}
