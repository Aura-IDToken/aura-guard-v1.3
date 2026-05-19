//! Runtime segment sealer.
//!
//! Wraps the segment-manifest construction primitives from [`crate::segment`]
//! with the bookkeeping needed by the live `aura-guard` server:
//!
//! * Loads existing manifests from disk at startup and replays unsealed
//!   entries from the audit log into the open-segment buffer so a restart
//!   does not silently drop in-flight entries.
//! * Closes a segment as soon as **either** the entry-count threshold
//!   (`AURA_SEGMENT_SIZE`) is reached **or** the time threshold
//!   (`AURA_SEGMENT_INTERVAL_SECONDS`) has elapsed since the last seal.
//! * Writes manifests atomically via a temp-file + rename.
//! * Emits Prometheus counters / gauges so operators can wire alerts to
//!   stalled sealing.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use parking_lot::Mutex;

use crate::log_writer::read_all_entries;
use crate::merkle::leaf_hash;
use crate::models::AuditEntry;
use crate::segment::{load_manifests, write_manifest, SegmentManifest, SEGMENT_SCHEMA};
use crate::{AuraError, Result};

/// Thread-safe handle to the segment sealer.
#[derive(Clone)]
pub struct SegmentSealer {
    inner: Arc<Inner>,
}

struct Inner {
    dir: PathBuf,
    size_threshold: u64,
    interval: Duration,
    state: Mutex<State>,
}

struct State {
    next_segment_id: u64,
    last_manifest: Option<SegmentManifest>,
    open_leaves: Vec<[u8; 32]>,
    open_first_seq: Option<u64>,
    open_last_seq: Option<u64>,
    open_last_chain_hash: String,
    last_seal_at: Instant,
}

/// Preimage that the optional RFC 3161 timestamp will cover.
///
/// Returned from a successful seal so the caller can fire a background
/// TSA submission without re-reading the manifest from disk.
#[derive(Debug, Clone)]
pub struct TsaWork {
    /// Segment id that was just sealed.
    pub segment_id: u64,
    /// Bytes that were hashed to produce the `segment_chain_hash`. This
    /// preimage is what the TSA signs over (after SHA-256).
    pub preimage: String,
    /// On-disk directory that will receive the `NNNNNN.tsr` file.
    pub dir: PathBuf,
}

/// Outcome of a sealing attempt.
#[derive(Debug, Clone)]
pub enum SealOutcome {
    /// No unsealed entries are buffered; nothing to do.
    Empty,
    /// Threshold not yet reached.
    NotDue,
    /// A manifest was written.
    Sealed {
        /// Segment that was just sealed.
        segment_id: u64,
        /// Number of entries it covers.
        entry_count: u64,
        /// Work item for the optional RFC 3161 submission, if a TSA URL is
        /// configured. The sealer itself does not perform the network call;
        /// the orchestration layer decides whether (and how) to submit.
        tsa_work: Option<TsaWork>,
    },
}

impl SegmentSealer {
    /// Build a sealer rooted at `dir`. Pass `size_threshold = 0` or
    /// `interval = Duration::ZERO` to disable the respective trigger.
    /// A sealer with **both** triggers disabled never seals automatically.
    pub fn new(dir: PathBuf, size_threshold: u64, interval: Duration) -> Result<Self> {
        std::fs::create_dir_all(&dir).map_err(|e| {
            AuraError::LogWrite(format!(
                "cannot create segments dir '{}': {e}",
                dir.display()
            ))
        })?;
        let manifests = load_manifests(&dir)?;
        for m in &manifests {
            if m.schema != SEGMENT_SCHEMA {
                return Err(AuraError::Config(format!(
                    "unsupported segment schema '{}' in {}",
                    m.schema,
                    dir.display()
                )));
            }
        }
        let last = manifests.last().cloned();
        let next_segment_id = last.as_ref().map(|m| m.segment_id + 1).unwrap_or(1);
        Ok(Self {
            inner: Arc::new(Inner {
                dir,
                size_threshold,
                interval,
                state: Mutex::new(State {
                    next_segment_id,
                    last_manifest: last,
                    open_leaves: Vec::new(),
                    open_first_seq: None,
                    open_last_seq: None,
                    open_last_chain_hash: String::new(),
                    last_seal_at: Instant::now(),
                }),
            }),
        })
    }

    /// Replay any audit-log entries whose `seq` is **strictly greater** than
    /// the last sealed `last_seq`, priming the open-segment buffer.
    ///
    /// Should be called once on boot, before HTTP traffic is accepted.
    pub fn prime_from_log(&self, log_path: &Path) -> Result<()> {
        if !log_path.exists() {
            return Ok(());
        }
        let entries = read_all_entries(log_path)?;
        let last_covered = self
            .inner
            .state
            .lock()
            .last_manifest
            .as_ref()
            .map(|m| m.last_seq);
        let mut state = self.inner.state.lock();
        for e in entries {
            if let Some(c) = last_covered {
                if e.seq <= c {
                    continue;
                }
            }
            push_entry_into_state(&mut state, &e)?;
        }
        Ok(())
    }

    /// Observe a freshly-appended entry. Called from the audit handler
    /// **after** the entry has been durably written to the log.
    ///
    /// Returns `Sealed { .. }` if observing this entry caused the size
    /// threshold to trip and a segment to close.
    pub fn observe(&self, entry: &AuditEntry) -> Result<SealOutcome> {
        let mut state = self.inner.state.lock();
        push_entry_into_state(&mut state, entry)?;
        let size_reached = self.inner.size_threshold > 0
            && state.open_leaves.len() as u64 >= self.inner.size_threshold;
        if size_reached {
            seal_locked(&self.inner, &mut state)
        } else {
            Ok(SealOutcome::NotDue)
        }
    }

    /// Seal the currently-open segment if the interval has elapsed.
    /// Called from a background task on a periodic timer.
    pub fn try_seal_due_to_time(&self) -> Result<SealOutcome> {
        let mut state = self.inner.state.lock();
        if state.open_leaves.is_empty() {
            return Ok(SealOutcome::Empty);
        }
        if self.inner.interval.is_zero() {
            return Ok(SealOutcome::NotDue);
        }
        if state.last_seal_at.elapsed() < self.inner.interval {
            return Ok(SealOutcome::NotDue);
        }
        seal_locked(&self.inner, &mut state)
    }

    /// Force-seal whatever is currently buffered. Called on shutdown.
    pub fn flush(&self) -> Result<SealOutcome> {
        let mut state = self.inner.state.lock();
        if state.open_leaves.is_empty() {
            return Ok(SealOutcome::Empty);
        }
        seal_locked(&self.inner, &mut state)
    }

    /// Path of the segments directory.
    pub fn dir(&self) -> &Path {
        &self.inner.dir
    }

    /// Number of entries currently buffered in the open segment.
    pub fn open_entry_count(&self) -> u64 {
        self.inner.state.lock().open_leaves.len() as u64
    }

    /// Segment id that will be assigned to the next seal.
    pub fn next_segment_id(&self) -> u64 {
        self.inner.state.lock().next_segment_id
    }
}

/// If the runtime configuration has a TSA URL set, kick off a background
/// `spawn_blocking` task that POSTs the freshly-sealed segment preimage to
/// the TSA and persists the response next to the manifest. This is **fail-
/// open**: the function always returns immediately, never propagates errors
/// out-of-band, and only emits Prometheus counters + tracing logs.
///
/// The function must be called from inside a Tokio runtime.
pub fn maybe_spawn_tsa_submission(config: &Arc<crate::config::Config>, work: TsaWork) {
    let Some(url) = config.tsa_url.clone() else {
        return;
    };
    let timeout = Duration::from_secs(config.tsa_timeout_seconds.max(1));
    tokio::task::spawn_blocking(move || {
        submit_tsa_blocking(&url, work, timeout);
    });
}

fn submit_tsa_blocking(url: &str, work: TsaWork, timeout: Duration) {
    let segment_id = work.segment_id;
    let dir = work.dir.clone();
    match crate::rfc3161::timestamp(url, work.preimage.as_bytes(), timeout) {
        Ok((tsr_bytes, _digest)) => {
            let tsr_path = dir.join(format!("{:06}.tsr", segment_id));
            if let Err(e) = write_atomic(&tsr_path, &tsr_bytes) {
                tracing::error!(error = %e, segment_id, "failed to persist TSR");
                metrics::counter!("aura_tsa_request_failures_total").increment(1);
                return;
            }
            tracing::info!(
                segment_id,
                bytes = tsr_bytes.len(),
                "segment timestamp anchored via RFC 3161"
            );
            metrics::counter!("aura_tsa_requests_total").increment(1);
        }
        Err(e) => {
            tracing::warn!(error = %e, segment_id, "RFC 3161 submission failed (fail-open)");
            metrics::counter!("aura_tsa_request_failures_total").increment(1);
        }
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tsr.tmp");
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn push_entry_into_state(state: &mut State, entry: &AuditEntry) -> Result<()> {
    let raw = hex::decode(&entry.chain_hash).map_err(|e| {
        AuraError::Config(format!(
            "audit entry seq={} has malformed chain_hash: {e}",
            entry.seq
        ))
    })?;
    state.open_leaves.push(leaf_hash(&raw));
    if state.open_first_seq.is_none() {
        state.open_first_seq = Some(entry.seq);
    }
    state.open_last_seq = Some(entry.seq);
    state.open_last_chain_hash = entry.chain_hash.clone();
    Ok(())
}

fn seal_locked(inner: &Inner, state: &mut State) -> Result<SealOutcome> {
    if state.open_leaves.is_empty() {
        return Ok(SealOutcome::Empty);
    }
    let first_seq = state.open_first_seq.unwrap_or(0);
    let last_seq = state.open_last_seq.unwrap_or(first_seq);
    let entry_count = state.open_leaves.len() as u64;
    // Re-use the cleaner construction path in `segment::build_manifest`. To
    // do so we synthesize a thin "AuditEntry-shaped" slice that exposes the
    // chain_hash field expected by that builder.
    //
    // Build directly from leaves to avoid round-tripping through full entries.
    let sealed_at = Utc::now().to_rfc3339();
    let manifest = build_manifest_from_leaves(
        state.next_segment_id,
        first_seq,
        last_seq,
        &state.open_leaves,
        &state.open_last_chain_hash,
        state.last_manifest.as_ref(),
        &sealed_at,
    );

    let _path = write_manifest(&inner.dir, &manifest)?;

    let segment_id = manifest.segment_id;
    let preimage = SegmentManifest::segment_chain_preimage(
        &manifest.prev_segment_chain_hash,
        &manifest.merkle_root,
        manifest.first_seq,
        manifest.last_seq,
        &manifest.sealed_at,
    );
    state.last_manifest = Some(manifest);
    state.next_segment_id = segment_id + 1;
    state.open_leaves.clear();
    state.open_first_seq = None;
    state.open_last_seq = None;
    state.open_last_chain_hash.clear();
    state.last_seal_at = Instant::now();

    metrics::counter!("aura_segments_sealed_total").increment(1);
    metrics::counter!("aura_segment_entries_total").increment(entry_count);
    metrics::gauge!("aura_segments_open_entries").set(0.0);

    Ok(SealOutcome::Sealed {
        segment_id,
        entry_count,
        tsa_work: Some(TsaWork {
            segment_id,
            preimage,
            dir: inner.dir.clone(),
        }),
    })
}

/// Same shape as [`crate::segment::build_manifest`] but consumes leaf hashes
/// directly, avoiding the need to retain full [`AuditEntry`] structs in
/// memory between seals.
fn build_manifest_from_leaves(
    segment_id: u64,
    first_seq: u64,
    last_seq: u64,
    leaves: &[[u8; 32]],
    head_chain_hash_at_close: &str,
    prev: Option<&SegmentManifest>,
    sealed_at: &str,
) -> SegmentManifest {
    use crate::merkle::merkle_root;
    use sha2::{Digest, Sha256};

    let merkle_root_hex = hex::encode(merkle_root(leaves));
    let (prev_root, prev_chain) = match prev {
        Some(m) => (m.merkle_root.clone(), m.segment_chain_hash.clone()),
        None => (String::new(), crate::segment::segment_genesis_hash()),
    };
    let preimage = SegmentManifest::segment_chain_preimage(
        &prev_chain,
        &merkle_root_hex,
        first_seq,
        last_seq,
        sealed_at,
    );
    let segment_chain_hash = hex::encode(Sha256::digest(preimage.as_bytes()));

    SegmentManifest {
        schema: SEGMENT_SCHEMA.to_string(),
        segment_id,
        first_seq,
        last_seq,
        entry_count: leaves.len() as u64,
        merkle_root: merkle_root_hex,
        prev_merkle_root: prev_root,
        prev_segment_chain_hash: prev_chain,
        segment_chain_hash,
        head_chain_hash_at_close: head_chain_hash_at_close.to_string(),
        sealed_at: sealed_at.to_string(),
        tst_path: None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::chain::recompute_for_entry;
    use crate::crypto::genesis_hash;
    use crate::segment::verify_segment_chain;
    use tempfile::TempDir;

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

    #[test]
    fn size_threshold_seals_segment() {
        let tmp = TempDir::new().unwrap();
        let sealer = SegmentSealer::new(tmp.path().to_path_buf(), 3, Duration::ZERO).unwrap();
        let mut prev = genesis_hash();
        for i in 0..3 {
            let e = make_entry(i, &prev);
            prev = e.chain_hash.clone();
            let out = sealer.observe(&e).unwrap();
            if i < 2 {
                assert!(matches!(out, SealOutcome::NotDue));
            } else {
                assert!(matches!(
                    out,
                    SealOutcome::Sealed {
                        segment_id: 1,
                        entry_count: 3,
                        ..
                    }
                ));
            }
        }
        assert_eq!(sealer.open_entry_count(), 0);
        assert_eq!(sealer.next_segment_id(), 2);
        let manifests = load_manifests(tmp.path()).unwrap();
        assert_eq!(manifests.len(), 1);
        verify_segment_chain(&manifests).unwrap();
    }

    #[test]
    fn flush_seals_partial_segment() {
        let tmp = TempDir::new().unwrap();
        let sealer = SegmentSealer::new(tmp.path().to_path_buf(), 10, Duration::ZERO).unwrap();
        let mut prev = genesis_hash();
        for i in 0..2 {
            let e = make_entry(i, &prev);
            prev = e.chain_hash.clone();
            sealer.observe(&e).unwrap();
        }
        let out = sealer.flush().unwrap();
        assert!(matches!(
            out,
            SealOutcome::Sealed {
                segment_id: 1,
                entry_count: 2,
                ..
            }
        ));
        let out2 = sealer.flush().unwrap();
        assert!(matches!(out2, SealOutcome::Empty));
    }

    #[test]
    fn manifests_chain_across_seals() {
        let tmp = TempDir::new().unwrap();
        let sealer = SegmentSealer::new(tmp.path().to_path_buf(), 2, Duration::ZERO).unwrap();
        let mut prev = genesis_hash();
        for i in 0..4 {
            let e = make_entry(i, &prev);
            prev = e.chain_hash.clone();
            sealer.observe(&e).unwrap();
        }
        let manifests = load_manifests(tmp.path()).unwrap();
        assert_eq!(manifests.len(), 2);
        assert_eq!(manifests[0].first_seq, 0);
        assert_eq!(manifests[0].last_seq, 1);
        assert_eq!(manifests[1].first_seq, 2);
        assert_eq!(manifests[1].last_seq, 3);
        assert_eq!(
            manifests[1].prev_segment_chain_hash,
            manifests[0].segment_chain_hash
        );
        verify_segment_chain(&manifests).unwrap();
    }
}
