//! Append-only audit log writer with fail-closed write semantics.
//!
//! All concurrent requests serialize through a single `parking_lot::Mutex` —
//! this guarantees that two long entries can never interleave on disk.
//! A write failure flips a `halted` flag: subsequent audit calls return
//! `AuraError::LogWrite` (HTTP 503) until the operator restarts the server.

use parking_lot::Mutex;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use crate::models::AuditEntry;
use crate::{AuraError, Result};

/// Thread-safe audit-log writer.
///
/// Cloning produces another handle to the **same** underlying file and counter,
/// so the writer can be cheaply embedded in shared application state.
#[derive(Clone)]
pub struct LogWriter {
    inner: Arc<Inner>,
}

struct Inner {
    path: PathBuf,
    file: Mutex<Option<File>>,
    next_seq: AtomicU64,
    last_chain: Mutex<String>,
    halted: AtomicBool,
}

impl LogWriter {
    /// Open (or create) the JSONL audit log and replay the existing chain head.
    pub fn open(path: PathBuf, genesis: &str) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                AuraError::LogWrite(format!(
                    "cannot create log directory '{}': {e}",
                    parent.display()
                ))
            })?;
        }

        // Replay the existing file to find the head sequence + chain_hash.
        let (next_seq, head_chain) = if path.exists() {
            replay_head(&path, genesis)?
        } else {
            (0u64, genesis.to_string())
        };

        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(&path)
            .map_err(|e| {
                AuraError::LogWrite(format!("cannot open log '{}': {e}", path.display()))
            })?;

        Ok(Self {
            inner: Arc::new(Inner {
                path,
                file: Mutex::new(Some(file)),
                next_seq: AtomicU64::new(next_seq),
                last_chain: Mutex::new(head_chain),
                halted: AtomicBool::new(false),
            }),
        })
    }

    /// Reserve the next sequence number atomically.
    pub fn next_seq(&self) -> u64 {
        self.inner.next_seq.fetch_add(1, Ordering::SeqCst)
    }

    /// Return the `chain_hash` of the most recently committed entry
    /// (or the genesis hash if no entries exist yet).
    pub fn current_head(&self) -> String {
        self.inner.last_chain.lock().clone()
    }

    /// Append a fully-formed entry to the log.
    ///
    /// Returns `AuraError::LogWrite` (fatal — flips the halted flag) on any
    /// filesystem failure.
    pub fn append(&self, entry: &AuditEntry) -> Result<()> {
        if self.inner.halted.load(Ordering::SeqCst) {
            return Err(AuraError::LogWrite(format!(
                "audit log halted (file '{}' previously failed to write)",
                self.inner.path.display()
            )));
        }

        let line = serde_json::to_string(entry).map_err(AuraError::Json)?;

        let mut guard = self.inner.file.lock();
        let file = guard.as_mut().ok_or_else(|| {
            self.inner.halted.store(true, Ordering::SeqCst);
            AuraError::LogWrite("audit log file handle was closed".into())
        })?;

        if let Err(e) = writeln!(file, "{line}") {
            self.inner.halted.store(true, Ordering::SeqCst);
            return Err(AuraError::LogWrite(format!("write failed: {e}")));
        }
        if let Err(e) = file.sync_data() {
            self.inner.halted.store(true, Ordering::SeqCst);
            return Err(AuraError::LogWrite(format!("fsync failed: {e}")));
        }
        *self.inner.last_chain.lock() = entry.chain_hash.clone();
        Ok(())
    }

    /// Whether the writer is in the halted (fail-closed) state.
    pub fn is_halted(&self) -> bool {
        self.inner.halted.load(Ordering::SeqCst)
    }
}

/// Re-read the existing log to find the next sequence and head chain_hash.
fn replay_head(path: &std::path::Path, genesis: &str) -> Result<(u64, String)> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        AuraError::LogWrite(format!(
            "cannot read existing log '{}': {e}",
            path.display()
        ))
    })?;
    let mut last_seq: Option<u64> = None;
    let mut head_chain = genesis.to_string();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let entry: AuditEntry = serde_json::from_str(line).map_err(|e| {
            AuraError::LogWrite(format!(
                "log corrupt — cannot parse entry: {e}; line='{}'",
                &line[..line.len().min(80)]
            ))
        })?;
        last_seq = Some(entry.seq);
        head_chain = entry.chain_hash;
    }
    let next_seq = last_seq.map(|s| s + 1).unwrap_or(0);
    Ok((next_seq, head_chain))
}

/// Parse a JSONL audit log into structured entries. Used by `aura-replay`.
pub fn read_all_entries(path: &std::path::Path) -> Result<Vec<AuditEntry>> {
    let raw = std::fs::read_to_string(path).map_err(|e| AuraError::PolicyRead {
        path: path.display().to_string(),
        source: e,
    })?;
    let mut entries = Vec::new();
    for (i, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let entry: AuditEntry = serde_json::from_str(line).map_err(|e| AuraError::PolicyParse {
            path: path.display().to_string(),
            message: format!("line {} not valid JSON: {e}", i + 1),
        })?;
        entries.push(entry);
    }
    Ok(entries)
}
