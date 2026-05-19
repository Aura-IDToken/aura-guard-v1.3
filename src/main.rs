//! Aura-Guard v1.3 — deterministic AI audit middleware.
//!
//! ## Bootstrap fail-closed contract
//!
//! On startup every policy listed in [`AppState::EXPECTED_POLICIES`] must load
//! and signature-verify successfully. Any failure terminates the process with
//! exit code **`78`** (`sysexits.h::EX_CONFIG`) before the HTTP listener is
//! bound. There is no "lazy load on first request" path — that would create
//! a temporal integrity gap during which the runtime would be online but the
//! policy enforcement boundary would not yet be fully populated. The decision
//! engine refuses to evaluate against any policy that was not pre-loaded and
//! checksummed at boot.

#![forbid(unsafe_code)]

use std::process::ExitCode;
use std::sync::Arc;

use std::time::Duration;

use aura_guard::api::{build_router, AppState, EXPECTED_POLICIES};
use aura_guard::config::Config;
use aura_guard::crypto::genesis_hash;
use aura_guard::log_writer::LogWriter;
use aura_guard::policy::{load_policy, CompiledPolicy, TrustedSigners};
use aura_guard::sealer::{SealOutcome, SegmentSealer};
use dashmap::DashMap;
use tokio::sync::Notify;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

/// `sysexits.h::EX_CONFIG` — "configuration error: cannot start safely".
const EX_CONFIG: u8 = 78;

#[tokio::main]
async fn main() -> ExitCode {
    init_tracing();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(BootError::Config(msg)) => {
            error!(error = %msg, exit_code = EX_CONFIG, "BOOT FAIL: refusing to start");
            ExitCode::from(EX_CONFIG)
        }
        Err(BootError::Runtime(err)) => {
            error!(error = %err, "runtime error");
            ExitCode::FAILURE
        }
    }
}

/// Errors that can stop `aura-guard` from booting.
///
/// `Config` maps to exit code 78 (`sysexits.h::EX_CONFIG`) and is the
/// signal SREs should watch for in their orchestration: the binary refused
/// to start because something integrity-critical was wrong.
enum BootError {
    /// Cannot start safely — surfaced to operators as exit code 78.
    Config(String),
    /// Anything that comes up *after* the bootstrap fail-closed gate passes.
    Runtime(anyhow::Error),
}

impl From<anyhow::Error> for BootError {
    fn from(err: anyhow::Error) -> Self {
        BootError::Runtime(err)
    }
}

async fn run() -> Result<(), BootError> {
    let config = Arc::new(Config::from_env().map_err(|e| BootError::Config(e.to_string()))?);

    // Install Prometheus recorder before any counter is touched.
    let _ = aura_guard::metrics::install();

    // Load trusted signers (fail-closed unless auth_disabled).
    let enforce_signatures = !config.auth_disabled;
    let signers = if enforce_signatures {
        Arc::new(
            TrustedSigners::load(&config.trusted_signers_file).map_err(|e| {
                BootError::Config(format!(
                    "cannot load trusted signers from {}: {e}",
                    config.trusted_signers_file.display()
                ))
            })?,
        )
    } else {
        warn!(
            "AURA_AUTH_DISABLED=true — running in DEV mode: \
             no API key, no policy signature enforcement"
        );
        Arc::new(TrustedSigners::empty())
    };

    // Open append-only audit log (replays head from existing file).
    let log = LogWriter::open(config.audit_log_path.clone(), &genesis_hash())
        .map_err(|e| BootError::Config(format!("cannot open audit log: {e}")))?;

    // **Bootstrap fail-closed gate.**
    //
    // Every expected policy MUST load and signature-verify. Any failure here
    // means the runtime would otherwise serve a request against a policy set
    // that wasn't fully validated at boot — which violates the deterministic-
    // evidence contract. We refuse to listen.
    let policies: DashMap<String, Arc<CompiledPolicy>> = DashMap::new();
    for name in EXPECTED_POLICIES {
        match load_policy(name, &config.policies_dir, &signers, enforce_signatures) {
            Ok(p) => {
                info!(
                    policy = name,
                    rules = p.rules.len(),
                    hash = %p.policy_hash,
                    "policy loaded"
                );
                policies.insert((*name).to_string(), Arc::new(p));
            }
            Err(e) => {
                return Err(BootError::Config(format!(
                    "policy {name:?} failed to load at boot: {e}. \
                     Aura-Guard refuses to start with an incomplete enforcement boundary."
                )));
            }
        }
    }

    // Construct the segment sealer (if either trigger is active) and prime
    // it from any unsealed audit-log entries left over from a prior run.
    let sealer = if config.segment_size > 0 || config.segment_interval_seconds > 0 {
        let s = SegmentSealer::new(
            config.segments_dir.clone(),
            config.segment_size,
            Duration::from_secs(config.segment_interval_seconds),
        )
        .map_err(|e| BootError::Config(format!("cannot initialize segment sealer: {e}")))?;
        s.prime_from_log(&config.audit_log_path)
            .map_err(|e| BootError::Config(format!("cannot prime segment sealer: {e}")))?;
        info!(
            segments_dir = %config.segments_dir.display(),
            segment_size = config.segment_size,
            segment_interval_seconds = config.segment_interval_seconds,
            unsealed_entries = s.open_entry_count(),
            next_segment_id = s.next_segment_id(),
            "segment sealer initialized"
        );
        Some(s)
    } else {
        warn!(
            "segment sealing disabled (AURA_SEGMENT_SIZE=0 and \
             AURA_SEGMENT_INTERVAL_SECONDS=0)"
        );
        None
    };

    let state = AppState {
        config: config.clone(),
        policies: Arc::new(policies),
        log: log.clone(),
        signers,
        enforce_signatures,
        sealer: sealer.clone(),
    };

    let app = build_router(state);

    // Background task: time-based segment sealing.
    let shutdown = Arc::new(Notify::new());
    let sealer_task = if let Some(sealer) = sealer.clone() {
        let interval = Duration::from_secs(config.segment_interval_seconds.max(1));
        let shutdown = shutdown.clone();
        let cfg_for_task = config.clone();
        Some(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // Skip the immediate first tick (Tokio fires one at t=0).
            ticker.tick().await;
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        match sealer.try_seal_due_to_time() {
                            Ok(SealOutcome::Sealed { segment_id, entry_count, tsa_work }) => {
                                info!(segment_id, entry_count, "segment sealed (interval)");
                                if let Some(work) = tsa_work {
                                    aura_guard::sealer::maybe_spawn_tsa_submission(
                                        &cfg_for_task, work);
                                }
                            }
                            Ok(_) => {}
                            Err(e) => {
                                error!(error = %e, "interval-driven seal failed");
                                metrics::counter!("aura_segments_seal_errors_total")
                                    .increment(1);
                            }
                        }
                    }
                    _ = shutdown.notified() => break,
                }
            }
        }))
    } else {
        None
    };

    info!(
        bind = %config.bind,
        audit_log = %config.audit_log_path.display(),
        body_limit = config.max_body_bytes,
        request_timeout_ms = config.request_timeout_ms,
        enforce_signatures,
        policies_pre_loaded = EXPECTED_POLICIES.len(),
        "Aura-Guard v1.3 listening"
    );

    let listener = tokio::net::TcpListener::bind(config.bind)
        .await
        .map_err(|e| anyhow::anyhow!("failed to bind {}: {e}", config.bind))?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| anyhow::anyhow!("axum serve error: {e}"))?;

    // Stop the background sealer task and flush any in-flight segment.
    shutdown.notify_waiters();
    if let Some(handle) = sealer_task {
        let _ = handle.await;
    }
    if let Some(sealer) = sealer {
        match sealer.flush() {
            Ok(SealOutcome::Sealed {
                segment_id,
                entry_count,
                tsa_work,
            }) => {
                info!(segment_id, entry_count, "segment sealed (shutdown flush)");
                if let Some(work) = tsa_work {
                    aura_guard::sealer::maybe_spawn_tsa_submission(&config, work);
                    // Best-effort: give the in-flight TSA POST a brief chance
                    // to land before the runtime drops it (fail-open).
                    tokio::time::sleep(Duration::from_secs(config.tsa_timeout_seconds.min(15)))
                        .await;
                }
            }
            Ok(_) => {}
            Err(e) => error!(error = %e, "shutdown flush failed"),
        }
    }

    info!("Aura-Guard shutdown complete");
    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_env("AURA_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .json()
        .init();
}

async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    match signal(SignalKind::terminate()) {
        Ok(mut term) => {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => info!("SIGINT received"),
                _ = term.recv() => info!("SIGTERM received"),
            }
        }
        Err(e) => {
            warn!(error = %e, "cannot install SIGTERM handler; falling back to SIGINT only");
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}
