#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Bootstrap fail-closed contract tests.
//!
//! Spawns the real `aura-guard` binary in a hermetic environment and verifies
//! it refuses to start (exit code **78**, `sysexits.h::EX_CONFIG`) when the
//! enforcement boundary is incomplete:
//!
//! * a policy listed in `EXPECTED_POLICIES` is missing,
//! * the trusted-signers file is missing,
//! * the policy signature does not verify against any trusted signer.
//!
//! These tests pin the architectural invariant that gave rise to the v1.3
//! review feedback: there is no "warn and lazy-load" path; the runtime
//! either starts with a fully validated enforcement boundary or not at all.

use std::process::Command;
use std::time::Duration;
use tempfile::TempDir;

/// `sysexits.h::EX_CONFIG`.
const EX_CONFIG: i32 = 78;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_aura-guard")
}

/// Run `aura-guard` with the given env vars, give it a brief window to fail,
/// kill it if it did manage to bind, and return the exit code.
fn run_and_collect_exit(env: &[(&str, String)]) -> i32 {
    let mut cmd = Command::new(binary());
    cmd.env_clear();
    cmd.env("PATH", std::env::var("PATH").unwrap_or_default());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("spawn aura-guard");

    // Boot failure is synchronous and fast (<200 ms). Poll briefly.
    for _ in 0..30 {
        if let Some(status) = child.try_wait().expect("try_wait") {
            return status.code().unwrap_or(-1);
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // The binary did NOT fail fast — it probably bound a socket. That itself
    // means the fail-closed contract is broken, but we still need to clean
    // up so the test runner doesn't leak processes.
    let _ = child.kill();
    let _ = child.wait();
    panic!("aura-guard did not exit within 3 seconds; expected boot failure");
}

#[test]
fn refuses_to_start_when_policy_missing() {
    let tmp = TempDir::new().unwrap();
    let policies_dir = tmp.path().join("policies");
    std::fs::create_dir_all(&policies_dir).unwrap();
    std::fs::write(policies_dir.join("trusted_signers.json"), b"{}").unwrap();

    let code = run_and_collect_exit(&[
        ("AURA_BIND", "127.0.0.1:0".into()),
        ("AURA_POLICIES_DIR", policies_dir.display().to_string()),
        (
            "AURA_TRUSTED_SIGNERS_FILE",
            policies_dir
                .join("trusted_signers.json")
                .display()
                .to_string(),
        ),
        (
            "AURA_AUDIT_LOG_PATH",
            tmp.path().join("audit.jsonl").display().to_string(),
        ),
        ("AURA_AUTH_DISABLED", "true".into()),
    ]);

    assert_eq!(
        code, EX_CONFIG,
        "missing finance-v1.yaml must surface as exit 78 (EX_CONFIG), got {code}"
    );
}

#[test]
fn refuses_to_start_when_trusted_signers_missing() {
    let tmp = TempDir::new().unwrap();
    let policies_dir = tmp.path().join("policies");
    std::fs::create_dir_all(&policies_dir).unwrap();
    // Note: no trusted_signers.json. Auth is NOT disabled.

    let code = run_and_collect_exit(&[
        ("AURA_BIND", "127.0.0.1:0".into()),
        ("AURA_API_KEY", "x".into()),
        ("AURA_POLICIES_DIR", policies_dir.display().to_string()),
        (
            "AURA_TRUSTED_SIGNERS_FILE",
            policies_dir
                .join("trusted_signers.json")
                .display()
                .to_string(),
        ),
        (
            "AURA_AUDIT_LOG_PATH",
            tmp.path().join("audit.jsonl").display().to_string(),
        ),
    ]);

    assert_eq!(
        code, EX_CONFIG,
        "missing trusted_signers.json under enforce must surface as exit 78, got {code}"
    );
}
