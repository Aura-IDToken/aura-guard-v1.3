//! Unit tests for [`aura_guard::config::Config::validate`].
//!
//! All tests construct [`Config`] values directly (bypassing `from_env`) and
//! exercise [`Config::validate`] to assert the security constraints introduced
//! to prevent accidental production deployments with:
//!
//! * `AURA_AUTH_DISABLED=true` on a non-loopback bind address,
//! * an API key that is too short to resist brute-force, or
//! * a well-known placeholder API key.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use aura_guard::config::{Config, MIN_API_KEY_LEN};

/// A minimal [`Config`] that passes `validate()`: strong key on loopback with
/// auth enforcement enabled. Individual tests mutate specific fields.
fn base_config() -> Config {
    Config {
        bind: "127.0.0.1:8080".parse().expect("parse loopback addr"),
        api_key: Some("a".repeat(MIN_API_KEY_LEN)),
        auth_disabled: false,
        ..Config::default()
    }
}

// ── API key length guard ──────────────────────────────────────────────────────

#[test]
fn validate_accepts_key_exactly_at_minimum_length() {
    let cfg = Config {
        api_key: Some("a".repeat(MIN_API_KEY_LEN)),
        ..base_config()
    };
    assert!(
        cfg.validate().is_ok(),
        "key of exactly {MIN_API_KEY_LEN} chars must be accepted"
    );
}

#[test]
fn validate_accepts_key_longer_than_minimum() {
    let cfg = Config {
        api_key: Some("a".repeat(MIN_API_KEY_LEN + 32)),
        ..base_config()
    };
    assert!(cfg.validate().is_ok(), "key longer than minimum must be accepted");
}

#[test]
fn validate_rejects_key_one_below_minimum_length() {
    let cfg = Config {
        api_key: Some("a".repeat(MIN_API_KEY_LEN - 1)),
        ..base_config()
    };
    let err = cfg.validate().expect_err("key one char below minimum must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("at least"),
        "error must mention the minimum length requirement, got: {msg}"
    );
}

#[test]
fn validate_rejects_single_char_key() {
    let cfg = Config {
        api_key: Some("x".to_string()),
        ..base_config()
    };
    assert!(cfg.validate().is_err(), "single-char key must be rejected");
}

// ── Known-placeholder (denylist) guard ───────────────────────────────────────

#[test]
fn validate_rejects_changeme_key() {
    let cfg = Config {
        api_key: Some("changeme".to_string()),
        ..base_config()
    };
    assert!(cfg.validate().is_err(), "'changeme' must be rejected");
}

#[test]
fn validate_rejects_secret_key() {
    let cfg = Config {
        api_key: Some("secret".to_string()),
        ..base_config()
    };
    assert!(cfg.validate().is_err(), "'secret' must be rejected");
}

#[test]
fn validate_rejects_password_key() {
    let cfg = Config {
        api_key: Some("password".to_string()),
        ..base_config()
    };
    assert!(cfg.validate().is_err(), "'password' must be rejected");
}

// ── auth_disabled + non-loopback bind guard ───────────────────────────────────

#[test]
fn validate_rejects_auth_disabled_on_all_interfaces_ipv4() {
    let cfg = Config {
        bind: "0.0.0.0:8080".parse().expect("parse 0.0.0.0"),
        auth_disabled: true,
        api_key: None,
        ..Config::default()
    };
    let err = cfg
        .validate()
        .expect_err("auth_disabled=true on 0.0.0.0 must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("non-loopback") || msg.contains("AURA_AUTH_DISABLED"),
        "error must describe the non-loopback guard, got: {msg}"
    );
}

#[test]
fn validate_rejects_auth_disabled_on_private_network_address() {
    let cfg = Config {
        bind: "10.0.0.5:8080".parse().expect("parse private addr"),
        auth_disabled: true,
        api_key: None,
        ..Config::default()
    };
    assert!(
        cfg.validate().is_err(),
        "auth_disabled=true on a private-network address must be rejected"
    );
}

#[test]
fn validate_accepts_auth_disabled_on_loopback_ipv4() {
    let cfg = Config {
        bind: "127.0.0.1:8080".parse().expect("parse loopback"),
        auth_disabled: true,
        api_key: None,
        ..Config::default()
    };
    assert!(
        cfg.validate().is_ok(),
        "auth_disabled=true on loopback (127.0.0.1) is permitted for local dev"
    );
}

#[test]
fn validate_accepts_auth_disabled_on_loopback_ipv6() {
    let cfg = Config {
        bind: "[::1]:8080".parse().expect("parse ipv6 loopback"),
        auth_disabled: true,
        api_key: None,
        ..Config::default()
    };
    assert!(
        cfg.validate().is_ok(),
        "auth_disabled=true on loopback (::1) is permitted for local dev"
    );
}

// ── No API key set (auth_disabled path) ──────────────────────────────────────

#[test]
fn validate_skips_key_strength_check_when_no_key_is_set() {
    // auth_disabled=true + no key + loopback must succeed;
    // validate() must not error when api_key is None.
    let cfg = Config {
        bind: "127.0.0.1:8080".parse().expect("parse loopback"),
        auth_disabled: true,
        api_key: None,
        ..Config::default()
    };
    assert!(cfg.validate().is_ok());
}

#[test]
fn validate_rejects_missing_key_when_auth_is_enabled() {
    // auth_disabled=false (the default) + no key must be rejected by validate()
    // so that manually-constructed Config values are checked without needing from_env().
    let cfg = Config {
        bind: "127.0.0.1:8080".parse().expect("parse loopback"),
        auth_disabled: false,
        api_key: None,
        ..Config::default()
    };
    let err = cfg
        .validate()
        .expect_err("missing api_key with auth enabled must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("AURA_API_KEY") || msg.contains("required"),
        "error must mention that an API key is required, got: {msg}"
    );
}
