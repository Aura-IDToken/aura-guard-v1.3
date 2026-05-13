//! # Aura-Guard
//!
//! Deterministic AI audit middleware with a cryptographic evidence chain.
//!
//! This crate exposes the runtime engine (used by the `aura-guard` server) and
//! the verification primitives (used by the `aura-replay` CLI).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod auth;
pub mod chain;
pub mod config;
pub mod crypto;
pub mod engine;
pub mod error;
pub mod log_writer;
pub mod metrics;
pub mod models;
pub mod normalizer;
pub mod policy;
pub mod validators;

pub mod api;

pub use error::{AuraError, Result};
