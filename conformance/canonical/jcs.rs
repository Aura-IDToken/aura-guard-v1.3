//! RFC 8785 (JCS) canonical serialization — conformance access point.
//!
//! # Status: PROMOTED
//!
//! This module used to hold the implementation. The C2-1 promotion gate moved
//! it, mechanically and without semantic change, to [`aura_guard::canonical`]
//! in `src/`. What remains here is a re-export.
//!
//! That is deliberate. CANONICAL-001 and the C1 full-domain corpus call
//! `jcs::canonical_bytes`, so after this re-export they execute against the
//! **production** function. Their results are evidence about shipped code
//! rather than about a parallel conformance-only copy — which is exactly what
//! promotion is supposed to achieve. A second copy living here would have left
//! C1 verifying something the runtime never calls.
//!
//! The transformation, the pinned engine (`serde_json_canonicalizer =0.3.2`),
//! the signature, and every byte of output are unchanged. C1 re-executes
//! against this path unmodified; see `C1-FULL-DOMAIN-JCS.md` and
//! `C2-1-PRODUCTION-PROMOTION.md`.
//!
//! Input validation still does not happen here. RFC 8785 §3.1 places it
//! upstream, in [`aura_guard::event_payload`].

pub use aura_guard::canonical::canonical_bytes;
