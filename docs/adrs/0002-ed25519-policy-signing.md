# ADR-0002: Ed25519 for policy signing

Status: Accepted (v1.3).

## Context

Policy files (`policies/*.yaml`) govern every audit decision. We need to make
silent tampering by an operator impossible without invalidating the signature.

## Decision

Sign each policy with **Ed25519** (`ed25519-dalek` crate, RustCrypto).
Verifier keys live in `policies/trusted_signers.json`. The signature is the
raw Ed25519 signature over the YAML bytes, hex-encoded into
`<policy>.yaml.sig`, paired with `<policy>.yaml.signer` carrying the signer
ID.

## Alternatives considered

* **RSA-PSS 3072** — bigger keys, slower verification, more surface area.
* **ECDSA-P256** — comparable security but Rust ecosystem prefers Ed25519
  for fixed-message signing; deterministic by construction (no nonce reuse
  pitfalls).
* **Minisign / signify** — file-format heavy, less library support.

## Rationale

* **Determinism** — Ed25519 signatures are deterministic; same key + same
  message ⇒ same signature, useful for reproducible builds.
* **Speed + size** — 32-byte keys, 64-byte signatures, sub-millisecond verify.
* **Audited implementation** — `ed25519-dalek` v2 is widely used and audited.
* **HSM friendly** — Ed25519 is supported by mainstream HSMs / cloud KMS for
  the v1.5 enterprise roadmap.

## Consequences

* The runtime stores no secrets — only public verifier keys. Private signing
  keys live with the policy author (or HSM in production).
* Adding a new signer is a one-line JSON edit, easily code-reviewed.
* Key rotation: append new pubkey, re-sign all packs, keep the old key trusted
  for a transition window, then remove.
