# ADR-0001: SHA-256 hash chain (vs. Merkle tree)

Status: Accepted (v1.3).

## Context

We need a tamper-evident audit log. Three options were considered:

1. Per-entry SHA-256 only (v1.2 status quo).
2. SHA-256 chained between entries (Bitcoin-style block-header chain).
3. Merkle tree with periodic root anchoring.

## Decision

Adopt option 2 for v1.3 and revisit option 3 in v1.4.

Each entry stores `prev_hash` (the previous entry's `chain_hash`) and
`chain_hash` (SHA-256 of canonical fields incl. `prev_hash`). The first
entry's `prev_hash` is the canonical genesis
`SHA-256("AURA-GUARD-GENESIS-v1.3")`.

## Rationale

* **Tamper detection is the primary requirement** — both chained-hash and
  Merkle approaches solve this. Chained-hash is simpler and verifiable with a
  single linear pass.
* **Replay is sequential by nature** — auditors stream the file once.
* **Merkle becomes valuable when batching to external anchors** — that is the
  v1.4 deliverable, where the chain head is wrapped into a daily Merkle root
  and timestamped (RFC 3161) for cross-system attestation.

## Consequences

* Recovery from a truncated tail file is trivial: re-open the file and
  recompute the head.
* Recovery from a single corrupted line requires manual quarantine and
  re-issue from upstream — acceptable for an audit log.
