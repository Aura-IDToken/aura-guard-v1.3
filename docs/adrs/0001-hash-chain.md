# ADR-0001: SHA-256 hash chain (vs. Merkle tree)

Status: Accepted in v1.3, still current.

## Context

We need a tamper-evident audit log. Three options were considered:

1. Per-entry SHA-256 only (v1.2 status quo).
2. SHA-256 chained between entries (Bitcoin-style block-header chain).
3. Merkle tree with periodic root anchoring.

## Decision

Adopt option 2 for v1.3 as the per-entry integrity primitive.

Each entry stores `prev_hash` (the previous entry's `chain_hash`) and
`chain_hash` (SHA-256 of canonical fields incl. `prev_hash`). The first
entry's `prev_hash` is the canonical genesis
`SHA-256("AURA-GUARD-GENESIS-v1.3")`.

## Rationale

* **Tamper detection is the primary requirement** — both chained-hash and
  Merkle approaches solve this. Chained-hash is simpler and verifiable with a
  single linear pass.
* **Replay is sequential by nature** — auditors stream the file once.
* **Merkle becomes valuable when batching to external anchors** — this was
  later delivered as segment manifests and optional RFC 3161 timestamping
  without replacing the linear hash-chain decision recorded here.

## Consequences

* Recovery from a truncated tail file is trivial: re-open the file and
  recompute the head.
* Recovery from a single corrupted line requires manual quarantine and
  re-issue from upstream — acceptable for an audit log.

## Related shipped work

The current implementation layers additional evidence structures on top of
this decision rather than replacing it:

* `aura-seal` and `src/{merkle,segment,sealer}.rs` add Merkle-sealed
  segments for batch proofs and manifest-level tamper detection.
* `src/tst_verify.rs` adds strict RFC 3161 verification for optional TSA
  tokens attached to sealed segments.
