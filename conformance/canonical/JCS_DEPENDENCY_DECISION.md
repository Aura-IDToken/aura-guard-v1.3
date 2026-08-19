# JCS Rust Dependency Decision — DQ-006

Status: APPROVED FOR CONFORMANCE-ONLY USE

## Candidate

`serde_json_canonicalizer = 0.3.2`

## Provenance / license evidence

- Published crate: `serde_json_canonicalizer` 0.3.2.
- Purpose: RFC 8785 JSON Canonicalization Scheme output for `serde_json`.
- License: MIT.
- Release: 2026-02-03.
- Public documentation states `to_string` and `to_vec` APIs and describes RFC 8785 compatibility.

## Scope decision

The dependency is approved only for the isolated `ck003/canonical-001-conformance` branch while DQ-006 is being validated.

It MUST NOT be introduced into production hash/Merkle code as part of this change.

## API decision

Use `serde_json_canonicalizer::to_vec` as the byte-producing boundary. The conformance adapter returns those bytes unchanged; hashing is performed separately by the existing SHA-256 implementation.

## Important RFC 8785 constraint

The crate documentation states that arbitrary-precision `serde_json` numbers are not RFC 8785-conformant and are converted through IEEE-754 double semantics. Aura protocol fixtures therefore MUST NOT introduce raw integers outside the protocol's approved numeric domain merely to make a fixture pass. Numeric-domain constraints remain a separate protocol decision.

## Approval rationale

The crate is preferable to a bespoke JCS implementation because the project requires a standards-based, independently testable canonicalization boundary and the crate explicitly targets RFC 8785. The dependency remains provisional until `CANONICAL-001` and the required equality checks pass.

## Sources

- docs.rs `serde_json_canonicalizer` 0.3.2 documentation and package metadata.
- RFC 8785, JSON Canonicalization Scheme.
