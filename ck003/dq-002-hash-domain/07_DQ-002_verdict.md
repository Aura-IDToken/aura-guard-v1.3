# DQ-002 — Hash Domain Verdict

**Status:** CONDITIONALLY CLOSED / CI-BLOCKED  
**Date:** 2026-08-17  
**Repository:** `Aura-IDToken/aura-guard-v1.3`  
**PR:** #57 — `CK-003: DQ-002 hash-domain conformance gate`  
**Branch:** `ck003/dq-002-hash-domain`

## 1. Decision

Aura adopts **RI-RS** as the canonical hash-domain model for CK-003:

```text
canonical object
      |
      v
canonical bytes
      |
      +-- leaf --> SHA-256(0x00 || bytes)
      |
      +-- node --> SHA-256(0x01 || left[32] || right[32])
```

Merkle Tree Hash semantics are RFC 6962-style: recursive largest-power-of-two split, single-node promotion for non-power-of-two trees, and no duplication of the last leaf.

**Production hashing semantics are not changed by this DQ-002 PR.** The purpose of this package is to establish and continuously test the contract before Core remediation.

## 2. Evidence status

| Evidence item | Status | Basis |
|---|---|---|
| Current normative specification snapshot | PASS | Snapshot reviewed during DQ-002 evidence refresh |
| Hash-domain decision | PASS | RI-RS selected as canonical model |
| Cross-language fixture | PASS | Pinned leaf/node vectors in `audit/fixtures/ck003_dq002_001.json` |
| RI-PY conformance | PASS* | Independent Python computation reproduces the fixture vectors |
| RI-RS conformance test | IMPLEMENTED | `tests/ck003_dq002_ri_rs_conformance.rs` |
| CI gate | IMPLEMENTED | `.github/workflows/ck003-dq002.yml` |
| GitHub Actions execution | BLOCKED | GitHub billing/account restriction prevents job start |

`*` Local/independent evidence is not a substitute for a successful GitHub Actions run.

## 3. Independent cryptographic verification

For the pinned canonical bytes:

```text
agent_id=MACHINE_ACCOUNT_001|ari=95000|drift=5000|ts=2026-01-01T00:00:00Z
```

The expected RI-RS leaf digest is:

```text
f7acc9aaf8937e3bdc02a2d39ac661a742343abcd3d4a76807a2f1585a158e4b
```

For a node with the same digest on both sides, the expected digest is:

```text
1b3ff765c9dc0659880dff1f051ee4c22b9476a6275dcf3b2437f9e1feec9dd6
```

These values were independently recomputed as:

```text
SHA-256(0x00 || canonical_bytes)
SHA-256(0x01 || leaf || leaf)
```

and match the pinned fixture.

## 4. Repository evidence

The production Guard implementation on the DQ-002 branch already implements the selected domain separation:

- `leaf_hash(data)` prepends `0x00`.
- `node_hash(left, right)` prepends `0x01` and consumes two 32-byte digests.
- `merkle_root()` uses the RFC 6962 recursive split semantics.
- Odd/unpaired nodes are promoted rather than duplicated.

The DQ-002 conformance test calls the production `leaf_hash()` and `node_hash()` functions directly; it does not reimplement the algorithm inside the test.

## 5. CI limitation

The dedicated workflow is present and correctly wired, but the GitHub Actions jobs currently cannot start because the account is blocked by a billing problem.

Therefore:

```text
CI gate = IMPLEMENTED
CI execution = BLOCKED
CI PASS = NOT CLAIMED
```

This is an **environmental blocker**, not a protocol-conformance failure.

## 6. Closure criterion

DQ-002 may be promoted from **CONDITIONALLY CLOSED** to **PROVEN/CLOSED** only after the following event occurs:

1. GitHub billing/account restriction is resolved.
2. PR #57 workflow starts.
3. `RI-RS conformance` job passes.
4. `DQ-002 gate` job passes.
5. The successful run is retained as the CI evidence reference.

No cryptographic redesign is required for that re-run.

## 7. Explicit non-decisions

This package does **not**:

- merge PR #57;
- change production Core hashing;
- migrate RI-PY yet;
- declare cross-repository conformance proven by CI;
- close unrelated CK-003 DQs.

## Final verdict

> **DQ-002: CONDITIONALLY CLOSED — TECHNICAL EVIDENCE CONSISTENT, CI EXECUTION BLOCKED BY GITHUB BILLING.**
>
> The canonical hash-domain decision is fixed as RI-RS. The cross-language fixture and production RI-RS conformance gate are in place. Final closure is intentionally deferred until one successful GitHub Actions execution is observed.
