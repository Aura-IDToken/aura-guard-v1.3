# Segments and RFC 3161 timestamping

This document describes the v1.4 Merkle-segment layer that sits **on top of**
the v1.3 per-entry hash chain. The two layers are independent: the per-entry
chain provides per-write tamper evidence (every entry references the previous
one); the segment layer batches contiguous entries into signed checkpoints and
optionally anchors each checkpoint to an external time-stamp authority (TSA).

| Property                              | Per-entry chain (v1.3) | Segment layer (v1.4) |
| ------------------------------------- | ---------------------- | -------------------- |
| Cryptographic primitive               | SHA-256 chain          | RFC 6962 Merkle tree |
| Granularity                           | Single entry           | Contiguous batch     |
| Inclusion-proof size                  | O(N)                   | O(log N)             |
| External anchoring                    | No                     | Optional (RFC 3161)  |
| Verifiable without re-reading the log | No                     | Yes (Merkle proof)   |
| Hot-path latency impact               | Append + sync          | None (in-memory)     |
| Mandatory                             | Yes                    | Yes (default on)     |

## Layout on disk

```
logs/
├── audit.jsonl                          # per-entry chain (v1.3, unchanged)
└── segments/
    ├── 000001.manifest.json             # segment-chain entry + Merkle root
    ├── 000001.tsr                       # optional RFC 3161 response
    ├── 000002.manifest.json
    ├── 000002.tsr
    └── …
```

Segments are immutable once written. `aura-guard` never re-opens a sealed
manifest; the only file mutation after `write_atomic` is the optional
sibling `.tsr` that the background TSA task may persist.

## Manifest schema

```json
{
  "schema": "aura-guard.segment.v1",
  "segment_id": 7,
  "first_seq": 6000,
  "last_seq": 6999,
  "entry_count": 1000,
  "merkle_root": "<hex SHA-256>",
  "prev_merkle_root": "<hex SHA-256 of prior segment>",
  "prev_segment_chain_hash": "<hex>",
  "segment_chain_hash": "<hex>",
  "head_chain_hash_at_close": "<hex chain_hash of last entry>",
  "sealed_at": "RFC3339 UTC",
  "tst_path": "000007.tsr"
}
```

`segment_chain_hash` is computed deterministically from a single concatenated
preimage (`|`-separated): the prior segment's `segment_chain_hash`, the new
Merkle root, `first_seq`, `last_seq`, and `sealed_at`. The first segment uses
the constant genesis seed `SHA-256("AURA-GUARD-SEGMENT-GENESIS-v1")` as its
`prev_segment_chain_hash`. Any tampering with a manifest or its position in
the chain therefore breaks the next manifest's self-hash.

## Merkle construction (RFC 6962)

- `leaf_hash(chain_hash_bytes)  = SHA-256(0x00 || chain_hash_bytes)`
- `node_hash(left, right)       = SHA-256(0x01 || left || right)`
- Left-heavy tree: at each level, the left subtree contains the largest
  power-of-two number of leaves not exceeding the level's size.

The leaf input is the **raw 32 bytes** of `chain_hash` (the same SHA-256
output the per-entry chain emits), not its hex encoding. This matches the
encoding used by the public Certificate Transparency logs.

## Sealing triggers

A segment is sealed when the **first** of the following occurs:

1. `AURA_SEGMENT_SIZE` entries have been buffered (default `1000`; set to
   `0` to disable size-based sealing).
2. `AURA_SEGMENT_INTERVAL_SECONDS` have elapsed since the previous seal
   (default `60`; set to `0` to disable time-based sealing).
3. The process receives a graceful shutdown signal (`SIGINT` / `SIGTERM`).

Sealing is synchronous on the audit hot path **only** when triggered by
the size threshold inside `audit::handle_audit`. The interval and shutdown
paths run on the Tokio runtime outside the request flow.

If both triggers are disabled, segments are written only at shutdown.

## Configuration

| Variable                          | Default          | Effect                                                                                |
| --------------------------------- | ---------------- | ------------------------------------------------------------------------------------- |
| `AURA_SEGMENTS_DIR`               | `logs/segments`  | Directory for `*.manifest.json` and `*.tsr` files.                                    |
| `AURA_SEGMENT_SIZE`               | `1000`           | Entry count that triggers a seal. `0` disables.                                       |
| `AURA_SEGMENT_INTERVAL_SECONDS`   | `60`             | Time-based seal threshold. `0` disables.                                              |
| `AURA_TSA_URL`                    | _(unset)_        | Optional RFC 3161 HTTP(S) endpoint. When unset, no network requests are made.         |
| `AURA_TSA_TIMEOUT_SECONDS`        | `10`             | HTTP timeout for TSA POSTs.                                                           |

## RFC 3161 timestamping

When `AURA_TSA_URL` is set, every successful seal also fires a background
`spawn_blocking` task that:

1. Builds a SHA-256 `TimeStampReq` over the segment's `segment_chain_preimage`.
2. POSTs the request with `Content-Type: application/timestamp-query`.
3. On HTTP 200, persists the raw response bytes as
   `logs/segments/NNNNNN.tsr`.

The task is **fail-open**: network errors, TSA outages, malformed responses,
and missing `messageImprint` echoes are logged + counted via
`aura_tsa_request_failures_total`, but the service does not halt and the
sealed manifest itself remains valid. Operators who require strict
timestamp coverage can alert on the counter and re-stamp gaps offline.

### Issuance pipeline (v1.4)

- Hand-rolled DER encoder for `TimeStampReq` (RFC 3161 §2.4.1).
- Blocking HTTP submission via `ureq` (pure-Rust TLS via `rustls`).
- Opaque persistence of the `TimeStampResp` bytes.

### Strict verification (v1.5)

`aura-seal verify-tst --tsa-roots <operator-pinned-bundle.pem>` runs the
full RFC 3161 / RFC 5652 token validation:

1. Decode the outer `TimeStampResp` and check
   `PKIStatusInfo.status \u2208 {granted (0), grantedWithMods (1)}`.
2. Decode the inner CMS `SignedData`. Require `eContentType =
   id-ct-TSTInfo` (1.2.840.113549.1.9.16.1.4) and exactly one
   `SignerInfo`.
3. Decode the encapsulated `TSTInfo`. Require `version = 1` and
   `messageImprint == SHA-256(segment_chain_preimage)`. The expected
   imprint is recomputed from the matching manifest at verify time, so
   a TSR that has been swapped onto the wrong manifest is rejected.
4. Verify the `id-aa-contentType` and `id-aa-messageDigest` signed
   attributes. The latter must equal `digestAlg(eContent.value)` —
   any post-stamp mutation of the TSTInfo bytes breaks this check.
5. Verify the `signingCertificate` (RFC 2634, SHA-1) or
   `signingCertificateV2` (RFC 5816, SHA-256+) signed attribute against
   the SignerInfo's signer certificate — anti-substitution per
   RFC 5816 §3.
6. Re-encode `signedAttrs` as `SET OF` (per RFC 5652 §5.4), hash it,
   and verify the SignerInfo signature using the signer certificate's
   subjectPublicKey. Supported signature algorithms: RSA-PKCS1-v1.5
   with SHA-256/-384/-512, ECDSA on P-256 with SHA-256/-384/-512,
   ECDSA on P-384 with SHA-256/-384/-512.
7. Walk the certificate chain from the signer up through the embedded
   intermediate(s) until it terminates at one of the operator-pinned
   trust anchors loaded from the PEM bundle. The verifier fails if the
   chain reaches a self-signed certificate that is **not** in the
   pinned set.
8. Require the signer certificate to carry the
   `id-kp-timeStamping` Extended Key Usage
   (1.3.6.1.5.5.7.3.8) per RFC 3161 §2.3.
9. Require `genTime` to fall inside the signer certificate's
   `notBefore..notAfter` window.

The verifier is offline-only: it never opens a network socket and does
not perform CRL or OCSP lookups. Revocation is operationally enforced
by rotating the pinned trust-anchor bundle. Pure-Rust crates only
(`cms`, `x509-cert`, `der`, `rsa`, `p256`, `p384`).

### Backward-compatible imprint-only mode

`aura-seal verify-tst` without `--tsa-roots` performs only the
messageImprint check (the v1.4 behaviour). The CLI prints a one-line
stderr warning to make the operational posture explicit:

```
warning: imprint-only verification (no --tsa-roots provided);
         messageImprint will be checked but the TSA signature,
         certificate chain, and EKU will not be validated.
```

This is appropriate for early integrators who have not yet pinned a
TSA root. The strict mode is the production default.

### Operator workflow: pinning trust anchors

1. Download the root certificate(s) for every TSA you intend to use
   (e.g. `https://freetsa.org/files/cacert.pem`).
2. Concatenate them into a single PEM bundle:
   ```bash
   cat freetsa-cacert.pem digicert-tsa-root.pem > /etc/aura-guard/tsa-roots.pem
   ```
3. Mount the bundle read-only into the verifier (or commit it under
   `config/`). Rotate the file out of band when a TSA rolls its root.
4. Run periodic offline verification in your evidence pipeline:
   ```bash
   aura-seal verify-tst --segments /var/lib/aura-guard/segments \
     --tsa-roots /etc/aura-guard/tsa-roots.pem --json
   ```
   Exit code `6` indicates any failure; the JSON payload carries the
   per-segment `failure_reason`.

## Verifying segments offline

```bash
# Verify segment-chain linkage only (fast; no audit log needed).
aura-seal verify-chain --segments logs/segments

# Verify segment-chain AND that every manifest's Merkle root matches the
# corresponding slice of the audit log.
aura-seal verify --log logs/audit.jsonl --segments logs/segments

# Verify that each `.tsr` file's messageImprint matches the manifest it
# claims to stamp (imprint-only, v1.4 behaviour).
aura-seal verify-tst --segments logs/segments

# Strict RFC 3161 + PKIX verification against operator-pinned trust
# anchors. Exit code 6 on any failure with a concrete reason.
aura-seal verify-tst --segments logs/segments \
    --tsa-roots config/tsa-roots.pem --json

# Emit an inclusion proof for a specific entry as JSON.
aura-seal proof --log logs/audit.jsonl --segments logs/segments --seq 4242

# Verify segments alongside the per-entry chain in one pass.
aura-replay --log logs/audit.jsonl --verify-segments --segments-dir logs/segments
```

Exit codes (`aura-seal` / `aura-replay --verify-segments`):

| code | meaning                                                  |
| ---- | -------------------------------------------------------- |
| `0`  | success                                                  |
| `1`  | I/O error reading log or manifests                       |
| `2`  | per-entry chain break (`aura-replay`)                    |
| `3`  | lineage mismatch (`aura-replay --verify-lineage`)        |
| `4`  | segment-chain break or manifest self-hash mismatch       |
| `5`  | manifest's Merkle root does not match the audit log      |
| `6`  | TST verification failed (imprint, signature, chain, EKU, or genTime) |

## Threat model addendum

| Attack                                                | Detected by                                              |
| ----------------------------------------------------- | -------------------------------------------------------- |
| Tampering with a single audit entry                   | `aura-replay`                                            |
| Truncating the audit log mid-segment                  | `aura-seal verify`                                       |
| Replacing a sealed manifest with a forged one         | `aura-seal verify-chain` (segment self-hash)             |
| Deleting a sealed manifest                            | `aura-seal verify-chain` (id gap)                        |
| Reordering manifests                                  | `aura-seal verify-chain` (linkage)                       |
| Backdating a sealed manifest                          | `aura-seal verify-tst` (TSA-issued time)                 |
| TSA outage                                            | Service continues; counter `aura_tsa_request_failures_total` increments |

## Metrics

| Metric                                      | Type    | Description                                          |
| ------------------------------------------- | ------- | ---------------------------------------------------- |
| `aura_segments_sealed_total`                | counter | Segments closed since process start.                 |
| `aura_segment_entries_total`                | counter | Entries packed into closed segments.                 |
| `aura_segments_open_entries`                | gauge   | Entries currently in the open buffer.                |
| `aura_segments_seal_errors_total`           | counter | Errors raised by the sealer.                         |
| `aura_tsa_requests_total`                   | counter | Successful RFC 3161 stamps.                          |
| `aura_tsa_request_failures_total`           | counter | TSA submission failures (transport / HTTP / imprint).|
