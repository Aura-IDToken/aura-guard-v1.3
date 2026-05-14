# Replay Demo

A five-minute walk-through of chain integrity, bootstrap fail-closed, and
lineage continuity. Each step is also runnable end-to-end via
[`scripts/replay-demo.sh`](../scripts/replay-demo.sh).

## Prerequisites

```bash
./scripts/setup.sh             # build + sign policies
export AURA_API_KEY=changeme
./target/release/aura-guard &  # run server in background
```

## Step 1 — Happy path audit

```bash
curl -s -X POST http://127.0.0.1:8080/v1/audit \
     -H "X-API-Key: ${AURA_API_KEY}" \
     -H 'Content-Type: application/json' \
     -d @examples/request-finance-cc.json | jq '.decision, .chain_hash'
```

Expected: `"DENY"` and a 64-hex chain hash.

## Step 2 — Chain check (everything intact)

```bash
./target/release/aura-replay --log logs/audit.jsonl
```

Expected output: `CHAIN OK — head_chain_hash: <hash>` and exit code 0.

## Step 3 — Tamper detection

```bash
sed -i 's/"decision":"DENY"/"decision":"ALLOW"/' logs/audit.jsonl   # rewrite history

./target/release/aura-replay --log logs/audit.jsonl                 # re-verify
echo "exit code: $?"
```

Expected output:

```
FAIL: CHAIN BREAK DETECTED at entry #N: expected prev_hash=..., got ...
exit code: 2
```

This proves that **any** mutation — even a one-letter flip — breaks the
cryptographic chain. Auditors no longer need to trust the operator's word.

## Step 4 — Policy integrity (runtime)

```bash
echo "# tampered" >> policies/finance-v1.yaml          # silently weaken a rule
./target/release/aura-guard                            # restart the server
echo "exit code: $?"
```

Expected:

```
BOOT FAIL: refusing to start ... policy "finance-v1" failed to load at boot: ...
exit code: 78
```

This proves two things at once:

1. **Admins cannot silently weaken policies** — the Ed25519 signature
   binding against `trusted_signers.json` catches any byte-level change.
2. **The runtime refuses to operate with an incomplete enforcement
   boundary.** Exit code `78` is `sysexits.h::EX_CONFIG` — supervisors
   (systemd, Kubernetes liveness) should treat it as a hard alert, not
   as a restart loop.

## Step 5 — Lineage continuity (offline)

```bash
# Restore the unsigned-but-correct policy first so the chain check passes,
# then verify that on-disk policy hashes still match the log provenance:
./target/release/aura-replay --log logs/audit.jsonl --verify-lineage
echo "exit code: $?"
```

Expected on a clean log:

```
CHAIN OK — head_chain_hash: <hash>
LINEAGE OK — every policy_hash on disk matches the logged provenance
exit code: 0
```

If any policy file has been swapped or re-issued since the audit entry
was written, the CLI aborts with `LINEAGE MISMATCH` (exit 3). The
legacy `--recompute` alias still works but prints a deprecation warning
to stderr; switch your audit playbooks to `--verify-lineage`.

## Operational summary

* **Tamper detection is mechanical, not heuristic.** A one-byte edit
  invalidates every subsequent `chain_hash`; auditors only need the CLI
  and the published genesis hash to verify a captured log.
* **Policy tampering is caught at boot.** Exit code `78` is the
  contract; supervisors should treat it as a hard alert and not as part
  of a restart loop.
* **Lineage continuity is verifiable off-line.** `--verify-lineage`
  compares the on-disk policy hash against the value stored in the log
  and exits `3` on mismatch. The deprecated `--recompute` alias still
  works and prints a stderr warning.
