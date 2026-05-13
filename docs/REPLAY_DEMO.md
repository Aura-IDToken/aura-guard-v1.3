# Replay Demo — 5-minute "trust but verify"

This is the demo script from `03_ARCHITECTURE_DEMO_GUIDE_v1.3`, fully
automated by [`scripts/replay-demo.sh`](../scripts/replay-demo.sh).

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

## Step 3 — Tamper detection (the killer feature)

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

## Talking points

* "Aura-Guard isn't a content filter — it's the **black-box recorder**
  for high-risk AI."
* "What we generate is **tamper-evident decision lineage**: a regulator
  with our CLI and our published genesis hash can verify every decision
  without trusting us at all."
* "This is **Atom-Grade Trust**: deterministic, reproducible, lineage-
  verifiable. The boot path is fail-closed and the verifier exit codes
  are designed to fit into SOC / SIEM playbooks unchanged."
