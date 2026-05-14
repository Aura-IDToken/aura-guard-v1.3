# Exit codes

Aura-Guard binaries follow Unix conventions and `sysexits.h` where applicable.
Treat the table below as the contract that SOC playbooks, supervisors and CI
should be wired against.

| Code | Name | Binary | Meaning |
| ---: | --- | --- | --- |
| `0`  | success                  | all   | Normal exit / verification succeeded. |
| `1`  | runtime error            | all   | Unexpected I/O error, malformed log, missing file. |
| `2`  | `CHAIN BREAK DETECTED`   | `aura-replay` | The audit log's hash chain does not validate — an entry was inserted, removed, or mutated. |
| `3`  | `LINEAGE MISMATCH`       | `aura-replay --verify-lineage` | An on-disk policy YAML's SHA-256 no longer matches the `policy_hash` recorded with at least one audit entry. |
| `78` | `EX_CONFIG`              | `aura-guard` | The server refused to start because the bootstrap fail-closed gate was not satisfied (missing policy, invalid signature, unreadable trusted-signers file, missing API key, etc.). The HTTP listener was **never** bound. |

## How to wire this into supervisors

### systemd

```ini
[Service]
Restart=on-failure
RestartPreventExitStatus=78
```

`RestartPreventExitStatus=78` is critical: it stops a restart loop on a
fail-closed boot. Pair with an `OnFailure=` unit to page the on-call.

### Kubernetes

- Liveness probe: `/health` (returns `200 OK` while the process is up).
- Readiness probe: `/ready` (returns `503` while the audit log is halted).
- Exit code `78` will surface as `CrashLoopBackOff`; the recommended
  posture is **not** to auto-heal, because exit `78` means the policy
  enforcement boundary is incomplete and rolling back to the previous
  manifest is safer than starting up degraded.

### CI smoke tests

`scripts/replay-demo.sh` exits `0` only when `aura-replay` returned `2`
on a tampered log. That makes it safe to wire into CI:

```yaml
- name: replay demo
  run: ./scripts/replay-demo.sh
```

## Where each exit code is emitted

| Code | Source |
| --- | --- |
| `78` | [`src/main.rs`](../src/main.rs) `EX_CONFIG` constant, mapped via `BootError::Config` |
| `2`  | [`src/bin/aura_replay.rs`](../src/bin/aura_replay.rs) when `verify_chain` returns `Err` |
| `3`  | [`src/bin/aura_replay.rs`](../src/bin/aura_replay.rs) when `policy_hash` continuity check fails |
| `1`  | I/O errors during log read, trusted-signer load failures, malformed JSONL |
