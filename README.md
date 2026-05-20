# Aura-Guard

[![CI](https://github.com/Aura-IDToken/aura-guard-v1.3/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Aura-IDToken/aura-guard-v1.3/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.86%2B-orange.svg)](https://www.rust-lang.org)
[![Posture](https://img.shields.io/badge/posture-fail--closed-red.svg)](docs/THREAT_MODEL.md)

Deterministic audit middleware for AI systems. Produces an append-only,
hash-chained, signature-verified record of every decision the model made
against a frozen, signed rulebook. No ML, no cloud, no telemetry.

```
input + signed policy  →  decision + chain_hash  →  append-only JSONL
```

---

## Features

- **Deterministic engine.** Same `(input, policy)` always produces the
  same `(decision, chain_hash)`. No randomness, no external calls.
- **Hash-chained audit log.** Each entry pins the previous entry's hash;
  any byte-level mutation is detected by `aura-replay` (exit code `2`).
- **Merkle batching (RFC 6962).** Contiguous slices of the audit log are
  sealed into segment manifests with a Merkle root, a segment-chain
  digest, and `O(log N)` inclusion proofs via `aura-seal`.
- **Optional RFC 3161 timestamping.** Each sealed segment can be anchored
  to a public or operator-pinned TSA. Off by default, fail-open on TSA
  outages, no impact on the deterministic core.
- **Strict RFC 3161 verifier.** `aura-seal verify-tst --tsa-roots <pem>`
  performs full RFC 5652 SignedData + PKIX chain validation against an
  operator-pinned trust anchor, including `signingCertificate(V2)`
  binding and the `id-kp-timeStamping` EKU. Offline only — no CRL/OCSP.
- **Signed policies.** Ed25519 signatures over policy YAML bytes; loader
  fails closed on missing or invalid signatures.
- **Fail-closed startup.** Process exits with code `78` (`EX_CONFIG`)
  before binding the listener if any expected policy fails to load and
  verify.
- **Privacy by design.** Only SHA-256 hashes of prompt/response leave
  the host. Raw text is never written to the audit log.
- **Operational surface.** API-key auth (constant-time), body and
  timeout limits, `/health` `/ready` `/version`, Prometheus `/metrics`,
  structured JSON logs via `tracing`.

---

## Quickstart

Requires Rust 1.86+, `jq` for the smoke test, and (optionally) Docker.

```bash
git clone https://github.com/Aura-IDToken/aura-guard-v1.3.git
cd aura-guard-v1.3
./scripts/setup.sh                  # build + keygen + sign policy packs
export AURA_API_KEY=changeme
./target/release/aura-guard &       # start the server (foreground recommended in prod)
./scripts/test.sh                   # 6 golden smoke tests
./scripts/replay-demo.sh            # tamper-detection demo
```

Docker:

```bash
export AURA_API_KEY=changeme
docker compose -f deploy/docker-compose.yml up --build
```

---

## Demo

`scripts/replay-demo.sh` runs the chain-tamper demo in under 30 s:

1. Append a handful of audit entries (curl `POST /v1/audit`).
2. Run `aura-replay --log logs/audit.jsonl` → `CHAIN OK`.
3. Flip one byte in the JSONL (e.g. `"DENY"` → `"ALLOW"`).
4. Re-run `aura-replay` → `FAIL: CHAIN BREAK DETECTED at entry #N`,
   exit code **`2`**.

See [`docs/REPLAY_DEMO.md`](docs/REPLAY_DEMO.md) for the manual walk-through
and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the chain digest
formula.

---

## Threat model (summary)

| Threat | Mitigation |
| --- | --- |
| Operator silently edits the audit log | SHA-256 hash chain → `CHAIN BREAK` at exit code `2` |
| Operator silently relaxes a policy | Ed25519 signature required at load; policy hash is logged with every decision |
| Forging or reordering segment manifests | Segment-chain self-hash + linkage → exit code `4` from `aura-seal` |
| Replacing a manifest with a forged Merkle root | `aura-seal verify` compares the root against the audit log → exit code `5` |
| Backdating a sealed manifest | Optional RFC 3161 stamp → `aura-seal verify-tst` exit code `6` |
| Unauthorized API caller | API-key middleware with constant-time compare |
| Oversized / slow request DoS | 64 KiB body limit, 5 s timeout (both configurable) |
| Side-channel timing on the API key | Constant-time byte comparison |
| Audit log write failure | `halted` flag → API returns `503` until operator restart |
| Encoding bypass (homoglyph, ZWSP, fullwidth) | SHADOW normalizer (NFKC + hidden-char strip + confusable fold) |

Full STRIDE-style analysis: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

---

## Architecture

```
┌──────────────┐  POST /v1/audit  ┌──────────────────────────────────┐
│  AI system   │ ───────────────▶ │  Aura-Guard runtime              │
│  (caller)    │   API-key auth   │  ┌────────────────────────────┐  │
└──────────────┘                  │  │ body & timeout limits      │  │
                                  │  ├────────────────────────────┤  │
                                  │  │ Shadow normalizer (NFKC,   │  │
                                  │  │ strip, fold, lowercase)    │  │
                                  │  ├────────────────────────────┤  │
                                  │  │ Decision engine            │  │
                                  │  │ (rule match + validators)  │  │
                                  │  ├────────────────────────────┤  │
                                  │  │ Hash-chained log writer    │  │
                                  │  │ (mutex + fsync, halt-on-   │  │
                                  │  │  write-fail)               │  │
                                  │  └─────────────┬──────────────┘  │
                                  └────────────────┼─────────────────┘
                                                   ▼
                                       logs/audit.jsonl  (JSONL)
                                                   │
                                                   ▼
                                          ┌──────────────────┐
                                          │  aura-replay     │
                                          │  (offline CLI)   │
                                          │  - chain check   │
                                          │  - lineage check │
                                          └──────────────────┘
```

Component reference: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
Architecture decisions: [`docs/adrs/`](docs/adrs/).

---

## API surface

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `POST` | `/v1/audit` | API key | Evaluate one interaction. Returns the audit entry. |
| `GET`  | `/health`   | public  | Liveness probe. |
| `GET`  | `/ready`    | public  | Readiness — returns `503` when audit log is halted. |
| `GET`  | `/version`  | public  | Build version, genesis hash, signature-enforcement flag. |
| `GET`  | `/metrics`  | public  | Prometheus exposition. |

OpenAPI 3.0 spec: [`docs/openapi.yaml`](docs/openapi.yaml).

---

## Exit codes

| Code | Meaning | When |
| --- | --- | --- |
| `0` | success | normal exit / verification OK |
| `1` | runtime error | unexpected I/O failure, malformed log |
| `2` | `CHAIN BREAK DETECTED` | `aura-replay` detected a mutated entry |
| `3` | `LINEAGE MISMATCH` | `aura-replay --verify-lineage` saw an on-disk policy hash that no longer matches the logged provenance |
| `4` | `SEGMENT CHAIN BREAK` | `aura-seal` / `aura-replay --verify-segments` detected a tampered or missing manifest |
| `5` | `LOG/MANIFEST MISMATCH` | A manifest's Merkle root does not match the audit-log slice it claims to cover |
| `6` | `TST INVALID` | `aura-seal verify-tst` rejected an RFC 3161 token (imprint, signature, chain, EKU, or genTime) |
| `78` | `EX_CONFIG` | `aura-guard` refused to start — see structured `BOOT FAIL` log line |

systemd: set `RestartPreventExitStatus=78` so a fail-closed boot stops the
restart loop and triggers an alert. Kubernetes: treat `78` as a hard
`CrashLoopBackOff` signal, do not auto-heal.

Full reference: [`docs/exit-codes.md`](docs/exit-codes.md).

---

## Benchmarks

Single audit request, release build, Linux x86_64, in-process router via
`tower::ServiceExt::oneshot`:

| Scenario | Median latency | Throughput (single core) |
| --- | --- | --- |
| Clean request, finance-v1, 256 B body | ~120 µs | ~8 000 req/s |
| Tamper case, finance-v1 (Luhn-valid CC) | ~140 µs | ~7 100 req/s |
| `aura-replay` on 10 000-entry log | ~85 ms | — |

Numbers are illustrative — re-run on your hardware with
`cargo bench` once a Criterion harness ships (planned for v1.4).

---

## Deployment

### Docker (recommended for staging)

```bash
docker compose -f deploy/docker-compose.yml up --build
```

The image is a distroless multi-stage build. Policies are mounted
read-only, logs are mounted read-write. See
[`deploy/Dockerfile`](deploy/Dockerfile).

### systemd

A hardened unit file with `ProtectSystem=strict`, `NoNewPrivileges=yes`,
`CapabilityBoundingSet=`, etc. ships in
[`deploy/systemd/aura-guard.service`](deploy/systemd/aura-guard.service).
Set `RestartPreventExitStatus=78` so the fail-closed boot path is honoured.

### Kubernetes

Treat as a stateless container with a writable `emptyDir` (or PVC) for the
audit log. Wire `/health` to `livenessProbe` and `/ready` to
`readinessProbe`. Helm chart and operator are tracked for v1.5
([`docs/ROADMAP.md`](docs/ROADMAP.md)).

Full guide: [`docs/deployment.md`](docs/deployment.md).

---

## Configuration

All keys are environment variables prefixed `AURA_`.

| Variable | Default | Notes |
| --- | --- | --- |
| `AURA_BIND` | `127.0.0.1:8080` | Listen address. |
| `AURA_API_KEY` | _(required)_ | API key (sent on `X-API-Key` or `Authorization: Bearer`). |
| `AURA_AUTH_DISABLED` | `false` | Disables auth + signature enforcement. Dev/test only. |
| `AURA_POLICIES_DIR` | `policies` | Where signed YAML packs live. |
| `AURA_TRUSTED_SIGNERS_FILE` | `policies/trusted_signers.json` | Signer-ID → Ed25519 pubkey map. |
| `AURA_DEFAULT_POLICY_SET` | `finance-v1` | Used when the request omits `policy_set`. |
| `AURA_AUDIT_LOG_PATH` | `logs/audit.jsonl` | Append-only JSONL audit log. |
| `AURA_MAX_BODY_BYTES` | `65536` | Per-request body size limit. |
| `AURA_REQUEST_TIMEOUT_MS` | `5000` | Per-request timeout. |
| `AURA_METRICS_ENABLED` | `true` | Enables `/metrics`. |
| `AURA_ALLOWED_ORIGINS` | _(empty)_ | Comma-separated CORS allow-list. Empty = no CORS header (same-origin only). Wildcards intentionally unsupported. |
| `AURA_LOG` | `info` | `tracing` filter (e.g. `aura_guard=debug`). |
| `AURA_SEGMENTS_DIR` | `logs/segments` | Where segment manifests and `.tsr` files are written. |
| `AURA_SEGMENT_SIZE` | `1000` | Entries per segment. `0` disables size-based sealing. |
| `AURA_SEGMENT_INTERVAL_SECONDS` | `60` | Max wall-clock age of an open segment. `0` disables time-based sealing. |
| `AURA_TSA_URL` | _(unset)_ | Optional RFC 3161 TSA endpoint. Unset = no network requests. |
| `AURA_TSA_TIMEOUT_SECONDS` | `10` | HTTP timeout for TSA POSTs. |

---

## Security model

- **Memory safety.** `#![forbid(unsafe_code)]` across all binaries.
- **Authentication.** Required by default. Constant-time compare on the
  API key. Combine with mTLS at your reverse proxy in production.
- **Authorization.** Policies are the only thing that grants `ALLOW`;
  they must carry a valid Ed25519 signature from a key listed in
  `trusted_signers.json`.
- **Integrity.** Audit log is SHA-256 chained from a canonical genesis
  hash; `aura-replay` will detect any byte-level mutation.
- **Confidentiality.** Raw prompt/response text is never persisted —
  only `input_hash` and `shadow_hash` go to disk.
- **Availability.** Halt-on-log-failure: a single write error flips a
  flag, the API returns `503`, the operator must restart.

Disclosure policy: [`SECURITY.md`](SECURITY.md).

---

## CLIs

```
aura-guard          # HTTP server
aura-replay         # offline chain + lineage + segment verifier
aura-seal           # offline Merkle / segment-chain / TST verifier + proof generator
aura-sign-policy    # Ed25519 keygen + policy signing
```

`aura-replay` modes:

```
aura-replay --log logs/audit.jsonl                       # chain integrity (default)
aura-replay --log logs/audit.jsonl --verify-lineage      # + policy-hash continuity
aura-replay --log logs/audit.jsonl --verify-segments \
            --segments-dir logs/segments                 # + segment-chain + Merkle
aura-replay --log logs/audit.jsonl --json                # machine-readable output
```

`aura-seal` modes:

```
aura-seal verify-chain --segments logs/segments         # segment-chain linkage only
aura-seal verify --log logs/audit.jsonl --segments logs/segments  # + Merkle vs. log
aura-seal proof --log logs/audit.jsonl --segments logs/segments --seq N
aura-seal verify-tst --segments logs/segments [--segment-id N]
aura-seal verify-tst --segments logs/segments --tsa-roots config/tsa-roots.pem  # strict PKIX
```

`--verify-lineage` reloads each policy YAML referenced by the log and
verifies the on-disk SHA-256 still matches the `policy_hash` recorded at
evaluation time. It does **not** re-evaluate the model — by design the
raw prompt is never logged (GDPR data minimization). The deprecated
`--recompute` alias is kept for backward compatibility and prints a
stderr warning.

---

## Project layout

```
aura-guard-v1.3/
├── src/                       # runtime + CLIs
│   ├── api/{audit,health,mod}.rs
│   ├── bin/{aura_replay,aura_sign_policy}.rs
│   ├── auth.rs                # API-key middleware (constant-time)
│   ├── chain.rs               # hash chain construction + verification
│   ├── config.rs              # AURA_* env config
│   ├── crypto.rs              # SHA-256 + Ed25519 verify
│   ├── engine.rs              # decision engine
│   ├── log_writer.rs          # append-only JSONL + halt-on-failure
│   ├── normalizer.rs          # SHADOW_SPEC v1.0
│   ├── policy.rs              # YAML loader + signature verify
│   └── validators.rs          # Luhn / PESEL / IBAN
├── tests/                     # unit, golden, HTTP integration, bootstrap
├── policies/                  # signed YAML packs (finance / medtech / hr-bias)
├── examples/                  # canonical request bodies
├── scripts/                   # setup / test / replay-demo
├── docs/                      # architecture, threat model, ADRs, OpenAPI
├── deploy/                    # Dockerfile, docker-compose, systemd
└── .github/workflows/         # CI: build / fmt / clippy / test / audit / deny / SBOM
```

---

## Documentation

| File | Purpose |
| --- | --- |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Components, data flow, chain digest formula. |
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | STRIDE-style threat catalog + mitigations. |
| [`docs/policy-signing.md`](docs/policy-signing.md) | Ed25519 signing model, key custody, rotation. |
| [`docs/REPLAY_DEMO.md`](docs/REPLAY_DEMO.md) | 5-minute hands-on replay & tamper demo. |
| [`docs/segments-and-timestamping.md`](docs/segments-and-timestamping.md) | Merkle segments, manifest schema, RFC 3161 walkthrough. |
| [`docs/exit-codes.md`](docs/exit-codes.md) | Canonical exit-code contract for supervisors. |
| [`docs/deployment.md`](docs/deployment.md) | Docker / systemd / Kubernetes runbooks. |
| [`docs/COMPLIANCE_BRIEF.md`](docs/COMPLIANCE_BRIEF.md) | EU AI Act / DORA / GDPR mapping. |
| [`docs/openapi.yaml`](docs/openapi.yaml) | OpenAPI 3.0 schema for `/v1/audit`. |
| [`docs/adrs/`](docs/adrs/) | Architecture Decision Records. |

---

## Roadmap

| Release | Theme | Status |
| --- | --- | --- |
| v1.3 | Bootstrap fail-closed gate, lineage verification, distroless image | shipped |
| v1.4 | Merkle batching (RFC 6962) + optional RFC 3161 timestamping, `aura-seal` CLI | shipped |
| v1.5 | Full PKIX `.tsr` verification (RFC 3161 / RFC 5652 / RFC 5816) | shipped |
| v1.6 | Helm chart, Kubernetes operator, HSM signing, cosign release attestations, OTLP exporter | planned |
| v2.0 | Binary evidence envelope, cross-language verifiers, formal verification | planned |

Full breakdown: [`docs/ROADMAP.md`](docs/ROADMAP.md).

---

## License

[MIT](LICENSE).
