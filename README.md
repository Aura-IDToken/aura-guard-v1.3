# Aura-Guard v1.3 — Tamper-Evident AI Decision Lineage

[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-pilot--ready-blue)]()
[![Posture](https://img.shields.io/badge/posture-fail--closed-red)]()

Aura-Guard is a **deterministic evidence protocol for AI systems**: an
append-only, cryptographically chained, replay-verifiable record of every
decision the model made and every policy that was in force at the time.
It is not a model. It does not use ML. It does not call out to the cloud.
It is the **forensic substrate** that lets auditors move from *"trust us"*
to *"verify us"*.

Think of it as the **black-box recorder** for high-risk AI: it does not stop
the airplane, it makes sure the next person who looks at it can prove what
happened, in what order, against which rulebook, with mathematical continuity.

> *Input (A) + Policy (P) → Decision (D) + Hash (H) — every time.*

### Bootstrap fail-closed contract

On startup **every** policy listed in `EXPECTED_POLICIES` must load and
signature-verify successfully. Any failure terminates the process with
exit code **`78`** (`sysexits.h::EX_CONFIG`) **before** the HTTP listener
is bound. There is no "warn and lazy-load on first request" path — that
would create a temporal integrity gap during which the runtime would be
online but the policy enforcement boundary would not yet be fully
populated. The decision engine refuses to evaluate against any policy
that was not pre-loaded and checksummed at boot.

See [`src/main.rs`](src/main.rs) (`run()` → *Bootstrap fail-closed gate*)
and [`tests/bootstrap_fail_closed.rs`](tests/bootstrap_fail_closed.rs).

## What you get in v1.3 "Atom-Grade"

| Pillar | v1.2 | **v1.3** |
| --- | --- | --- |
| Case-handling | broken (silently drops uppercase regex) | **Shadow normalizer + (?i) regex (preserves original for hash)** |
| PII validators | regex-only (lots of false-positives) | **Luhn, PESEL, IBAN mod-97** |
| Audit log | per-entry SHA-256 | **SHA-256 hash chain seeded by canonical genesis hash** |
| Tamper detection | manual | **`aura-replay` CLI (exit 2 on `CHAIN BREAK`)** |
| Policy integrity | none | **Ed25519 signature verification (fail-closed)** |
| AuthN | none | **API key (`X-API-Key` / `Bearer`) with constant-time compare** |
| Body / timeout limits | none | **64 KiB / 5 s (configurable)** |
| Observability | `eprintln!` | **`tracing` JSON + Prometheus `/metrics`** |
| Health checks | none | **`/health`, `/ready`, `/version`** |
| Tests | 0 unit, 6 unchecked e2e | **20+ unit, 9 golden, 6 HTTP integration** |
| CI | none | **GitHub Actions: build / fmt / clippy -D warnings / test / audit / deny / SBOM** |
| Supply chain | none | **Cargo.lock committed, `cargo-deny`, `cargo-audit`, CycloneDX SBOM** |
| Container | none | **Distroless multi-stage Docker image** |

## Quick start

```bash
# 1. Build + generate signing key + sign all policy packs
./scripts/setup.sh

# 2. Run the server (export the API key first)
export AURA_API_KEY=changeme
./target/release/aura-guard

# 3. In another shell — run the smoke tests
./scripts/test.sh

# 4. Show the killer feature — tamper detection
./scripts/replay-demo.sh
```

## API surface

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| POST | `/v1/audit` | API key | Evaluate one AI interaction. Returns the audit entry (decision + chain). |
| GET  | `/health`   | — | Liveness probe. |
| GET  | `/ready`    | — | Readiness probe (503 when audit log halted). |
| GET  | `/version`  | — | Build version + genesis hash. |
| GET  | `/metrics`  | — | Prometheus scrape endpoint. |

### Request schema

```json
{
  "context": "Finance Bot",
  "policy_set": "finance-v1",
  "payload": {
    "prompt": "Send EUR 100 to PL61109010140000071219812874.",
    "response": "Need beneficiary KYC first."
  }
}
```

### Response / log-entry schema

```json
{
  "schema": "aura-guard.audit.v1",
  "seq": 42,
  "audit_id": "5be3...",
  "timestamp": "2026-05-12T22:30:00+00:00",
  "decision": "DENY",
  "policy_set": "finance-v1",
  "policy_hash": "9f2c...",
  "context": "Finance Bot",
  "input_hash": "ab12...",
  "shadow_hash": "cd34...",
  "violations": [{ "rule": "iban-pl", "action": "deny", "confidence": 1.0, "validator": "iban" }],
  "prev_hash": "...",
  "chain_hash": "..."
}
```

## Configuration (`AURA_*` env vars)

| Variable | Default | Notes |
| --- | --- | --- |
| `AURA_BIND` | `127.0.0.1:8080` | Listen address. |
| `AURA_API_KEY` | *(required)* | Required unless `AURA_AUTH_DISABLED=true`. |
| `AURA_AUTH_DISABLED` | `false` | Disables API-key + policy-signature enforcement (dev/test only). |
| `AURA_POLICIES_DIR` | `policies` | Where YAML packs live. |
| `AURA_TRUSTED_SIGNERS_FILE` | `policies/trusted_signers.json` | Signer ID → pubkey map. |
| `AURA_DEFAULT_POLICY_SET` | `finance-v1` | Used when the request omits `policy_set`. |
| `AURA_AUDIT_LOG_PATH` | `logs/audit.jsonl` | Append-only JSONL audit log. |
| `AURA_MAX_BODY_BYTES` | `65536` | Per-request body size limit. |
| `AURA_REQUEST_TIMEOUT_MS` | `5000` | Per-request timeout. |
| `AURA_METRICS_ENABLED` | `true` | Enables `/metrics`. |
| `AURA_LOG` | `info` | `tracing` filter (e.g. `aura_guard=debug`). |

## CLIs shipped

```
aura-guard          # the HTTP server
aura-replay         # offline chain verifier (exit 2 on CHAIN BREAK, exit 3 on LINEAGE MISMATCH)
aura-sign-policy    # keygen + sign YAML policies (Ed25519)
```

`aura-replay` understands two verification modes:

```
aura-replay --log logs/audit.jsonl                       # chain integrity only
aura-replay --log logs/audit.jsonl --verify-lineage      # + policy-hash continuity
```

`--verify-lineage` reloads the policy YAML each entry was evaluated against
and verifies the on-disk SHA-256 still matches the `policy_hash` stored
at the time. It does **not** re-evaluate decisions — the raw prompt and
response never enter the log by design (GDPR data minimization). What it
proves is *cryptographic continuity* between the policy that was applied
in production and the policy currently sitting on disk.

## Docker

```bash
docker build -f deploy/Dockerfile -t aura-guard:1.3 .
docker run --rm -p 8080:8080 \
    -e AURA_API_KEY=changeme \
    -v $PWD/policies:/app/policies:ro \
    -v $PWD/logs:/app/logs \
    aura-guard:1.3
```

## Project layout

```
aura-guard-v1.3/
├── src/                   # runtime engine, CLIs
│   ├── api/{audit,health,mod}.rs
│   ├── bin/{aura_replay, aura_sign_policy}.rs
│   ├── auth.rs            # API key middleware (constant-time)
│   ├── chain.rs           # hash chain construction + verification
│   ├── config.rs          # AURA_* env config
│   ├── crypto.rs          # SHA-256 + Ed25519 verify
│   ├── engine.rs          # deterministic decision engine
│   ├── log_writer.rs      # append-only JSONL, halt-on-log-failure
│   ├── metrics.rs         # Prometheus
│   ├── models.rs          # DTOs + log entry
│   ├── normalizer.rs      # SHADOW_SPEC v1.0
│   ├── policy.rs          # YAML loader + signature verify
│   └── validators.rs      # Luhn / PESEL / IBAN
├── policies/              # YAML packs + .sig + .signer
├── examples/              # canonical request bodies for demos and tests
├── tests/                 # unit / golden / HTTP integration
├── docs/                  # ARCH, COMPLIANCE, THREAT_MODEL, ROADMAP, ADRs, OpenAPI
├── deploy/                # Dockerfile, docker-compose, systemd unit
├── scripts/               # setup.sh / test.sh / replay-demo.sh
├── reports/               # PDF generator (board summary)
└── .github/workflows/     # CI (build / lint / test / audit / deny / SBOM)
```

## Positioning

| Aura-Guard *is* | Aura-Guard is *not* |
| --- | --- |
| Tamper-evident decision lineage | An "AI firewall" |
| Forensic AI middleware | A moderation model |
| Compliance / audit infrastructure | A prompt-injection classifier |
| A cryptographic evidence protocol | A generic API gateway |
| Black-box recorder for regulated AI | A heuristic content filter |

The value is not feature breadth. The value is **mathematically provable
decision continuity** against a frozen, signed rulebook, with a privacy-
preserving evidence chain that anyone with the CLI can independently verify.

## Roadmap

See [`docs/ROADMAP.md`](docs/ROADMAP.md). Highlights:

* **v1.4** — Merkle batching, cosign-signed releases, OpenTelemetry traces, mTLS.
* **v1.5** — Helm chart, Kubernetes operator, HSM signing, governance UI.
* **v2.0** — Atom-Grade evidence envelopes (`EVIDENCE_SPEC v1.1`), formal verification of the engine, certified WORM storage adapters.

## Documentation

* [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — components, data flow, evidence chain.
* [`docs/COMPLIANCE_BRIEF.md`](docs/COMPLIANCE_BRIEF.md) — EU AI Act, DORA, GDPR mapping.
* [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — STRIDE-style threat catalog + mitigations.
* [`docs/REPLAY_DEMO.md`](docs/REPLAY_DEMO.md) — the 5-minute "tamper detection" demo.
* [`docs/openapi.yaml`](docs/openapi.yaml) — OpenAPI 3.0 schema for `/v1/audit`.
* [`docs/adrs/`](docs/adrs/) — Architecture Decision Records.
* [`SECURITY.md`](SECURITY.md) — disclosure policy and security guarantees.

## License

MIT — see [`LICENSE`](LICENSE).
