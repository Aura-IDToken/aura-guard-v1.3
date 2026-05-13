# Architecture — Aura-Guard v1.3

## Bootstrap fail-closed gate

Before Aura-Guard binds a single TCP socket it walks the
`EXPECTED_POLICIES` list defined in [`src/api/mod.rs`](../src/api/mod.rs)
and attempts to load + signature-verify every entry. Any failure exits
the process with code **`78`** (`sysexits.h::EX_CONFIG`). At runtime
`resolve_policy` is **cache-only** — it will never lazy-load a policy
from disk in response to a request. This is the constitutional invariant
that eliminates the "the server is up but the rulebook isn't" temporal
integrity gap; supervisors should treat exit 78 as a hard alert rather
than part of a restart loop.


```
┌─────────────────┐    HTTP/JSON      ┌────────────────────────────────┐
│  AI Application │ ────────────────▶ │       Aura-Guard runtime        │
│  (LLM / agent)  │                   │                                │
└─────────────────┘                   │  ┌──────────────────────────┐  │
                                      │  │  /v1/audit (axum)        │  │
                                      │  │  + API-key middleware    │  │
                                      │  │  + body & timeout limits │  │
                                      │  └────────────┬─────────────┘  │
                                      │               ▼                │
                                      │  ┌──────────────────────────┐  │
                                      │  │ Shadow Normalizer        │  │
                                      │  │  NFKC ▸ strip ▸ fold     │  │
                                      │  │  ▸ lowercase             │  │
                                      │  └────────────┬─────────────┘  │
                                      │               ▼                │
                                      │  ┌──────────────────────────┐  │
                                      │  │ Decision Engine          │  │
                                      │  │  rules + validators      │  │
                                      │  │  DENY > REVIEW > ALLOW   │  │
                                      │  └────────────┬─────────────┘  │
                                      │               ▼                │
                                      │  ┌──────────────────────────┐  │
                                      │  │ Hash-Chained Log Writer  │  │
                                      │  │  parking_lot + fsync     │  │
                                      │  │  halt-on-write-fail      │  │
                                      │  └────────────┬─────────────┘  │
                                      │               ▼                │
                                      │   logs/audit.jsonl (JSONL)     │
                                      │   - schema, seq, audit_id      │
                                      │   - input_hash, shadow_hash    │
                                      │   - policy_hash (provenance)   │
                                      │   - prev_hash + chain_hash     │
                                      │                                │
                                      │   policies/                    │
                                      │   - <pack>.yaml                │
                                      │   - <pack>.yaml.sig    Ed25519 │
                                      │   - <pack>.yaml.signer         │
                                      │   - trusted_signers.json       │
                                      │                                │
                                      │   metrics, traces (stdout JSON)│
                                      └────────────────────────────────┘
                                                       │
                                                       ▼
                                              ┌─────────────────┐
                                              │  aura-replay    │
                                              │  (offline CLI)  │
                                              │  - chain check  │
                                              │  - policy hash  │
                                              │    continuity   │
                                              └─────────────────┘
```

## Trust zones

| Zone | Components | Trust assumption |
| --- | --- | --- |
| **Untrusted Input** | request body (`context`, `prompt`, `response`) | arbitrary user/LLM content; may contain bypass payloads |
| **Aura-Guard Core** | normalizer + engine + log writer | memory-safe Rust (`#![forbid(unsafe_code)]`); reviewed for ReDoS and panic paths |
| **Evidence Store** | `logs/audit.jsonl` + `policies/` | append-only filesystem; mounting on WORM/RO storage further hardens |
| **Verifier** | `aura-replay` CLI + trusted signer keys | reproduces decisions off-line, even on a different host |

## SHADOW_SPEC v1.0 (strict ordered pipeline)

1. UTF-8 validation (implicit — Rust `&str`).
2. Unicode NFKC composition.
3. Hidden-character stripping (ZWSP, BOM, soft hyphen, bidi marks, word
   joiners, …) — see `src/normalizer.rs::HIDDEN_CHARS`.
4. Confusable folding (Cyrillic / Greek look-alikes, fullwidth Latin and
   digits) — see `src/normalizer.rs::fold_confusables`.
5. ASCII lowercase.

The original (untouched) input is hashed for the evidence record so the
shadow path **never** mutates the on-disk audit data.

## Hash-chain digest (`chain.rs`)

```text
chain_hash = SHA-256( prev_hash | decision | policy_set | policy_hash
                     | context | input_hash | shadow_hash | seq | timestamp )
```

`prev_hash` of entry #0 is the canonical
`SHA-256("AURA-GUARD-GENESIS-v1.3")`. The genesis hash is published in
[`/version`](#) and pinned in the `chain.rs` unit test so any unintended
change is caught immediately.

## Policy provenance

Every audit entry stores `policy_hash` = SHA-256 of the YAML bytes that were
actually evaluated. `aura-replay --verify-lineage` reloads each referenced
YAML, recomputes its SHA-256, and aborts with exit code 3
(`LINEAGE MISMATCH`) the moment any on-disk file diverges from the value
stored in the log. `--recompute` is preserved as a deprecated alias and
emits a one-time stderr warning.
