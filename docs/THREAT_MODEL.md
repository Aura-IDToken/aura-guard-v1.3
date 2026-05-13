# Threat Model — Aura-Guard v1.3

## 1. Trust boundaries

| Boundary | Untrusted side | Trusted side |
| --- | --- | --- |
| HTTP API | upstream LLM / orchestrator | `axum` handlers (auth + body limit) |
| Filesystem | operator-controlled `policies/` | `policy.rs` loader (Ed25519 verify) |
| Audit log | append-only JSONL on disk | `log_writer.rs` (mutex + fsync) |
| Replay CLI | offline reader | `aura-replay` (no side effects) |

## 2. Protected assets

1. **Audit log integrity** — once a decision is recorded it cannot be altered
   or deleted without detection.
2. **Policy authenticity** — only signed policies govern decisions.
3. **Decision reproducibility** — given the same input + policy, every host
   produces the same decision and chain digest.
4. **Privacy** — raw prompt / response content never appears in the log.

## 3. STRIDE table

| Category | Threat | Mitigation |
| --- | --- | --- |
| **S**poofing | Unauthorized client calls `/v1/audit` | `X-API-Key` / `Bearer` middleware with constant-time compare. Recommend mTLS at the reverse proxy. |
| **T**ampering | Operator edits `logs/audit.jsonl` | Hash chain over canonical fields, seeded by genesis hash; any mutation flagged as `CHAIN BREAK`. |
| **T**ampering | Operator silently relaxes a policy | Ed25519 signature required at load; signer ID stored in `policies/<name>.yaml.signer`. |
| **R**epudiation | Operator denies a decision occurred | `seq + audit_id + chain_hash` plus optional WORM mount. |
| **I**nformation Disclosure | Audit log leaks prompts | Only SHA-256 hashes of prompt/response are persisted; raw text is not logged. |
| **I**nformation Disclosure | Side-channel via timing | API key compare is constant-time. |
| **D**enial of Service | Oversized request bodies | `tower-http` `RequestBodyLimit` (64 KiB default). |
| **D**enial of Service | Slowloris / hung requests | `tower-http` `TimeoutLayer` (5 s default). |
| **D**enial of Service | ReDoS via crafted prompt | Patterns are pre-compiled once, evaluated under a request-level timeout; rules can use length-bounded quantifiers. |
| **D**enial of Service | Audit log fills disk | `halted` flag flips on first write failure → 503 across the API, manual recovery required. |
| **E**levation of Privilege | Arbitrary policy injection | Loader rejects YAML without a matching `.sig`+`.signer` triple. |

## 4. Bypass-resistance

Detection must survive these specific evasion attempts:

| Evasion | Detection |
| --- | --- |
| Zero-width spaces between digits (`4111\u200B-1111...`) | Hidden-character strip in shadow normalizer |
| Fullwidth Latin / digits (`ＰＬ６１…`) | Confusable folding |
| Cyrillic / Greek homoglyphs (`АEUTDEFF`, `р` for `p`) | Confusable folding |
| Mixed case (`Pl61109010140...`) | `(?i)` regex |
| Decomposed Unicode (`cafe\u0301`) | NFKC composition |
| 11-digit number that is **not** a PESEL | PESEL checksum validator |
| 16-digit number that is **not** a CC | Luhn validator |
| IBAN with wrong check digits | mod-97 validator |

Each row is covered by a regression test in `tests/golden.rs` /
`src/normalizer.rs::tests`.

## 5. Explicit non-goals

* Semantic AI intent detection (ML).
* Hallucination scoring.
* Network-layer DDoS (deploy behind a WAF / load balancer).
* TPM / HSM key custody (planned for v1.5 / v2.0 — see ROADMAP).
* Encrypted prompt/response retention (planned for v1.4 — see ROADMAP).

## 6. Residual risks

1. **Operator-supplied YAML** — a maliciously crafted but correctly-signed
   policy could embed catastrophic regex. Mitigation: maintain a "policy
   review" workflow with at least two distinct signer IDs.
2. **Key compromise** — a leaked signer key allows arbitrary policy
   injection. Mitigation: store signer keys in an HSM, rotate quarterly,
   monitor `policy_hash` for unexpected changes.
3. **Side-channel timing on regex** — partially mitigated by length-bounded
   quantifiers; the full ReDoS-resistant DFA pass is roadmap v1.4.
