# Compliance Brief — Aura-Guard v1.3

## 1. Overview

Aura-Guard v1.3 is a **tamper-evident decision-lineage protocol for AI
systems** — a deterministic, fail-closed evidence layer, not a content
filter and not a security platform. It produces an append-only,
cryptographically chained record of every decision and the exact signed
policy that was in force at the time, so a regulator or independent
auditor can verify what happened, in what order, against which rulebook,
without having to trust either the operator or the vendor.

It provides:

* **Reproducibility** — identical (input, policy) → identical (decision, hash).
* **Non-repudiation** — every audit entry is linked to the previous one via
  SHA-256 hash chain seeded by a canonical genesis hash.
* **Provenance** — each entry records the SHA-256 of the YAML policy that
  was actually evaluated.
* **Authenticity** — policies must carry a valid Ed25519 signature from a
  trusted signer; loading fails-closed otherwise.
* **Bootstrap continuity** — the binary refuses to start (exit `78`,
  `EX_CONFIG`) if any expected policy fails to load and signature-verify
  at boot. There is no lazy-load path — the enforcement boundary is
  either complete or the runtime is offline.
* **Privacy** — only hashes leave the local infrastructure. Raw prompt /
  response text is **never** written to the audit log.

## 2. Regulatory mapping

| Regulation | Requirement | Aura-Guard v1.3 implementation |
| --- | --- | --- |
| EU AI Act, Art. 12 | Automatic record-keeping of events | Append-only JSONL log with hash chain + `policy_hash` provenance |
| EU AI Act, Art. 13 | Transparency and traceability | Determinism + `aura-replay` reproduces any past decision |
| EU AI Act, Art. 14 | Human oversight | `REVIEW` decisions are surfaced as first-class outcomes; the queue is plain JSONL |
| DORA, Art. 6 | Operational resilience | Fail-closed posture (halt-on-log-failure); zero-cloud deployment supported |
| GDPR, Art. 5 / 25 | Data minimization, privacy by design | Only hashes of prompt/response stored — never the raw content |
| GDPR, Art. 32 | Integrity and confidentiality of processing | Ed25519-signed policies + memory-safe Rust + `unsafe_code = "forbid"` |
| SOC 2 / ISO 27001 | Immutable logging + segregation of duties | Append-only log, signed policies, distinct signer IDs |

## 3. Detection capabilities (shipped policy packs)

| Pack | Rule | Validator | Action |
| --- | --- | --- | --- |
| `finance-v1` | `credit-card` (13-19 digit pattern) | **Luhn** | DENY |
| `finance-v1` | `iban-pl` (`PL` + 26 digits) | **IBAN mod-97** | DENY |
| `finance-v1` | `iban-generic` (ISO-13616) | **IBAN mod-97** | REVIEW |
| `finance-v1` | `swift-code` (BIC, gated by `context: Finance`) | regex only | REVIEW |
| `medtech-v1` | `pesel` (11 digits) | **PESEL checksum + date** | DENY |
| `medtech-v1` | `diagnosis-keyword` (ICD-10 vocabulary) | regex only | REVIEW |
| `medtech-v1` | `medication-dosage` (gated by `context: MedTech`) | regex only | REVIEW |
| `hr-bias-v1` | `age-discrimination` (PL + EN forms) | regex only | DENY |
| `hr-bias-v1` | `gender-family-bias` | regex only | REVIEW |
| `hr-bias-v1` | `disability-bias` | regex only | REVIEW |

All rules are matched against SHADOW_SPEC v1.0 normalized input — zero-width
spaces, fullwidth digits, Cyrillic / Greek homoglyphs and decomposed Unicode
forms cannot bypass detection.

## 4. Out-of-scope

* Semantic intent detection — Aura-Guard is rule-based, not ML.
* Fact-checking or hallucination prevention.
* Network-layer DoS — deploy behind your reverse proxy / WAF.
* Endpoint protection — package the binary with your standard EDR/HIDS.

## 5. Verification by auditors

1. `aura-replay --log <captured.jsonl>` — confirms the SHA-256 hash chain
   has not been tampered with. Exit 2 = `CHAIN BREAK`.
2. `aura-replay --log <captured.jsonl> --verify-lineage` — additionally
   verifies that the policy file referenced by each entry (`policy_hash`)
   still matches its on-disk representation. Exit 3 = `LINEAGE MISMATCH`.
3. Diff between published genesis hash and `/version` output — proves that
   the running instance speaks the published v1.3 protocol.
4. Boot-time check: the supervisor (systemd / Kubernetes) MUST treat exit
   code 78 as a hard alert, not a restart loop. An exit 78 means the
   enforcement boundary could not be validated and the runtime refused to
   serve traffic — that is the intended fail-closed posture.

## 6. Limitations and honest disclosure

* **`--verify-lineage` is not a full decision replay.** The raw prompt and
  response are never written to the audit log (privacy minimization by
  design). What `--verify-lineage` proves is *cryptographic continuity*
  between the policy that was applied in production and the policy
  currently sitting on disk — not that the model would produce the same
  output today. Full decision replay would require retaining prompts in a
  separate sealed evidence store (Phase 4 roadmap, "Encrypted Evidence
  Vault").
* `policy_hash` confirms continuity but not authenticity *of past
  inspections* — pair with cosign-signed releases (v1.4 roadmap) for
  end-to-end attestation.
* The runtime is on-host; protection of the host (TPM, sealed boot, secure
  enclaves) is part of the operator's deployment responsibility — Phase 5 of
  the roadmap addresses this in software.
* `aura-replay --recompute` is retained as a **deprecated alias** for
  `--verify-lineage` and prints a one-time warning to stderr. The old
  name implied something the binary never did (re-evaluating the model);
  the new name describes what it actually verifies.
