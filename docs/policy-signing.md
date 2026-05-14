# Policy signing

Every policy YAML that governs an audit decision must carry a valid
Ed25519 signature from a key listed in `policies/trusted_signers.json`.
The loader fails closed (`BOOT FAIL`, exit `78`) on missing or invalid
signatures.

## File layout

For each policy `policies/<name>.yaml`:

```
policies/
├── <name>.yaml          # the policy itself (canonical bytes that are hashed)
├── <name>.yaml.sig      # hex-encoded Ed25519 signature over the YAML bytes
└── <name>.yaml.signer   # signer ID (single line, matches a key in trusted_signers.json)
```

`policies/trusted_signers.json` is a JSON object mapping signer ID to
hex-encoded 32-byte Ed25519 public key:

```json
{
  "aura-engineering": "9f2c…",
  "aura-compliance":  "ab12…"
}
```

## Generating a key and signing a policy

```bash
# 1) Generate a fresh Ed25519 key pair and register the public key in
#    trusted_signers.json under signer ID "aura-engineering".
./target/release/aura-sign-policy keygen \
    --out policies/aura.key \
    --signer aura-engineering \
    --trusted-signers policies/trusted_signers.json

# 2) Sign one or more policy YAMLs with that key.
./target/release/aura-sign-policy sign \
    --key policies/aura.key \
    --signer aura-engineering \
    policies/finance-v1.yaml \
    policies/medtech-v1.yaml
```

`./scripts/setup.sh` runs both steps idempotently and produces a usable
local setup in one command.

## Cryptographic assumptions

- **Algorithm:** Ed25519 (`ed25519-dalek` v2, RustCrypto).
- **Signed bytes:** the exact on-disk bytes of `<name>.yaml`. Whitespace
  and trailing newlines matter. The runtime reads the file before
  verification and hashes the same bytes for `policy_hash`.
- **Signature determinism:** Ed25519 signatures are deterministic for a
  given (key, message) pair — re-signing the same YAML with the same
  key produces a byte-identical `.sig`.
- **Public key handling:** runtime never sees the private key; only
  `trusted_signers.json` (public keys) needs to be deployed.

See [`docs/adrs/0002-ed25519-policy-signing.md`](adrs/0002-ed25519-policy-signing.md)
for the design rationale.

## Operational notes

### Key custody

Private signing keys belong with the policy author, not the runtime
host. For production we recommend storing them in an HSM or cloud KMS
(planned first-class support in v1.5 — see roadmap).

### Key rotation

1. Generate a new key pair.
2. Add the new public key to `trusted_signers.json` (the old one stays
   for the transition window).
3. Re-sign each policy YAML with the new key.
4. Roll out the new `.sig` / `.signer` files alongside the binary.
5. After the rollout is verified, remove the old public key from
   `trusted_signers.json` and restart the runtime — fail-closed checks
   on any old `.sig` will then trip exit `78` instead of being accepted.

### Multi-signer / 4-eye review

`trusted_signers.json` can hold any number of signer IDs. The
`<name>.yaml.signer` file is a single line that names which signer
issued the bundled `.sig`. To require sign-off from two distinct
signers, run the policy review workflow with two engineers and rotate
the active `.signer` between them per change.

A first-class N-of-M signing scheme is on the roadmap for v1.6 alongside
the policy approval workflows.

### What is **not** covered

- The signing key itself — protect it the same way you would protect a
  production code-signing certificate.
- Build provenance for the Aura-Guard binary — cosign/sigstore release
  attestations are planned for v1.4.
- Hardware-backed key custody — planned for v1.5 (HSM via PKCS#11).
