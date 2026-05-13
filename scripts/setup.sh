#!/usr/bin/env bash
# Aura-Guard v1.3 — one-shot setup script.
# - Builds release binaries.
# - Generates an Ed25519 signing key and signs all bundled policies.
# - Pre-creates the logs/ directory.

set -euo pipefail
cd "$(dirname "$0")/.."

echo "[setup] cargo build --release --bins"
cargo build --release --bins --quiet

mkdir -p logs

# Skip keygen if a key already exists (idempotent).
if [[ ! -f policies/aura.key ]]; then
  echo "[setup] generating Ed25519 signing key"
  ./target/release/aura-sign-policy keygen \
      --out policies/aura.key \
      --signer aura-engineering \
      --trusted-signers policies/trusted_signers.json > /dev/null
fi

echo "[setup] signing policy packs"
./target/release/aura-sign-policy sign \
  --key policies/aura.key \
  --signer aura-engineering \
  policies/finance-v1.yaml \
  policies/medtech-v1.yaml \
  policies/hr-bias-v1.yaml

echo "[setup] OK — start the server with:"
echo "    AURA_API_KEY=changeme ./target/release/aura-guard"
