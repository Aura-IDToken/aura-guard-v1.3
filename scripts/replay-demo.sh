#!/usr/bin/env bash
# Aura-Guard — replay verification demo.
#
# End-to-end flow:
#   1. POST a few audit decisions to the running server.
#   2. Run aura-replay on the resulting JSONL          → CHAIN OK   (exit 0).
#   3. Flip one byte in the JSONL (DENY -> ALLOW).
#   4. Run aura-replay again                            → CHAIN BREAK (exit 2).
#
# Prerequisites:
#   * `aura-guard` running on $AURA_BIND (default http://127.0.0.1:8080)
#     with $AURA_API_KEY exported (default "changeme" for local dev).
#   * `./scripts/setup.sh` has been run (release binaries + signed policies).
#
# The script itself exits 0 on the *expected* failure (chain break with rc=2)
# and non-zero if anything unexpected happens. That makes it safe to wire
# into CI smoke tests.

set -euo pipefail
cd "$(dirname "$0")/.."

URL="${AURA_BIND:-http://127.0.0.1:8080}"
KEY="${AURA_API_KEY:-changeme}"
LOG=logs/audit.jsonl
REPLAY=./target/release/aura-replay

step() {
  printf '\n==> %s\n' "$1"
}

audit() {
  local file=$1
  curl -fsS -X POST "${URL}/v1/audit" \
       -H 'Content-Type: application/json' \
       -H "X-API-Key: ${KEY}" \
       -d @"${file}" > /dev/null
}

step "Step 1: append a few audit entries via POST /v1/audit"
audit examples/request-clean.json
audit examples/request-finance-cc.json
audit examples/request-medtech.json
audit examples/request-hr.json
printf '    current entries in %s: %s\n' "${LOG}" "$(wc -l < ${LOG})"

step "Step 2: verify the hash chain (expect CHAIN OK, exit 0)"
${REPLAY} --log "${LOG}"
printf '    exit code: %s\n' $?

step "Step 3: tamper with entry #1 (flip DENY -> ALLOW)"
python3 - <<PY
from pathlib import Path
p = Path("${LOG}")
lines = p.read_text().splitlines()
lines[1] = lines[1].replace('"decision":"DENY"', '"decision":"ALLOW"', 1)
p.write_text("\n".join(lines) + "\n")
print("    tampered entry index 1 (DENY -> ALLOW)")
PY

step "Step 4: re-verify (expect CHAIN BREAK DETECTED, exit code 2)"
set +e
${REPLAY} --log "${LOG}"
rc=$?
set -e
printf '    exit code: %s\n' "${rc}"

if [[ ${rc} -eq 2 ]]; then
  printf '\nOK — tamper detected (aura-replay exit code 2, demo exit code 0).\n'
  exit 0
fi

if [[ ${rc} -eq 0 ]]; then
  printf '\nUNEXPECTED: replay succeeded on tampered log\n' >&2
else
  printf '\nUNEXPECTED aura-replay exit code: %s (expected 2)\n' "${rc}" >&2
fi
exit 1
