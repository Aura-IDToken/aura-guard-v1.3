#!/usr/bin/env bash
# Aura-Guard v1.3 — Replay verification demo.
# Runs the killer feature from the demo guide: append entries, run replay,
# tamper with one entry, run replay again and observe CHAIN BREAK DETECTED.

set -euo pipefail
cd "$(dirname "$0")/.."

URL="${AURA_BIND:-http://127.0.0.1:8080}"
KEY="${AURA_API_KEY:-changeme}"
LOG=logs/audit.jsonl

audit() {
  local file=$1
  curl -fsS -X POST "${URL}/v1/audit" \
       -H 'Content-Type: application/json' \
       -H "X-API-Key: ${KEY}" \
       -d @"${file}" > /dev/null
}

echo "==> Step 1: produce a few audit entries"
audit examples/request-clean.json
audit examples/request-finance-cc.json
audit examples/request-medtech.json
audit examples/request-hr.json
echo "current entries: $(wc -l < ${LOG})"

echo ""
echo "==> Step 2: replay (expect CHAIN OK)"
./target/release/aura-replay --log "${LOG}"

echo ""
echo "==> Step 3: tamper with the second entry (flip DENY -> ALLOW)"
python3 - <<PY
from pathlib import Path
p = Path("${LOG}")
lines = p.read_text().splitlines()
lines[1] = lines[1].replace('"decision":"DENY"', '"decision":"ALLOW"', 1)
p.write_text("\n".join(lines) + "\n")
print("tampered entry index 1")
PY

echo ""
echo "==> Step 4: replay again (expect CHAIN BREAK DETECTED, exit code 2)"
if ./target/release/aura-replay --log "${LOG}"; then
  echo "UNEXPECTED: replay succeeded on tampered log" >&2
  exit 1
else
  rc=$?
  if [[ ${rc} -eq 2 ]]; then
    echo ""
    echo "OK — tamper detected (exit code 2, as designed)."
    exit 0
  else
    echo "UNEXPECTED exit code: ${rc}" >&2
    exit 1
  fi
fi
