#!/usr/bin/env bash
# Aura-Guard v1.3 — end-to-end smoke test with jq assertions.
#
# Requires: the server already running on $AURA_BIND (default 127.0.0.1:8080)
# with API key $AURA_API_KEY exported.

set -euo pipefail
cd "$(dirname "$0")/.."

URL="${AURA_BIND:-http://127.0.0.1:8080}"
KEY="${AURA_API_KEY:-changeme}"

PASS=0
FAIL=0

assert_decision() {
  local name="$1" expected="$2" file="$3"
  local resp
  resp=$(curl -fsS -X POST "${URL}/v1/audit" \
            -H 'Content-Type: application/json' \
            -H "X-API-Key: ${KEY}" \
            -d @"${file}")
  local got
  got=$(echo "${resp}" | jq -r '.decision')
  if [[ "${got}" == "${expected}" ]]; then
    PASS=$((PASS + 1))
    printf "  PASS  %-40s decision=%s\n" "${name}" "${got}"
  else
    FAIL=$((FAIL + 1))
    printf "  FAIL  %-40s expected=%s got=%s\n" "${name}" "${expected}" "${got}"
    echo "  response: ${resp}"
  fi
}

echo "==> /health"
curl -fsS "${URL}/health" | jq .

echo "==> /ready"
curl -fsS "${URL}/ready" | jq .

echo "==> /v1/audit golden tests"
assert_decision "finance-cc-luhn-valid" DENY    examples/request-finance-cc.json
assert_decision "finance-iban-valid"    DENY    examples/request-finance-iban.json
assert_decision "medtech-pesel-valid"   DENY    examples/request-medtech.json
assert_decision "hr-bias-gender"        REVIEW  examples/request-hr.json
assert_decision "clean-request"         ALLOW   examples/request-clean.json
assert_decision "zwsp-bypass-blocked"   DENY    examples/request-zwsp-bypass.json

echo ""
echo "Summary: ${PASS} passed, ${FAIL} failed."
exit ${FAIL}
