#!/usr/bin/env bash
# End-to-end smoke test of the Acme stack with a real Keycloak.
#   ./examples/acme/smoke.sh          (starts the stack, runs checks, leaves it running)
#   KEEP=0 ./examples/acme/smoke.sh   (tears it down afterwards)
set -euo pipefail
cd "$(dirname "$0")"

KC=http://localhost:8080/realms/acme/protocol/openid-connect/token
GW=http://localhost:8088/mcp

docker compose up -d --build --wait
for _ in $(seq 1 60); do curl -sf http://localhost:8088/healthz >/dev/null && break; sleep 2; done

token() {
  curl -sf "$KC" -d grant_type=password -d client_id=acme-bot -d client_secret=dev-bot-secret \
    -d username="$1" -d password=dev | jq -r .access_token
}

# mcp <token> <json-rpc body> : runs initialize once per token and prints the JSON response
declare -A SESSION
mcp() {
  local tok=$1 body=$2
  if [[ -z "${SESSION[$tok]:-}" ]]; then
    SESSION[$tok]=$(curl -sf -D - -o /dev/null "$GW" -H "authorization: Bearer $tok" -H "content-type: application/json" \
      -H "accept: application/json, text/event-stream" \
      -d '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}' \
      | tr -d '\r' | awk -F': ' 'tolower($1)=="mcp-session-id"{print $2}')
  fi
  curl -sf "$GW" -H "authorization: Bearer $tok" -H "mcp-session-id: ${SESSION[$tok]}" -H "content-type: application/json" \
    -H "accept: application/json, text/event-stream" -d "$body"
}

check() {
  if [[ "$2" == "$3" ]]; then echo "ok   $1"; else echo "FAIL $1: expected [$3], got [$2]"; exit 1; fi
}

HANNA=$(token hanna); HENRIK=$(token henrik); SVEN=$(token sven)
LIST='{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

check "hanna sees only directory search" \
  "$(mcp "$HANNA" "$LIST" | jq -c '[.result.tools[].name] | sort')" '["hr.search_employees"]'
check "henrik sees salaries" \
  "$(mcp "$HENRIK" "$LIST" | jq -c '[.result.tools[].name] | sort')" '["hr.get_salary","hr.search_employees"]'
check "sven sees crm tools" \
  "$(mcp "$SVEN" "$LIST" | jq -c '[.result.tools[].name] | sort')" '["crm.list_deals","crm.query","crm.update_deal"]'

call() { echo "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"$1\",\"arguments\":$2}}"; }
check "henrik: other unit denied" \
  "$(mcp "$HENRIK" "$(call hr.get_salary '{"unit":"sales"}')" | jq -r '.result.isError')" "true"
check "henrik: own unit allowed" \
  "$(mcp "$HENRIK" "$(call hr.get_salary '{"unit":"hr"}')" | jq -r '.result.structuredContent.ok')" "true"
check "sven: foreign tenant denied" \
  "$(mcp "$SVEN" "$(call crm.list_deals '{"tenant":"enterprise"}')" | jq -r '.result.isError')" "true"
check "sven: big deal approved by webhook" \
  "$(mcp "$SVEN" "$(call crm.update_deal '{"tenant":"dach","deal_id":"d-1","amount":80000}')" | jq -r '.result.structuredContent.ok')" "true"

check "admin explain" \
  "$(curl -sf http://localhost:8089/v1/explain -H 'authorization: Bearer dev-admin-token' -H 'content-type: application/json' \
      -d '{"principal":{"subject":{"id":"henrik","roles":["hr-lead"],"attrs":{"org_unit":"hr"}},"agent":"acme-bot"},"action":{"kind":"tool","name":"hr.get_salary","args":{"unit":"sales"}}}' \
      | jq -r .decision.rule)" "salary-only-own-unit"

echo "all smoke checks passed"
if [[ "${KEEP:-1}" == "0" ]]; then docker compose down -v; fi
