#!/usr/bin/env bash
set -uo pipefail

TOKEN="${THREAT_INFO_API_TOKEN:-local-dev-token-1234}"
CERT=certs/cert.pem
CURL=(curl -sS --max-time 10)

if [[ -n "${BASE_URL:-}" ]]; then
	BASE="$BASE_URL"
elif [[ -f "$CERT" ]] && curl -fs --cacert "$CERT" https://localhost:8080/healthz >/dev/null 2>&1; then
	BASE=https://localhost:8080
	CURL+=(--cacert "$CERT")
else
	BASE=http://localhost:8080
fi

HASH="$(openssl rand -hex 16)"
UNKNOWN="$(openssl rand -hex 16)"
AUTH="Authorization: Bearer $TOKEN"
JSON='Content-Type: application/json'
CREATE="{\"md5\":\"$HASH\",\"name\":\"Trojan.Win32.Generic\",\"severity\":\"high\",\"category\":\"trojan\",\"tags\":[\"dropper\"]}"
REPLACE='{"name":"Trojan.Win32.Generic","severity":"critical","category":"trojan"}'
INVALID='{"severity":"urgent"}'

failed=0

check() {
	local want="$1" label="$2"
	shift 2

	local got
	got="$("${CURL[@]}" -o /dev/null -w '%{http_code}' "$@")" || got="---"

	if [[ "$got" == "$want" ]]; then
		printf 'PASS  %-46s %s\n' "$label" "$got"
	else
		printf 'FAIL  %-46s %s (want %s)\n' "$label" "$got" "$want"
		failed=1
	fi
}

echo "Checking the API at $BASE"
echo

check 200 "GET  /readyz" "$BASE/readyz"
check 201 "POST /info                 create a threat" -X POST "$BASE/info" -H "$AUTH" -H "$JSON" -d "$CREATE"
check 409 "POST /info                 duplicate hash" -X POST "$BASE/info" -H "$AUTH" -H "$JSON" -d "$CREATE"
check 400 "POST /info                 invalid body" -X POST "$BASE/info" -H "$AUTH" -H "$JSON" -d "$INVALID"
check 401 "POST /info                 no token" -X POST "$BASE/info" -H "$JSON" -d "$CREATE"
check 200 "GET  /info/{md5}           read the threat" "$BASE/info/$HASH"
check 404 "GET  /info/{md5}           unknown hash" "$BASE/info/$UNKNOWN"
check 400 "GET  /info/{md5}           invalid hash" "$BASE/info/not-a-hash"
check 200 "PUT  /info/{md5}           replace the threat" -X PUT "$BASE/info/$HASH" -H "$AUTH" -H "$JSON" -d "$REPLACE"
check 404 "PUT  /info/{md5}           unknown hash" -X PUT "$BASE/info/$UNKNOWN" -H "$AUTH" -H "$JSON" -d "$REPLACE"
check 400 "PUT  /info/{md5}           invalid body" -X PUT "$BASE/info/$HASH" -H "$AUTH" -H "$JSON" -d "$INVALID"
check 401 "PUT  /info/{md5}           no token" -X PUT "$BASE/info/$HASH" -H "$JSON" -d "$REPLACE"

echo
if ((failed)); then
	echo "Some checks failed."
	exit 1
fi

echo "All checks passed."
