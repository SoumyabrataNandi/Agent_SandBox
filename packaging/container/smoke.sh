#!/usr/bin/env bash
# Smoke test for the sandboxd container image (cycle 6, FR-CT1). Used by the `container` workflow
# on every change to the container files, and by `release.yml` before an image is pushed.
#
#   packaging/container/smoke.sh <image> <host sandboxd binary>
#
# The host binary only mints the token (`sandboxd token new`); everything else runs in the image.
# Checks: `version`; readiness within 300 s; an authenticated `print(6*7)` answers 42; a request
# without a token gets 401; the server runs as uid 10001. Prints the container logs on failure.
set -euo pipefail

image="${1:?usage: smoke.sh <image> <sandboxd binary>}"
sandboxd="${2:?usage: smoke.sh <image> <sandboxd binary>}"
port="${SMOKE_PORT:-8080}"
name="sandboxd-smoke-$$"
base="http://127.0.0.1:${port}"

fail() {
    echo "smoke: FAIL: $*" >&2
    docker logs "$name" 2>&1 | tail -n 100 >&2 || true
    exit 1
}
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT

docker run --rm "$image" version

out="$("$sandboxd" token new --name smoke)"
token="$(printf '%s\n' "$out" | sed -n '2p' | tr -d ' ')"
hash="$(printf '%s\n' "$out" | grep -o 'sha256 = "[0-9a-f]*"' | cut -d'"' -f2)"
[ -n "$token" ] && [ ${#hash} -eq 64 ] || { echo "smoke: could not parse 'token new' output" >&2; exit 1; }

docker run -d --name "$name" -p "127.0.0.1:${port}:8080" -e SANDBOXD_TOKENS="smoke=${hash}" "$image" >/dev/null

ready=
for i in $(seq 1 300); do
    if curl -fsS "$base/healthz" >/dev/null 2>&1; then echo "smoke: ready after ${i}s"; ready=1; break; fi
    [ "$(docker inspect -f '{{.State.Running}}' "$name")" = true ] || fail "the container exited during start-up"
    sleep 1
done
[ -n "$ready" ] || fail "not ready after 300 s"

r="$(curl -fsS -H "Authorization: Bearer ${token}" -H 'Content-Type: application/json' \
    -d '{"language":"python","code":"print(6*7)"}' "$base/v1/runs")" || fail "authenticated run request failed"
printf '%s' "$r" | python3 -c 'import json,sys; r=json.load(sys.stdin); assert r["stdout"]=="42\n", r' \
    || fail "unexpected run result: $r"
echo "smoke: run ok"

code="$(curl -s -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' \
    -d '{"language":"python","code":"1"}' "$base/v1/runs")"
[ "$code" = 401 ] || fail "expected 401 without a token, got $code"
echo "smoke: unauthenticated request refused"

uid="$(docker exec "$name" id -u)"
[ "$uid" = 10001 ] || fail "expected uid 10001, got $uid"
echo "smoke: PASS"
