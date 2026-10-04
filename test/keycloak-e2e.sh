#!/bin/sh
#
# End-to-end test against a real Keycloak: brings up the stack from
# docker-compose.keycloak.yml, drives login and RP logout with
# keycloak-flow.py, and tears the stack down again. Set KEEP=1 to leave the
# stack running for the manual browser walkthrough in the README.
#
set -eu
cd "$(dirname "$0")"
sh ./make-certs.sh

compose='docker compose -f docker-compose.keycloak.yml'
cleanup() {
    [ "${KEEP:-0}" = "1" ] || $compose down --remove-orphans >/dev/null 2>&1
}
trap cleanup EXIT INT TERM

$compose up --build --detach

# Keycloak needs its TLS material and a warm JVM before it answers discovery.
ready=0
for _ in $(seq 1 120); do
    if docker run --rm --network test_oidc -v "$PWD/certs:/certs:ro" \
        curlimages/curl:8.10.1 --fail --silent --cacert /certs/ca.crt \
        https://keycloak.test:8443/realms/oidc-test/.well-known/openid-configuration \
        >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 1
done
[ "$ready" -eq 1 ]

docker run --rm --network test_oidc \
    -v "$PWD/certs:/certs:ro" -v "$PWD:/work:ro" \
    python:3.12-slim python3 /work/keycloak-flow.py
