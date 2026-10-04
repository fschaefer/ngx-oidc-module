#!/bin/sh
#
# Run the module against an external Keycloak instead of the local one:
# only nginx and the backend are started, the issuer and the IdP CA come in
# via environment. No ports are published, the flow runs on the compose
# network. KEEP=1 leaves the stack up.
#
#   KC_ISSUER=https://192.168.13.54:8443/realms/oidc-test \
#   KC_CA=/path/to/ca.crt ./test/keycloak-remote-e2e.sh
#
set -eu
cd "$(dirname "$0")"

KC_ISSUER=${KC_ISSUER:?set KC_ISSUER to the realm URL, e.g. https://host:8443/realms/name}
KC_CA=${KC_CA:?set KC_CA to the PEM file that signed the IdP certificate}
[ -f "$KC_CA" ] || { echo "KC_CA not readable: $KC_CA" >&2; exit 2; }

cp "$KC_CA" certs/idp-ca.crt
sed "s|@KC_ISSUER@|$KC_ISSUER|" nginx-keycloak-remote.conf.in > nginx-keycloak-remote.conf

export NGINX_CONF=nginx-keycloak-remote.conf
# 80 ist auf Hosts mit eigenem Webserver belegt; der Flow braucht keinen Publish.
export APP_PORT=${APP_PORT:-8099}
compose='docker compose -f docker-compose.keycloak.yml'
cleanup() {
    [ "${KEEP:-0}" = "1" ] || $compose down --remove-orphans >/dev/null 2>&1
}
trap cleanup EXIT INT TERM

$compose up --build --detach app nginx >/dev/null

ready=0
for _ in $(seq 1 60); do
    if docker run --rm --user "$(id -u):$(id -g)" --network test_oidc -v "$PWD/certs/idp-ca.crt:/certs/idp-ca.crt:ro" \
        curlimages/curl:8.10.1 --fail --silent --cacert /certs/idp-ca.crt \
        "$KC_ISSUER/.well-known/openid-configuration" >/dev/null 2>&1 \
       && docker run --rm --user "$(id -u):$(id -g)" --network test_oidc curlimages/curl:8.10.1 \
        --fail --silent http://app.test/ >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 1
done
[ "$ready" -eq 1 ] || { echo "external IdP or nginx not ready" >&2; exit 1; }
echo "external IdP reachable: $KC_ISSUER"

docker run --rm --user "$(id -u):$(id -g)" --network test_oidc \
    -v "$PWD/certs/idp-ca.crt:/certs/ca.crt:ro" -v "$PWD:/work:ro" \
    -e KC_REALM="$KC_ISSUER" \
    python:3.12-slim python3 /work/keycloak-flow.py
