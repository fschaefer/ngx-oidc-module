#!/bin/sh
set -eu

cd "$(dirname "$0")"
sh ./make-certs.sh

compose='docker compose -f docker-compose.keycloak.yml'
$compose --profile idp up --build --detach

for _ in $(seq 1 90); do
    if curl --silent --fail --cacert certs/ca.crt \
        --resolve keycloak.test:8443:127.0.0.1 \
        https://keycloak.test:8443/realms/oidc-test/.well-known/openid-configuration \
        >/dev/null; then
        break
    fi
    sleep 1
done

curl --silent --fail --cacert certs/ca.crt \
    --resolve keycloak.test:8443:127.0.0.1 \
    https://keycloak.test:8443/realms/oidc-test/.well-known/openid-configuration \
    >/dev/null
printf '%s\n' 'Open http://app.test after mapping app.test and keycloak.test to 127.0.0.1.'
printf '%s\n' 'Login: jane / jane-password'
