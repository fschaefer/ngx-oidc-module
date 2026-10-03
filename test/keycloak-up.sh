#!/bin/sh
set -eu

cd "$(dirname "$0")"
mkdir -p certs

if [ ! -f certs/ca.crt ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
        -keyout certs/ca.key -out certs/ca.crt -subj '/CN=OIDC Test CA'
fi

if [ ! -f certs/keycloak.crt ]; then
    openssl req -newkey rsa:2048 -nodes \
        -keyout certs/keycloak.key -out /tmp/oidc-keycloak.csr \
        -subj '/CN=keycloak.test'
    printf '%s\n' 'subjectAltName=DNS:keycloak.test' >/tmp/oidc-keycloak.ext
    openssl x509 -req -days 1 -in /tmp/oidc-keycloak.csr \
        -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial \
        -extfile /tmp/oidc-keycloak.ext -out certs/keycloak.crt
    rm -f /tmp/oidc-keycloak.csr /tmp/oidc-keycloak.ext certs/ca.srl
fi

compose='docker compose -f docker-compose.keycloak.yml'
$compose up --build --detach

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
