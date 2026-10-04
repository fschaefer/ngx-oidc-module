#!/bin/sh
#
# Ensure the local test certificates exist and are still valid. The CA and
# the leaf certificates are regenerated once they are missing, expired, or
# about to expire, so a working copy keeps running without manual cleanup.
#
set -eu
cd "$(dirname "$0")"
mkdir -p certs

days=30

cert_ok() {
    [ -f "$1" ] && openssl x509 -checkend 3600 -noout -in "$1" >/dev/null 2>&1
}

if ! cert_ok certs/ca.crt || [ ! -f certs/ca.key ]; then
    rm -f certs/ca.crt certs/ca.key certs/ca.srl
    openssl req -x509 -newkey rsa:2048 -nodes -days "$days" \
        -keyout certs/ca.key -out certs/ca.crt -subj '/CN=OIDC Test CA' >/dev/null 2>&1
    # leaves signed by the old CA are no longer usable
    rm -f certs/idp.crt certs/idp.key certs/keycloak.crt certs/keycloak.key
fi

leaf() {
    name=$1
    cn=$2

    if cert_ok "certs/$name.crt" && [ -f "certs/$name.key" ]; then
        return 0
    fi

    openssl req -newkey rsa:2048 -nodes -keyout "certs/$name.key" \
        -out "/tmp/oidc-$name.csr" -subj "/CN=$cn" >/dev/null 2>&1
    printf '%s\n' "subjectAltName=DNS:$cn" >"/tmp/oidc-$name.ext"
    openssl x509 -req -days "$days" -in "/tmp/oidc-$name.csr" \
        -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial \
        -extfile "/tmp/oidc-$name.ext" -out "certs/$name.crt" >/dev/null 2>&1
    rm -f "/tmp/oidc-$name.csr" "/tmp/oidc-$name.ext"
}

leaf idp idp.test
leaf keycloak keycloak.test

rm -f certs/ca.srl
