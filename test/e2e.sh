#!/bin/sh
set -eu

cd "$(dirname "$0")"
compose='docker compose -f docker-compose.yml'
cookies=$(mktemp)
cleanup() {
    rm -f "$cookies"
    $compose down >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

mkdir -p certs
if [ ! -f certs/ca.crt ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
        -keyout certs/ca.key -out certs/ca.crt -subj '/CN=OIDC Test CA' >/dev/null 2>&1
    openssl req -newkey rsa:2048 -nodes -keyout certs/idp.key -out /tmp/oidc-idp.csr \
        -subj '/CN=idp.test' >/dev/null 2>&1
    printf '%s\n' 'subjectAltName=DNS:idp.test' >/tmp/oidc-idp.ext
    openssl x509 -req -days 1 -in /tmp/oidc-idp.csr -CA certs/ca.crt -CAkey certs/ca.key \
        -CAcreateserial -extfile /tmp/oidc-idp.ext -out certs/idp.crt >/dev/null 2>&1
    rm -f /tmp/oidc-idp.csr /tmp/oidc-idp.ext certs/ca.srl
fi

$compose build nginx idp >/dev/null
$compose up -d
ready=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
    if docker run --rm --network test_oidc curlimages/curl:8.10.1 \
        --insecure --fail --silent https://idp.test:8443/.well-known/openid-configuration \
        >/dev/null \
        && docker run --rm --network test_oidc curlimages/curl:8.10.1 \
        --silent http://nginx/ >/dev/null; then
        ready=1
        break
    fi
    sleep 1
done
[ "$ready" -eq 1 ]

docker run --rm --network test_oidc -v /tmp:/tmp \
    curlimages/curl:8.10.1 --insecure --fail --silent --show-error \
    --location --max-redirs 5 --cookie-jar /tmp/oidc-e2e-cookies \
    --cookie /tmp/oidc-e2e-cookies --connect-to demo.example.com:80:nginx:80 \
    'http://demo.example.com/deep/path?tab=profile' >"$cookies"

grep -qx 'Hello, Jane Doe!' "$cookies"
grep -qx 'Email: jane@example.com' "$cookies"
grep -qx 'Sub: user-12345' "$cookies"
grep -qx 'Department: Engineering' "$cookies"
! grep -q 'eyJ' /tmp/oidc-e2e-cookies
python3 -c "import time; lines=open('/tmp/oidc-e2e-cookies').read().splitlines(); row=next(x.split('\\t') for x in lines if '\\toidc_session_my_idp\\t' in x); ttl=int(row[4])-int(time.time()); assert 1790 <= ttl <= 1800, ttl"
! grep -q 'oidc_session_my_idp_state' /tmp/oidc-e2e-cookies
$compose restart nginx >/dev/null
sleep 1
docker run --rm --network test_oidc -v /tmp:/tmp \
    curlimages/curl:8.10.1 --insecure --fail --silent --show-error \
    --cookie /tmp/oidc-e2e-cookies --connect-to demo.example.com:80:nginx:80 \
    http://demo.example.com/deep/path?tab=profile | grep -qx 'Hello, Jane Doe!'
$compose logs --no-color idp | grep -q 'GET /userinfo HTTP/1.1" 200'
[ "$($compose logs --no-color idp | grep -c 'GET /jwks HTTP/1.1" 200')" -eq 3 ]

# refresh: short-lived access token (expires_in=3) forces a refresh grant
sleep 4
docker run --rm --network test_oidc -v /tmp:/tmp \
    curlimages/curl:8.10.1 --insecure --fail --silent --show-error \
    --location --max-redirs 3 --cookie-jar /tmp/oidc-e2e-cookies \
    --cookie /tmp/oidc-e2e-cookies --connect-to demo.example.com:80:nginx:80 \
    http://demo.example.com/deep/path?tab=profile | grep -qx 'Hello, Jane Doe!'
$compose logs --no-color idp | grep -q 'POST /token HTTP/1.1" 200'
refresh_grants=$($compose logs --no-color idp | grep -c 'POST /token HTTP/1.1" 200')
[ "$refresh_grants" -ge 2 ]

docker run --rm --network test_oidc -v /tmp:/tmp \
    curlimages/curl:8.10.1 --insecure --silent --show-error --include \
    --cookie /tmp/oidc-e2e-cookies --connect-to demo.example.com:80:nginx:80 \
    http://demo.example.com/logout >"$cookies"
grep -q 'Set-Cookie: oidc_session_my_idp=;' "$cookies"
grep -q 'Location: https://idp.test:8443/logout?post_logout_redirect_uri=' "$cookies"
$compose logs --no-color idp | grep -q 'POST /revoke HTTP/1.1" 200'

# backchannel logout: IdP-side logout kills the server session
rm -f /tmp/oidc-bc-cookies
docker run --rm --network test_oidc -v /tmp:/tmp \
    curlimages/curl:8.10.1 --insecure --fail --silent --show-error \
    --location --max-redirs 5 --cookie-jar /tmp/oidc-bc-cookies \
    --cookie /tmp/oidc-bc-cookies --connect-to demo.example.com:80:nginx:80 \
    http://demo.example.com/ | grep -qx 'Hello, Jane Doe!'
logout_token=$(docker run --rm --network test_oidc curlimages/curl:8.10.1 \
    --insecure --fail --silent https://idp.test:8443/logout-token)
bc_code=$(docker run --rm --network test_oidc curlimages/curl:8.10.1 \
    --silent -o /dev/null -w '%{http_code}' -X POST \
    --data "logout_token=${logout_token}" \
    --connect-to demo.example.com:80:nginx:80 \
    http://demo.example.com/_oidc_backchannel)
[ "$bc_code" = "200" ]
sess_code=$(docker run --rm --network test_oidc -v /tmp:/tmp \
    curlimages/curl:8.10.1 --silent -o /dev/null -w '%{http_code}' \
    --cookie /tmp/oidc-bc-cookies --connect-to demo.example.com:80:nginx:80 \
    http://demo.example.com/)
[ "$sess_code" = "302" ]
rm -f /tmp/oidc-bc-cookies

rm -f /tmp/oidc-e2e-cookies
printf '%s\n' 'E2E passed'
