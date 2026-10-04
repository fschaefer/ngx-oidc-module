#!/bin/sh
set -eu

cd "$(dirname "$0")"
compose='docker compose -f docker-compose.yml'
cookies=$(mktemp)
# Cookie-Dateien gehoeren dem Aufrufer, nicht /tmp: von Containern (root)
# geschriebene Dateien liessen sich dort wegen des sticky bits nicht loeschen,
# und bei entferntem Daemon sieht der Aufrufer /tmp nicht identisch.
tmpd="$PWD/.tmp"
mkdir -p "$tmpd"
cleanup() {
    rm -f "$cookies"
    $compose down >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

sh ./make-certs.sh

$compose build nginx idp >/dev/null
$compose up -d
ready=0
# Der Mock-IdP erzeugt beim Start zwei RSA-Schluessel, bevor er den Port bindet.
# Das dauert gelegentlich deutlich laenger als ein paar Sekunden.
for _ in $(seq 1 60); do
    if docker run --rm --user "$(id -u):$(id -g)" --network test_oidc curlimages/curl:8.10.1 \
        --insecure --fail --silent https://idp.test:8443/.well-known/openid-configuration \
        >/dev/null \
        && docker run --rm --user "$(id -u):$(id -g)" --network test_oidc curlimages/curl:8.10.1 \
        --fail --silent http://nginx/ >/dev/null; then
        ready=1
        break
    fi
    sleep 1
done
if [ "$ready" -ne 1 ]; then
    echo "idp or nginx did not become ready" >&2
    $compose logs --no-color idp 2>&1 | tail -20 >&2
    exit 1
fi

docker run --rm --user "$(id -u):$(id -g)" --network test_oidc -v "$tmpd:/tmp" \
    curlimages/curl:8.10.1 --insecure --fail --silent --show-error \
    --location --max-redirs 5 --cookie-jar /tmp/oidc-e2e-cookies \
    --cookie /tmp/oidc-e2e-cookies --connect-to demo.example.com:80:nginx:80 \
    'http://demo.example.com/deep/path?tab=profile' >"$cookies"

grep -qx 'Hello, Jane Doe!' "$cookies"
grep -qx 'Email: jane@example.com' "$cookies"
grep -qx 'Sub: user-12345' "$cookies"
grep -qx 'Department: Engineering' "$cookies"
! grep -q 'eyJ' "$tmpd/oidc-e2e-cookies"
python3 -c "import time; lines=open('$tmpd/oidc-e2e-cookies').read().splitlines(); row=next(x.split('\\t') for x in lines if '\\toidc_session_my_idp\\t' in x); ttl=int(row[4])-int(time.time()); assert 1790 <= ttl <= 1800, ttl"
! grep -q 'oidc_session_my_idp_state' "$tmpd/oidc-e2e-cookies"
$compose restart nginx >/dev/null
sleep 1
docker run --rm --user "$(id -u):$(id -g)" --network test_oidc -v "$tmpd:/tmp" \
    curlimages/curl:8.10.1 --insecure --fail --silent --show-error \
    --cookie /tmp/oidc-e2e-cookies --connect-to demo.example.com:80:nginx:80 \
    http://demo.example.com/deep/path?tab=profile | grep -qx 'Hello, Jane Doe!'
$compose logs --no-color idp | grep -q 'GET /userinfo HTTP/1.1" 200'
[ "$($compose logs --no-color idp | grep -c 'GET /jwks HTTP/1.1" 200')" -eq 3 ]

# refresh: short-lived access token (expires_in=3) forces a refresh grant
sleep 4
docker run --rm --user "$(id -u):$(id -g)" --network test_oidc -v "$tmpd:/tmp" \
    curlimages/curl:8.10.1 --insecure --fail --silent --show-error \
    --location --max-redirs 3 --cookie-jar /tmp/oidc-e2e-cookies \
    --cookie /tmp/oidc-e2e-cookies --connect-to demo.example.com:80:nginx:80 \
    http://demo.example.com/deep/path?tab=profile | grep -qx 'Hello, Jane Doe!'
$compose logs --no-color idp | grep -q 'POST /token HTTP/1.1" 200'
refresh_grants=$($compose logs --no-color idp | grep -c 'POST /token HTTP/1.1" 200')
[ "$refresh_grants" -ge 2 ]

# primary session must not authorize a location bound to secondary_idp.
secondary_code=$(docker run --rm --user "$(id -u):$(id -g)" --network test_oidc -v "$tmpd:/tmp" \
    curlimages/curl:8.10.1 --silent -o /dev/null -w '%{http_code}' \
    --cookie /tmp/oidc-e2e-cookies --connect-to demo.example.com:80:nginx:80 \
    http://demo.example.com/secondary)
[ "$secondary_code" = "302" ]
docker run --rm --user "$(id -u):$(id -g)" --network test_oidc -v "$tmpd:/tmp" \
    curlimages/curl:8.10.1 --insecure --fail --silent --show-error \
    --location --max-redirs 5 --cookie-jar /tmp/oidc-e2e-cookies \
    --cookie /tmp/oidc-e2e-cookies --connect-to demo.example.com:80:nginx:80 \
    http://demo.example.com/secondary | grep -qx 'Hello, Jane Doe!'
grep -q 'oidc_session_secondary_idp' "$tmpd/oidc-e2e-cookies"

docker run --rm --user "$(id -u):$(id -g)" --network test_oidc -v "$tmpd:/tmp" \
    curlimages/curl:8.10.1 --insecure --silent --show-error --include \
    --cookie /tmp/oidc-e2e-cookies --connect-to demo.example.com:80:nginx:80 \
    http://demo.example.com/logout >"$cookies"
grep -q 'Set-Cookie: oidc_session_my_idp=;' "$cookies"
grep -q 'Location: https://idp.test:8443/logout?post_logout_redirect_uri=' "$cookies"
grep -q '&id_token_hint=' "$cookies"
$compose logs --no-color idp | grep -q 'POST /revoke HTTP/1.1" 200'

# primary logout must not delete secondary_idp's cookie or SQLite session.
docker run --rm --user "$(id -u):$(id -g)" --network test_oidc -v "$tmpd:/tmp" \
    curlimages/curl:8.10.1 --fail --silent --show-error \
    --cookie /tmp/oidc-e2e-cookies --connect-to demo.example.com:80:nginx:80 \
    http://demo.example.com/secondary | grep -qx 'Hello, Jane Doe!'

# backchannel logout: IdP-side logout kills the server session
rm -f "$tmpd/oidc-bc-cookies"
docker run --rm --user "$(id -u):$(id -g)" --network test_oidc -v "$tmpd:/tmp" \
    curlimages/curl:8.10.1 --insecure --fail --silent --show-error \
    --location --max-redirs 5 --cookie-jar /tmp/oidc-bc-cookies \
    --cookie /tmp/oidc-bc-cookies --connect-to demo.example.com:80:nginx:80 \
    http://demo.example.com/ | grep -qx 'Hello, Jane Doe!'
logout_token=$(docker run --rm --user "$(id -u):$(id -g)" --network test_oidc curlimages/curl:8.10.1 \
    --insecure --fail --silent https://idp.test:8443/logout-token)
bc_code=$(docker run --rm --user "$(id -u):$(id -g)" --network test_oidc curlimages/curl:8.10.1 \
    --silent -o /dev/null -w '%{http_code}' -X POST \
    --data "logout_token=${logout_token}" \
    --connect-to demo.example.com:80:nginx:80 \
    http://demo.example.com/_oidc_backchannel)
[ "$bc_code" = "200" ]
sess_code=$(docker run --rm --user "$(id -u):$(id -g)" --network test_oidc -v "$tmpd:/tmp" \
    curlimages/curl:8.10.1 --silent -o /dev/null -w '%{http_code}' \
    --cookie /tmp/oidc-bc-cookies --connect-to demo.example.com:80:nginx:80 \
    http://demo.example.com/)
[ "$sess_code" = "302" ]
rm -f "$tmpd/oidc-bc-cookies"

rm -f "$tmpd/oidc-e2e-cookies"
printf '%s\n' 'E2E passed'
