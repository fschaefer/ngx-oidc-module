#!/usr/bin/env python3
"""Automated Keycloak flow for ngx-oidc-module (standard library only).

Logs in through the real Keycloak authorization page, checks the claims the
backend receives, then performs an RP-initiated logout and verifies that both
the nginx session and the Keycloak session are gone.

Run it inside a container attached to the compose network (keycloak-e2e.sh), or
on a host that resolves app.test and keycloak.test to the Docker host. The CA
used to verify keycloak.test is read from KC_CA (default /certs/ca.crt).
"""

import base64
import http.cookiejar
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

CA = os.environ.get("KC_CA", "/certs/ca.crt")
APP = "http://app.test/"
LOGOUT = "http://app.test/logout"
USER = os.environ.get("KC_USER", "jane")
PASSWORD = os.environ.get("KC_PASSWORD", "jane-password")
REALM = os.environ.get("KC_REALM", "https://keycloak.test:8443/realms/oidc-test")

failures = []


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def session():
    jar = http.cookiejar.CookieJar()
    ctx = ssl.create_default_context(cafile=CA)
    return jar, urllib.request.build_opener(
        NoRedirect(), urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=ctx))


def follow(opener, url, data=None, headers=None, limit=10):
    """Perform a request, following redirects by hand so every hop is visible."""
    hops = []
    for _ in range(limit):
        req = urllib.request.Request(url, data=data, headers=headers or {})
        try:
            resp = opener.open(req)
        except urllib.error.HTTPError as err:
            resp = err
        body = resp.read()
        hops.append((resp.status, url, resp.headers, body))
        print("  %d %s" % (resp.status, url))
        location = resp.headers.get("Location")
        if resp.status in (301, 302, 303, 307, 308) and location and len(hops) < limit:
            url, data, headers = urllib.parse.urljoin(url, location), None, None
            continue
        break
    return hops


def check(name, ok, info=""):
    print(("PASS " if ok else "FAIL ") + name + ((" | " + str(info)) if info else ""))
    if not ok:
        failures.append(name)


def main():
    jar, opener = session()

    print("1) request a protected location")
    hops = follow(opener, APP)
    check("Keycloak authorization page is reached",
          "/protocol/openid-connect/auth" in "".join(h[1] for h in hops)
          and "kc-form-login" in hops[-1][3].decode(errors="replace"))
    login_page = hops[-1]
    form = re.search(r'<form[^>]+id="kc-form-login"[^>]*action="([^"]+)"',
                     login_page[3].decode(errors="replace"), re.S)
    check("login form present", form is not None)
    if form is None:
        return 1
    action = form.group(1).replace("&amp;", "&")

    print("2) submit credentials")
    body = urllib.parse.urlencode({"username": USER, "password": PASSWORD,
                                   "credentialId": ""}).encode()
    hops = follow(opener, action, data=body,
                  headers={"Content-Type": "application/x-www-form-urlencoded"})
    text = hops[-1][3].decode(errors="replace")
    check("backend answers", hops[-1][0] == 200, text.strip()[:80])
    check("ID token claims reach the backend", "Hello, Jane Doe!" in text
          and "Email: jane@example.com" in text, text.strip().replace("\n", " | ")[:120])
    issued = [c.value for c in jar if c.name == "oidc_keycloak_session"]
    check("session cookie issued, opaque",
          bool(issued) and all(issued) and not any("eyJ" in v for v in issued),
          "cookies: " + ",".join(sorted(c.name for c in jar)))

    print("3) RP-initiated logout")
    hops = follow(opener, LOGOUT)
    location = hops[0][2].get("Location", "")
    check("end_session_endpoint redirect", "/protocol/openid-connect/logout" in location,
          location[:110])
    check("id_token_hint sent", "id_token_hint=" in location)
    check("post_logout_redirect_uri sent", "post_logout_redirect_uri=" in location)
    check("local session cookie cleared",
          any(c.name == "oidc_keycloak_session" and not c.value for c in jar))
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(location).query)
    if "id_token_hint" in query:
        token = query["id_token_hint"][0]
        payload = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(
            payload + "=" * (-len(payload) % 4)))
        check("id_token_hint belongs to this session",
              claims.get("iss") == REALM and claims.get("sub"), json.dumps(claims)[:110])
    else:
        check("id_token_hint belongs to this session", False, "no hint in redirect by %s" % APP)
        return 1

    print("4) IdP-side logout")
    hops = follow(opener, location, limit=8)
    check("post-logout target reached", hops[-1][0] == 200)
    check("Keycloak session ended (login form again)",
          "kc-form-login" in hops[-1][3].decode(errors="replace"))

    print()
    if failures:
        print("FLOW FAILED: " + ", ".join(failures))
        return 1
    print("Keycloak flow passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
