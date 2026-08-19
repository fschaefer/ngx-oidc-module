#!/usr/bin/env python3
"""Mock OIDC IdP for testing the nginx OIDC module end-to-end."""
import base64
import hashlib
import json
import time
import http.server
import ssl
import urllib.parse

import rsa

ISSUER = "https://idp.test:8443"
HOST = "0.0.0.0"
PORT = 8443

# Generate old/new signing keys to exercise JWKS key rotation.
(old_pub, old_key) = rsa.newkeys(2048)
(pub, key) = rsa.newkeys(2048)

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def int_to_b64url(n: int) -> str:
    nbytes = (n.bit_length() + 7) // 8
    return b64url(n.to_bytes(nbytes, "big"))

OLD_JWKS = {
    "keys": [{
        "kty": "RSA", "alg": "RS256", "use": "sig", "kid": "old-key",
        "n": int_to_b64url(old_pub.n), "e": int_to_b64url(old_pub.e),
    }]
}
JWKS = {
    "keys": [{
        "kty": "RSA", "alg": "RS256", "use": "sig", "kid": "test-key-1",
        "n": int_to_b64url(pub.n), "e": int_to_b64url(pub.e),
    }]
}

def make_id_token(code: str, nonce: str) -> str:
    header = {"alg": "RS256", "kid": "test-key-1", "typ": "JWT"}
    now = int(time.time())
    payload = {
        "iss": ISSUER,
        "sub": "user-12345",
        "aud": ["test-client", "other-client"],
        "azp": "test-client",
        "exp": now + 3600,
        "iat": now,
        "auth_time": now,
        "nonce": nonce,
        "email": "jane@example.com",
        "name": "Jane Doe",
    }
    signing_input = b64url(json.dumps(header).encode()) + "." + b64url(json.dumps(payload).encode())
    sig = rsa.sign(signing_input.encode(), key, "SHA-256")
    return signing_input + "." + b64url(sig)

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"[idp] {self.client_address[0]} {fmt % args}", flush=True)

    def _json(self, obj, status=200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/.well-known/openid-configuration":
            self._json({
                "issuer": ISSUER,
                "authorization_endpoint": ISSUER + "/authorize",
                "token_endpoint": ISSUER + "/token",
                "jwks_uri": ISSUER + "/jwks",
                "userinfo_endpoint": ISSUER + "/userinfo",
                "end_session_endpoint": ISSUER + "/logout",
            })
        elif parsed.path == "/jwks":
            Handler.jwks_requests += 1
            self._json(OLD_JWKS if Handler.jwks_requests == 1 else JWKS)
        elif parsed.path == "/userinfo":
            if self.headers.get("Authorization") != "Bearer mock-access-token":
                self._json({"error": "invalid_token"}, 401)
                return
            self._json({
                "sub": "user-12345",
                "email": "userinfo-jane@example.com",
                "department": "Engineering",
            })
        elif parsed.path == "/logout":
            redirect_uri = urllib.parse.parse_qs(parsed.query).get(
                "post_logout_redirect_uri", [""]
            )[0]
            if redirect_uri:
                self.send_response(302)
                self.send_header("Location", redirect_uri)
                self.end_headers()
            else:
                self.send_response(204)
                self.end_headers()
        elif parsed.path == "/authorize":
            q = urllib.parse.parse_qs(parsed.query)
            redirect_uri = q.get("redirect_uri", [""])[0]
            state = q.get("state", [""])[0]
            nonce = q.get("nonce", [""])[0]
            code_challenge = q.get("code_challenge", [""])[0]
            if q.get("code_challenge_method", [""])[0] != "S256" or not code_challenge:
                self._json({"error": "invalid_request"}, 400)
                return
            Handler.last_challenge = code_challenge
            # immediately redirect back with a code
            loc = redirect_uri + "?code=mock-code-123&state=" + urllib.parse.quote(state)
            self.send_response(302)
            self.send_header("Location", loc)
            self.end_headers()
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/token":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode()
            form = urllib.parse.parse_qs(body)
            if form.get("grant_type", [""])[0] == "refresh_token":
                sent = form.get("refresh_token", [""])[0]
                if not sent or sent != Handler.last_refresh:
                    self._json({"error": "invalid_grant"}, 400)
                    return
                Handler.refresh_counter += 1
                Handler.last_refresh = f"mock-refresh-{Handler.refresh_counter}"
                self._json({
                    "access_token": "mock-access-token",
                    "token_type": "Bearer",
                    "expires_in": 3,
                    "refresh_token": Handler.last_refresh,
                })
                return
            code = form.get("code", [""])[0]
            verifier = form.get("code_verifier", [""])[0]
            challenge = b64url(hashlib.sha256(verifier.encode()).digest())
            if not verifier or challenge != Handler.last_challenge:
                self._json({"error": "invalid_grant"}, 400)
                return
            # nonce is not in token request; we stash it via state earlier.
            # For the mock, we read nonce from a global set by /authorize.
            nonce = Handler.last_nonce
            id_token = make_id_token(code, nonce)
            Handler.refresh_counter += 1
            Handler.last_refresh = f"mock-refresh-{Handler.refresh_counter}"
            self._json({
                "access_token": "mock-access-token",
                "token_type": "Bearer",
                "id_token": id_token,
                "expires_in": 3,
                "refresh_token": Handler.last_refresh,
            })
        else:
            self._json({"error": "not found"}, 404)

Handler.last_nonce = ""
Handler.last_challenge = ""
Handler.jwks_requests = 0
Handler.refresh_counter = 0
Handler.last_refresh = ""

# patch authorize to record nonce
orig_do_GET = Handler.do_GET
def do_GET(self):
    parsed = urllib.parse.urlparse(self.path)
    if parsed.path == "/authorize":
        q = urllib.parse.parse_qs(parsed.query)
        Handler.last_nonce = q.get("nonce", [""])[0]
    orig_do_GET(self)
Handler.do_GET = do_GET

if __name__ == "__main__":
    srv = http.server.HTTPServer((HOST, PORT), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile="/certs/idp.crt", keyfile="/certs/idp.key")
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print(f"mock IdP listening on {HOST}:{PORT}")
    srv.serve_forever()
