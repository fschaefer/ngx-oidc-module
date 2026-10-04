# Running the module as a service in front of an application

Recipe for a deployment that is not a test harness: the module terminates TLS,
keeps sessions in a SQLite volume and proxies to the application, supervised by
a systemd unit. It is the shape that runs on a lab box, verified end to end
against a Keycloak IdP.

## Files

| File | Purpose |
| --- | --- |
| `compose.yml` | application + nginx with the module, volumes, fixed subnet |
| `nginx.conf.in` | configuration template, secrets filled in at start |
| `nginx-oidc.service` | systemd unit (oneshot, rebuilds the image, compose up/down) |
| `certs/` | server certificate plus the IdP CA (`ca.crt` as `ssl_trusted_certificate`) |
| `.env` (0600) | `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_SESSION_KEY`, `PUBLIC_URL`, `PUBLIC_HOST`, `PUBLIC_PORT`, `APP_ADMIN_PASSWORD` |

## Steps

1. Build the image from this repository:
   `docker build -t ngx-oidc-service /path/to/ngx-oidc-module`
2. Register a confidential client at the IdP whose redirect URI matches
   `PUBLIC_URL + OIDC_REDIRECT_URI` exactly, and add the post-logout redirect URI
   `PUBLIC_URL/`.
3. Put the secrets into `.env` (0600) and the certificates into `certs/`.
4. `sudo systemctl enable --now nginx-oidc`

## Verifying it

The flow test in `test/keycloak-flow.py` drives any deployment, not just the
test stack:

```sh
KC_CA=certs/ca.crt \
KC_APP="$PUBLIC_URL/api/user" \
KC_LOGOUT="$PUBLIC_URL/logout" \
KC_REALM="$OIDC_ISSUER" \
KC_COOKIE=oidc_session_app \
KC_EXPECT='"login":"jane"' \
python3 test/keycloak-flow.py
```

## Pitfalls found while building this

- **The session directory must belong to the nginx worker.** The volume mount
  creates it as root, the worker runs as `nobody` and SQLite then fails with
  `unable to open database file`. The compose command fixes ownership before
  nginx starts.
- **A listener on a non-default port needs the port in the callback URI.** The
  module builds `redirect_uri` from the request `Host` header; providers compare
  it exactly, so `https://host:9443/...` must be registered as such.
- **`Host` must be preserved by anything in front.** Behind another proxy,
  forward the external Host header (and consider `X-Forwarded-Host`), otherwise
  the callback URI and the discovery issuer no longer match.
- **`docker compose down` ignores services behind a profile**, so a stack that
  uses profiles must name them when stopping.
