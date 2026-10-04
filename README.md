# ngx-oidc-module

Minimal nginx dynamic module for OpenID Connect Authorization Code Flow.

## Features

- OIDC Discovery with configured `issuer` validation
- Authorization Code Flow with PKCE `S256`
- RS256 ID-token validation via JWKS
- JWKS reload once on unknown `kid` for key rotation
- Validates `exp`, `iss`, `aud`, `azp`, `nonce`, optional `auth_time`
- AES-256-GCM encrypted session cookies
- Cookie expiry capped by ID-token `exp` and optional `session_max_age`
- SQLite-backed opaque sessions surviving nginx restart
- Refresh-token rotation and RFC 7009 revocation at RP logout (server-side only)
- Optional UserInfo lookup with `sub` binding
- Local, RP-initiated, and OIDC Backchannel Logout
- Provider-specific session/state cookies for multi-IdP deployments
- Original local request path and query restored after callback

## Limits

Not implemented:

- Clustered/multi-host session storage
- Frontchannel logout

Every endpoint advertised by the discovery document must live on the issuer's
host (https). Cross-origin token/JWKS/UserInfo endpoints are rejected at
discovery time.

## Build

Build nginx 1.31.3 and dynamic module:

```sh
docker build -t ngx-oidc-module .
```

Load module in nginx config:

```nginx
load_module modules/ngx_http_oidc_module.so;
```

For a native nginx source build:

```sh
./configure --with-http_ssl_module --add-dynamic-module=/path/to/ngx-oidc-module
make modules
```

Build requires OpenSSL, Jansson, and SQLite. Runtime requires `libssl3`, `libjansson4`, and `libsqlite3-0` on Debian Bookworm.

## Configuration

```nginx
http {
    resolver 10.0.0.2 ipv4=on valid=300s;

    oidc_provider company_idp {
        issuer        https://idp.example.com/realms/company;
        client_id     nginx-app;
        client_secret secret-from-your-secret-manager;

        # Keep this key in a secret manager. It prevents client-secret
        # rotation from invalidating existing encrypted sessions.
        session_encryption_key session-key-from-your-secret-manager;
        session_store sqlite:/var/lib/nginx/oidc/sessions.db;

        ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
        scopes "openid profile email";

        redirect_uri /_oidc_callback;
        logout_uri /logout;
        post_logout_uri https://app.example.com/;
        backchannel_logout_uri /_oidc_backchannel;

        userinfo on;
        session_max_age 8h;
        session_cookie oidc_session_company;
    }

    server {
        listen 443 ssl;
        server_name app.example.com;

        location / {
            auth_oidc company_idp;
            proxy_set_header X-OIDC-Sub $oidc_claim_sub;
            proxy_set_header X-OIDC-Email $oidc_claim_email;
            proxy_set_header X-OIDC-Department $oidc_userinfo_department;
            proxy_pass http://app_backend;
        }

        # Require IdP authentication no older than 15 minutes.
        location /admin/ {
            auth_oidc company_idp max_age=15m;
            proxy_pass http://app_backend;
        }
    }
}
```

`client_id` and `client_secret` are mandatory. `redirect_uri`, `logout_uri`, and `backchannel_logout_uri` must be local paths. `scopes` is one quoted value. `session_max_age` must be positive.

## Directives

### `oidc_provider <name> { ... }`

Provider block in `http` context.

| Directive | Required | Description |
| --- | --- | --- |
| `issuer <url>` | Yes | Expected issuer URL. Discovery document and ID token must match exactly. |
| `client_id <id>` | Yes | OIDC client ID. |
| `client_secret <secret>` | Yes | Confidential-client credential for token endpoint. |
| `session_encryption_key <secret>` | Yes | AES-GCM cookie key material. Required; there is no fallback to `client_secret`. |
| `session_store sqlite:<path>` | No | SQLite persistent session store. Browser receives opaque session ID. |
| `ssl_trusted_certificate <path>` | No | CA bundle for IdP TLS verification. |
| `config_url <url>` | No | Discovery endpoint override. |
| `scopes <scopes>` | No | Default: `openid`. |
| `redirect_uri <path>` | No | Local callback path. Default: `/_oidc_callback`. |
| `logout_uri <path>` | No | Local logout path. |
| `post_logout_uri <url>` | No | Redirect target after IdP logout. |
| `backchannel_logout_uri <path>` | No | Local IdP POST endpoint for OIDC Backchannel Logout. Requires `session_store` for session revocation. |
| `userinfo on` / `off` | No | Fetch UserInfo during callback. Default: `off`. |
| `session_max_age <duration>` | No | Extra session ceiling, capped by ID-token expiry. |
| `session_cookie <name>` | No | Session cookie name. Use one per provider on same domain. |

### `auth_oidc <provider> [max_age=<duration>]`

Location directive selecting a provider.

```nginx
auth_oidc company_idp;
auth_oidc company_idp max_age=15m;
```

`max_age` sends OIDC `max_age` to IdP and requires ID-token `auth_time` within duration. Use on sensitive locations only.

## Claims

ID-token claims:

```nginx
$oidc_claim_sub
$oidc_claim_email
$oidc_claim_name
```

UserInfo claims, when `userinfo on`:

```nginx
$oidc_userinfo_department
$oidc_userinfo_email
```

Namespaces stay separate. UserInfo `sub` must match validated ID-token `sub`.

## Cookies

Session cookie is AES-256-GCM encrypted and `HttpOnly; SameSite=Lax`; HTTPS requests also receive `Secure`.

Cookie expiry:

```text
min(ID-token exp - now, session_max_age)
```

Cookie payload limit is 3800 bytes. Large UserInfo responses fail login rather than exceeding browser cookie limits. With `session_store sqlite:<path>`, browser receives a 256-bit opaque ID and encrypted cookie payload is stored in SQLite instead.

SQLite uses WAL mode and a 5-second busy timeout. Use only local filesystem storage, keep database directory owned by nginx user and outside webroot, and do not place it on NFS.

### Refresh tokens

Requires `session_store`. Refresh tokens never reach the browser; they are AES-256-GCM encrypted in SQLite. When the access token expires within 60 seconds, the module sends `grant_type=refresh_token` to the token endpoint, stores the rotated refresh token and new expiry atomically (`BEGIN IMMEDIATE`), and serves the request from the still-valid session identity. On `invalid_grant` or any refresh failure the session row is deleted and the user is redirected to a fresh login.

Absolute session lifetime stays capped by `session_max_age`/ID-token `exp`; refresh does not extend it.

### Token revocation

At RP logout, module reads encrypted ID and refresh tokens from SQLite, calls IdP discovery `revocation_endpoint` per RFC 7009 with `token_type_hint=refresh_token` and client Basic authentication, then redirects to `end_session_endpoint` with `post_logout_redirect_uri` and `id_token_hint`. Missing endpoint, discovery failure, or revocation failure is logged and does not block local logout: browser cookie and SQLite session are still deleted.

### Backchannel Logout

Set `backchannel_logout_uri` and register its public HTTPS URL at IdP. IdP `POST`s form field `logout_token`; module validates signature, issuer, audience, expiry, Backchannel Logout event, and absence of `nonce`. With `session_store`, matching session rows are deleted: `sid` targets one session; `sub` is fallback and deletes all sessions for user. Endpoint returns `200` on accepted token and `400` on invalid token.

For provider `company_idp` with:

```nginx
session_cookie oidc_session_company;
```

state cookie becomes `oidc_session_company_state`. Without `session_cookie`, defaults remain `oidc_session` and `oidc_state`.

## Test

Requires Docker and Docker Compose. Test certificates are generated on
demand and renewed automatically once they are expired.

```sh
./test/e2e.sh
```

Mock E2E covers build, discovery, PKCE, JWKS rotation, `aud` array plus `azp`, `max_age` plus `auth_time`, UserInfo, encrypted cookie, expiry, original URI restore, session survival across nginx restart, forced refresh-token rotation, RFC 7009 revocation plus `id_token_hint` at RP logout, Backchannel Logout session revocation, and two providers sharing one SQLite file without sharing browser cookies or authorization.

### Browser test with Keycloak

Runs Nginx, a minimal Python backend, and Keycloak. This uses a real authorization page instead of the automatic mock-IdP redirect.

```sh
./test/keycloak-up.sh
```

Map both names to Docker host before opening the app:

```text
127.0.0.1 app.test keycloak.test
```

Open `http://app.test/`. Keycloak login appears at `https://keycloak.test:8443`. Trust `test/certs/ca.crt` in browser or accept its test-certificate warning. Log in as `jane` with password `jane-password`. Backend response contains Keycloak ID-token claims.

Open `http://app.test/logout` to test RP logout. Nginx removes its SQLite session, sends Keycloak `id_token_hint`, and returns to `http://app.test/`. That route is protected, so Keycloak login appears again; this confirms the local and Keycloak sessions ended.

Stop stack:

```sh
docker compose -f test/docker-compose.keycloak.yml --profile idp down
```

On Apple Silicon, Keycloak runs as `linux/amd64` because current native image crashes during JVM startup. First start under emulation takes roughly one minute.

### Automated Keycloak flow

```sh
./test/keycloak-e2e.sh
```

Brings the stack up, drives login and RP logout from a container on the compose
network, and asserts that the ID-token claims reach the backend, that the
end-session redirect carries `id_token_hint`, and that the Keycloak session is
gone afterwards. The stack is torn down again unless `KEEP=1` is set. No
`/etc/hosts` entry is needed for this variant.

### Against an external Keycloak

The stack can also rely on an IdP that already runs elsewhere (for example a
shared test Keycloak on another host). Only nginx and the backend are started;
issuer and the IdP's CA come from the environment:

```sh
KC_ISSUER=https://idp.example:8443/realms/oidc-test \
KC_CA=/path/to/idp-ca.crt ./test/keycloak-remote-e2e.sh
```

The template `test/nginx-keycloak-remote.conf.in` is rendered into
`test/nginx-keycloak-remote.conf`, so no host name is baked into the repository.
Nothing is published on port 80 here (`APP_PORT`, default 8099, only exists to
reach the stack by hand); the flow itself runs on the compose network.

## Security Notes

- Use HTTPS in production. Cookie `Secure` is applied only to HTTPS connections.
- Keep `client_secret` and `session_encryption_key` outside version control. Generate final nginx config from your deployment secret manager; nginx does not expand `${...}` in these directive values.
- Use a dedicated `session_cookie` for every provider sharing a domain.
- Keep UserInfo claims small; session cookie limit is intentional.
- `post_logout_uri` and public `backchannel_logout_uri` must be registered at IdP. Backchannel endpoint must be reachable by IdP over HTTPS.
- The callback URI is assembled from the request `Host` header, so a listener on a non-default port yields `host:port`; register exactly that URI at the IdP and keep `Host` intact when running behind another proxy.
- For a supervised, non-test deployment (TLS, SQLite session volume, systemd unit) see `example/docker-service/`.
- SQLite is single-host storage. Do not use it across load-balanced nginx nodes or NFS.
- Delete the SQLite file when upgrading across module versions that change the session schema; old rows are not migrated.
- Backend calls to the IdP (discovery, JWKS, token, UserInfo, refresh,
  revocation) run inside nginx workers with a 30-second timeout and an
  8 MiB response cap, so a slow or misbehaving IdP cannot pin workers or
  exhaust memory.

## License

BSD 2-Clause. See `LICENSE`.
