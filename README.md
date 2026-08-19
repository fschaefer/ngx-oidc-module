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
- Refresh-token rotation with atomic SQLite transactions (server-side only)
- Optional UserInfo lookup with `sub` binding
- Local and RP-initiated logout
- Provider-specific session/state cookies for multi-IdP deployments
- Original local request path and query restored after callback

## Limits

Not implemented:

- Clustered/multi-host session storage
- Backchannel/frontchannel logout
- Token revocation

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
        scopes openid profile email;

        redirect_uri /_oidc_callback;
        logout_uri /logout;
        post_logout_uri https://app.example.com/;

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

`client_id` and `client_secret` are mandatory. `redirect_uri` and `logout_uri` must be local paths. `session_max_age` must be positive.

## Directives

### `oidc_provider <name> { ... }`

Provider block in `http` context.

| Directive | Required | Description |
| --- | --- | --- |
| `issuer <url>` | Yes | Expected issuer URL. Discovery document and ID token must match exactly. |
| `client_id <id>` | Yes | OIDC client ID. |
| `client_secret <secret>` | Yes | Confidential-client credential for token endpoint. |
| `session_encryption_key <secret>` | No | AES-GCM cookie key material. Defaults to `client_secret`; configure separately in production. |
| `session_store sqlite:<path>` | No | SQLite persistent session store. Browser receives opaque session ID. |
| `ssl_trusted_certificate <path>` | No | CA bundle for IdP TLS verification. |
| `config_url <url>` | No | Discovery endpoint override. |
| `scopes <scopes>` | No | Default: `openid`. |
| `redirect_uri <path>` | No | Local callback path. Default: `/_oidc_callback`. |
| `logout_uri <path>` | No | Local logout path. |
| `post_logout_uri <url>` | No | Redirect target after IdP logout. |
| `userinfo on\|off` | No | Fetch UserInfo during callback. Default: `off`. |
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

For provider `company_idp` with:

```nginx
session_cookie oidc_session_company;
```

state cookie becomes `oidc_session_company_state`. Without `session_cookie`, defaults remain `oidc_session` and `oidc_state`.

## Test

Requires Docker and Docker Compose.

```sh
./test/e2e.sh
```

Test covers build, discovery, PKCE, JWKS rotation, `aud` array plus `azp`, `max_age` plus `auth_time`, UserInfo, encrypted cookie, expiry, original URI restore, session survival across nginx restart, forced refresh-token rotation, and RP logout.

## Security Notes

- Use HTTPS in production. Cookie `Secure` is applied only to HTTPS connections.
- Keep `client_secret` and `session_encryption_key` outside version control. Generate final nginx config from your deployment secret manager; nginx does not expand `${...}` in these directive values.
- Use a dedicated `session_cookie` for every provider sharing a domain.
- Keep UserInfo claims small; session cookie limit is intentional.
- `post_logout_uri` must be registered at IdP.
- SQLite is single-host storage. Do not use it across load-balanced nginx nodes or NFS.
- Delete the SQLite file when upgrading across module versions that change the session schema; old rows are not migrated.
