#ifndef _NGX_HTTP_OIDC_H_INCLUDED_
#define _NGX_HTTP_OIDC_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <jansson.h>
#include <sqlite3.h>

#define NGX_OIDC_DEFAULT_SCOPES      "openid"
#define NGX_OIDC_DEFAULT_REDIRECT    "/_oidc_callback"
#define NGX_OIDC_DEFAULT_COOKIE      "oidc_session"
#define NGX_OIDC_STATE_COOKIE        "oidc_state"
#define NGX_OIDC_JWKS_TTL            3600
#define NGX_OIDC_MAX_COOKIE_LEN       3800

typedef struct {
    ngx_str_t   name;

    /* configured */
    ngx_str_t   issuer;
    ngx_str_t   client_id;
    ngx_str_t   client_secret;
    ngx_str_t   session_encryption_key;
    ngx_str_t   session_store;
    sqlite3    *session_db;
    ngx_str_t   config_url;
    ngx_str_t   ssl_trusted_certificate;
    ngx_str_t   scopes;
    ngx_str_t   redirect_uri;
    ngx_str_t   logout_uri;
    ngx_str_t   backchannel_logout_uri;
    ngx_str_t   post_logout_uri;
    time_t      session_max_age;
    ngx_flag_t  userinfo;

    /* discovered */
    ngx_str_t   authorization_endpoint;
    ngx_str_t   token_endpoint;
    ngx_str_t   revocation_endpoint;
    ngx_str_t   end_session_endpoint;
    ngx_str_t   userinfo_endpoint;
    ngx_str_t   jwks_uri;

    /* runtime */
    ngx_str_t   jwks;              /* raw JWKS JSON */
    time_t      jwks_fetched;
    ngx_str_t   cookie_name;
    ngx_str_t   state_cookie_name;
    ngx_str_t   hmac_key;          /* derived from client_secret */
} ngx_http_oidc_provider_t;

typedef struct {
    ngx_array_t  providers;        /* ngx_http_oidc_provider_t */
} ngx_http_oidc_main_conf_t;

typedef struct {
    ngx_http_oidc_provider_t  *provider;
    time_t                     max_age;
} ngx_http_oidc_loc_conf_t;

typedef struct {
    ngx_str_t  claims;
    ngx_str_t  userinfo;
    ngx_http_oidc_provider_t  *provider;
} ngx_http_oidc_request_ctx_t;

/* http.c */
typedef struct {
    ngx_str_t   body;
    ngx_int_t   status;
} ngx_http_oidc_http_resp_t;

ngx_int_t ngx_http_oidc_http_get(ngx_pool_t *pool, ngx_log_t *log,
    ngx_str_t *url, ngx_str_t *trusted_ca, ngx_str_t *auth_header,
    ngx_http_oidc_http_resp_t *resp);
ngx_int_t ngx_http_oidc_http_post_form(ngx_pool_t *pool, ngx_log_t *log,
    ngx_str_t *url, ngx_str_t *trusted_ca, ngx_str_t *auth_header,
    ngx_str_t *body, ngx_http_oidc_http_resp_t *resp);
ngx_int_t ngx_http_oidc_endpoint_matches_issuer(ngx_str_t *issuer,
    ngx_str_t *endpoint);

/* jwt.c */
ngx_int_t ngx_http_oidc_jwt_verify(ngx_log_t *log, ngx_pool_t *pool,
    ngx_str_t *jwt, ngx_str_t *jwks, ngx_str_t *issuer, ngx_str_t *client_id,
    ngx_str_t *nonce, time_t max_age, ngx_flag_t check_exp,
    ngx_str_t *claims_out);

/* json.c */
ngx_int_t ngx_http_oidc_json_get_string(ngx_pool_t *pool, ngx_str_t *json,
    ngx_str_t *key, ngx_str_t *out);
ngx_int_t ngx_http_oidc_json_array_contains(ngx_str_t *json, ngx_str_t *key,
    ngx_str_t *needle);
ngx_int_t ngx_http_oidc_json_has_key(ngx_str_t *json, ngx_str_t *key);
ngx_int_t ngx_http_oidc_json_object_has_key(ngx_str_t *json, ngx_str_t *key,
    ngx_str_t *member);

/* base64url helpers (jwt.c) */
ngx_int_t ngx_http_oidc_b64url_decode(ngx_pool_t *pool, ngx_str_t *in,
    ngx_str_t *out);
ngx_int_t ngx_http_oidc_b64url_encode(ngx_pool_t *pool, ngx_str_t *in,
    ngx_str_t *out);

/* hmac helper (jwt.c) */
ngx_int_t ngx_http_oidc_hmac_sha256(ngx_pool_t *pool, ngx_str_t *key,
    ngx_str_t *data, ngx_str_t *out);

/* module.c */
ngx_int_t ngx_http_oidc_start_flow(ngx_http_request_t *r,
    ngx_http_oidc_provider_t *p, time_t max_age);

#endif /* _NGX_HTTP_OIDC_H_INCLUDED_ */
