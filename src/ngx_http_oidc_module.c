#include "ngx_http_oidc.h"

#define NGX_HTTP_OIDC_CONF  0x10000000

static ngx_int_t ngx_http_oidc_init(ngx_conf_t *cf);
static void *ngx_http_oidc_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_oidc_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_oidc_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_oidc_provider(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_oidc_auth(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_oidc_provider_param(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static ngx_int_t ngx_http_oidc_access_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_oidc_callback_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_oidc_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_oidc_discover(ngx_http_oidc_provider_t *p,
    ngx_log_t *log);
static ngx_int_t ngx_http_oidc_fetch_jwks(ngx_http_oidc_provider_t *p,
    ngx_log_t *log);
static ngx_int_t ngx_http_oidc_exchange_code(ngx_http_request_t *r,
    ngx_http_oidc_provider_t *p, ngx_str_t *code, ngx_str_t *code_verifier,
    ngx_str_t *id_token_out, ngx_str_t *access_token_out,
    ngx_str_t *refresh_token_out, time_t *access_expires_out);
static ngx_int_t ngx_http_oidc_fetch_userinfo(ngx_http_request_t *r,
    ngx_http_oidc_provider_t *p, ngx_str_t *access_token, ngx_str_t *id_claims,
    ngx_str_t *userinfo_out);
static ngx_int_t ngx_http_oidc_issue_session(ngx_http_request_t *r,
    ngx_http_oidc_provider_t *p, ngx_str_t *id_token, ngx_str_t *claims,
    ngx_str_t *userinfo, ngx_str_t *refresh_token, time_t access_expires);
static ngx_int_t ngx_http_oidc_validate_session(ngx_http_request_t *r,
    ngx_http_oidc_provider_t *p, ngx_str_t *claims_out, ngx_str_t *userinfo_out);
static ngx_int_t ngx_http_oidc_redirect(ngx_http_request_t *r, ngx_str_t *url);
static ngx_int_t ngx_http_oidc_backchannel(ngx_http_request_t *r,
    ngx_http_oidc_provider_t *p);
static void ngx_http_oidc_backchannel_done(ngx_http_request_t *r);
static ngx_int_t ngx_http_oidc_get_body_arg(ngx_http_request_t *r,
    ngx_str_t *name, ngx_str_t *value);
static ngx_int_t ngx_http_oidc_logout(ngx_http_request_t *r,
    ngx_http_oidc_provider_t *p);
static void ngx_http_oidc_revoke_refresh_token(ngx_http_request_t *r,
    ngx_http_oidc_provider_t *p, ngx_str_t *cookie);
static ngx_int_t ngx_http_oidc_build_redirect_uri(ngx_http_request_t *r,
    ngx_http_oidc_provider_t *p, ngx_str_t *out);
static ngx_int_t ngx_http_oidc_random(ngx_pool_t *pool, size_t len,
    ngx_str_t *out);
static ngx_int_t ngx_http_oidc_session_encrypt(ngx_pool_t *pool,
    ngx_http_oidc_provider_t *p, ngx_str_t *plaintext, ngx_str_t *out);
static ngx_int_t ngx_http_oidc_session_decrypt(ngx_pool_t *pool,
    ngx_http_oidc_provider_t *p, ngx_str_t *in, ngx_str_t *plaintext);
static ngx_int_t ngx_http_oidc_session_db_open(ngx_http_oidc_provider_t *p,
    ngx_log_t *log);
static ngx_int_t ngx_http_oidc_session_db_store(ngx_http_request_t *r,
    ngx_http_oidc_provider_t *p, ngx_str_t *session, ngx_str_t *refresh_token,
    time_t access_expires, time_t expires, ngx_str_t *sid, ngx_str_t *sub,
    ngx_str_t *cookie);
static ngx_int_t ngx_http_oidc_session_db_load(ngx_http_request_t *r,
    ngx_http_oidc_provider_t *p, ngx_str_t *cookie, ngx_str_t *session,
    ngx_str_t *refresh_token, time_t *access_expires);
static void ngx_http_oidc_session_db_delete(ngx_http_oidc_provider_t *p,
    ngx_str_t *cookie);
static ngx_int_t ngx_http_oidc_refresh_session(ngx_http_request_t *r,
    ngx_http_oidc_provider_t *p, ngx_str_t *cookie, ngx_str_t *refresh_token);
static ngx_int_t ngx_http_oidc_session_db_delete_sub(
    ngx_http_oidc_provider_t *p, ngx_str_t *sid, ngx_str_t *sub,
    ngx_log_t *log);
static ngx_int_t ngx_http_oidc_get_cookie(ngx_http_request_t *r,
    ngx_str_t *name, ngx_str_t *value);
static ngx_int_t ngx_http_oidc_set_cookie(ngx_http_request_t *r,
    ngx_str_t *name, ngx_str_t *value, ngx_str_t *path, time_t max_age);
static ngx_int_t ngx_http_oidc_get_query_arg(ngx_http_request_t *r,
    ngx_str_t *name, ngx_str_t *value);

static ngx_command_t  ngx_http_oidc_commands[] = {

    { ngx_string("oidc_provider"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
      ngx_http_oidc_provider,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("auth_oidc"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE12,
      ngx_http_oidc_auth,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("issuer"),
      NGX_HTTP_OIDC_CONF|NGX_CONF_TAKE1,
      ngx_http_oidc_provider_param,
      0,
      0,
      NULL },

    { ngx_string("client_id"),
      NGX_HTTP_OIDC_CONF|NGX_CONF_TAKE1,
      ngx_http_oidc_provider_param,
      0,
      0,
      NULL },

    { ngx_string("client_secret"),
      NGX_HTTP_OIDC_CONF|NGX_CONF_TAKE1,
      ngx_http_oidc_provider_param,
      0,
      0,
      NULL },

    { ngx_string("session_encryption_key"),
      NGX_HTTP_OIDC_CONF|NGX_CONF_TAKE1,
      ngx_http_oidc_provider_param,
      0,
      0,
      NULL },

    { ngx_string("session_store"),
      NGX_HTTP_OIDC_CONF|NGX_CONF_TAKE1,
      ngx_http_oidc_provider_param,
      0,
      0,
      NULL },

    { ngx_string("config_url"),
      NGX_HTTP_OIDC_CONF|NGX_CONF_TAKE1,
      ngx_http_oidc_provider_param,
      0,
      0,
      NULL },

    { ngx_string("ssl_trusted_certificate"),
      NGX_HTTP_OIDC_CONF|NGX_CONF_TAKE1,
      ngx_http_oidc_provider_param,
      0,
      0,
      NULL },

    { ngx_string("scopes"),
      NGX_HTTP_OIDC_CONF|NGX_CONF_TAKE1,
      ngx_http_oidc_provider_param,
      0,
      0,
      NULL },

    { ngx_string("redirect_uri"),
      NGX_HTTP_OIDC_CONF|NGX_CONF_TAKE1,
      ngx_http_oidc_provider_param,
      0,
      0,
      NULL },

    { ngx_string("logout_uri"),
      NGX_HTTP_OIDC_CONF|NGX_CONF_TAKE1,
      ngx_http_oidc_provider_param,
      0,
      0,
      NULL },

    { ngx_string("post_logout_uri"),
      NGX_HTTP_OIDC_CONF|NGX_CONF_TAKE1,
      ngx_http_oidc_provider_param,
      0,
      0,
      NULL },

    { ngx_string("userinfo"),
      NGX_HTTP_OIDC_CONF|NGX_CONF_FLAG,
      ngx_http_oidc_provider_param,
      0,
      0,
      NULL },

    { ngx_string("backchannel_logout_uri"),
      NGX_HTTP_OIDC_CONF|NGX_CONF_TAKE1,
      ngx_http_oidc_provider_param,
      0,
      0,
      NULL },

    { ngx_string("session_max_age"),
      NGX_HTTP_OIDC_CONF|NGX_CONF_TAKE1,
      ngx_http_oidc_provider_param,
      0,
      0,
      NULL },

    { ngx_string("session_cookie"),
      NGX_HTTP_OIDC_CONF|NGX_CONF_TAKE1,
      ngx_http_oidc_provider_param,
      0,
      0,
      NULL },

      ngx_null_command
};

static ngx_http_module_t  ngx_http_oidc_module_ctx = {
    NULL,                              /* preconfiguration */
    ngx_http_oidc_init,                /* postconfiguration */

    ngx_http_oidc_create_main_conf,    /* create main configuration */
    NULL,                              /* init main configuration */

    NULL,                              /* create server configuration */
    NULL,                              /* merge server configuration */

    ngx_http_oidc_create_loc_conf,     /* create location configuration */
    ngx_http_oidc_merge_loc_conf       /* merge location configuration */
};

ngx_module_t  ngx_http_oidc_module = {
    NGX_MODULE_V1,
    &ngx_http_oidc_module_ctx,         /* module context */
    ngx_http_oidc_commands,            /* module directives */
    NGX_HTTP_MODULE,                   /* module type */
    NULL,                              /* init master */
    NULL,                              /* init module */
    NULL,                              /* init process */
    NULL,                              /* init thread */
    NULL,                              /* exit thread */
    NULL,                              /* exit process */
    NULL,                              /* exit master */
    NGX_MODULE_V1_PADDING
};

/* ------------------------------------------------------------------ */

static void *
ngx_http_oidc_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_oidc_main_conf_t  *omcf;

    omcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_oidc_main_conf_t));
    if (omcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&omcf->providers, cf->pool, 4,
                       sizeof(ngx_http_oidc_provider_t)) != NGX_OK)
    {
        return NULL;
    }

    return omcf;
}

static void *
ngx_http_oidc_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_oidc_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_oidc_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->provider = NGX_CONF_UNSET_PTR;
    conf->max_age = NGX_CONF_UNSET;

    return conf;
}

static char *
ngx_http_oidc_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_oidc_loc_conf_t  *prev = parent;
    ngx_http_oidc_loc_conf_t  *conf = child;

    ngx_conf_merge_ptr_value(conf->provider, prev->provider, NULL);
    ngx_conf_merge_value(conf->max_age, prev->max_age, 0);

    return NGX_CONF_OK;
}

/* ------------------------------------------------------------------ */

static ngx_http_oidc_provider_t  *ngx_http_oidc_current_provider;

static char *
ngx_http_oidc_provider(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_oidc_main_conf_t  *omcf;
    ngx_http_oidc_provider_t   *p;
    ngx_http_oidc_provider_t   *prev;
    ngx_uint_t                  prev_cmd_type;
    char                       *rv;
    ngx_str_t                  *value;

    omcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_oidc_module);

    p = ngx_array_push(&omcf->providers);
    if (p == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memzero(p, sizeof(*p));

    value = cf->args->elts;
    p->name = value[1];

    /* defaults */
    ngx_str_set(&p->scopes, NGX_OIDC_DEFAULT_SCOPES);
    ngx_str_set(&p->redirect_uri, NGX_OIDC_DEFAULT_REDIRECT);
    ngx_str_set(&p->cookie_name, NGX_OIDC_DEFAULT_COOKIE);
    ngx_str_set(&p->state_cookie_name, NGX_OIDC_STATE_COOKIE);

    /* stash current provider pointer and cmd_type for sub-directives */
    prev = ngx_http_oidc_current_provider;
    ngx_http_oidc_current_provider = p;
    prev_cmd_type = cf->cmd_type;
    cf->cmd_type = NGX_HTTP_OIDC_CONF;

    rv = ngx_conf_parse(cf, NULL);

    cf->cmd_type = prev_cmd_type;
    ngx_http_oidc_current_provider = prev;

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    if (p->issuer.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "oidc_provider \"%V\": issuer is required", &p->name);
        return NGX_CONF_ERROR;
    }
    if (p->client_id.len == 0 || p->client_secret.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "oidc_provider \"%V\": client_id and client_secret are required",
                           &p->name);
        return NGX_CONF_ERROR;
    }
    if (p->session_encryption_key.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "oidc_provider \"%V\": session_encryption_key is required",
                           &p->name);
        return NGX_CONF_ERROR;
    }
    if (p->redirect_uri.len == 0 || p->redirect_uri.data[0] != '/'
        || (p->redirect_uri.len > 1 && p->redirect_uri.data[1] == '/'))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "oidc_provider \"%V\": redirect_uri must be a local path",
                           &p->name);
        return NGX_CONF_ERROR;
    }
    if (p->cookie_name.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "oidc_provider \"%V\": session_cookie must not be empty",
                           &p->name);
        return NGX_CONF_ERROR;
    }
    if (p->logout_uri.len > 0 && (p->logout_uri.data[0] != '/'
        || (p->logout_uri.len > 1 && p->logout_uri.data[1] == '/')))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "oidc_provider \"%V\": logout_uri must be a local path",
                           &p->name);
        return NGX_CONF_ERROR;
    }
    if (p->backchannel_logout_uri.len > 0
        && (p->backchannel_logout_uri.data[0] != '/'
            || (p->backchannel_logout_uri.len > 1
                && p->backchannel_logout_uri.data[1] == '/')))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "oidc_provider \"%V\": backchannel_logout_uri must be a local path",
                           &p->name);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_oidc_provider_param(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_oidc_provider_t  *p = ngx_http_oidc_current_provider;
    ngx_str_t                  *value;

    value = cf->args->elts;

    if (p == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" directive is only allowed inside "
                           "oidc_provider", &cmd->name);
        return NGX_CONF_ERROR;
    }

    if (cmd->name.len == 6 && ngx_strncmp(cmd->name.data, "issuer", 6) == 0) {
        p->issuer = value[1];
    } else if (cmd->name.len == 9
               && ngx_strncmp(cmd->name.data, "client_id", 9) == 0)
    {
        p->client_id = value[1];
    } else if (cmd->name.len == 13
               && ngx_strncmp(cmd->name.data, "client_secret", 13) == 0)
    {
        p->client_secret = value[1];
    } else if (cmd->name.len == 22
               && ngx_strncmp(cmd->name.data, "session_encryption_key", 22) == 0)
    {
        p->session_encryption_key = value[1];
    } else if (cmd->name.len == 13
               && ngx_strncmp(cmd->name.data, "session_store", 13) == 0)
    {
        p->session_store = value[1];
    } else if (cmd->name.len == 10
               && ngx_strncmp(cmd->name.data, "config_url", 10) == 0)
    {
        p->config_url = value[1];
    } else if (cmd->name.len == 23
               && ngx_strncmp(cmd->name.data, "ssl_trusted_certificate",
                              23) == 0)
    {
        p->ssl_trusted_certificate = value[1];
    } else if (cmd->name.len == 6
               && ngx_strncmp(cmd->name.data, "scopes", 6) == 0)
    {
        p->scopes = value[1];
    } else if (cmd->name.len == 12
               && ngx_strncmp(cmd->name.data, "redirect_uri", 12) == 0)
    {
        p->redirect_uri = value[1];
    } else if (cmd->name.len == 10
               && ngx_strncmp(cmd->name.data, "logout_uri", 10) == 0)
    {
        p->logout_uri = value[1];
    } else if (cmd->name.len == 15
               && ngx_strncmp(cmd->name.data, "post_logout_uri", 15) == 0)
    {
        p->post_logout_uri = value[1];
    } else if (cmd->name.len == 8
               && ngx_strncmp(cmd->name.data, "userinfo", 8) == 0)
    {
        if (value[1].len == 2 && ngx_strncmp(value[1].data, "on", 2) == 0) {
            p->userinfo = 1;
        } else if (value[1].len == 3
                   && ngx_strncmp(value[1].data, "off", 3) == 0)
        {
            p->userinfo = 0;
        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "userinfo must be \"on\" or \"off\"");
            return NGX_CONF_ERROR;
        }
    } else if (cmd->name.len == 22
               && ngx_strncmp(cmd->name.data, "backchannel_logout_uri", 22) == 0)
    {
        p->backchannel_logout_uri = value[1];
    } else if (cmd->name.len == 15
               && ngx_strncmp(cmd->name.data, "session_max_age", 15) == 0)
    {
        p->session_max_age = ngx_parse_time(&value[1], 1);
        if (p->session_max_age == (time_t) NGX_ERROR || p->session_max_age <= 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "session_max_age must be a positive duration: \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }
    } else if (cmd->name.len == 14
               && ngx_strncmp(cmd->name.data, "session_cookie", 14) == 0)
    {
        p->cookie_name = value[1];
        p->state_cookie_name.len = value[1].len + sizeof("_state") - 1;
        p->state_cookie_name.data = ngx_pnalloc(cf->pool, p->state_cookie_name.len);
        if (p->state_cookie_name.data == NULL) {
            return NGX_CONF_ERROR;
        }
        ngx_memcpy(p->state_cookie_name.data, value[1].data, value[1].len);
        ngx_memcpy(p->state_cookie_name.data + value[1].len, "_state",
                   sizeof("_state") - 1);
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_oidc_auth(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_oidc_loc_conf_t    *olcf = conf;
    ngx_http_oidc_main_conf_t   *omcf;
    ngx_http_oidc_provider_t    *p;
    ngx_str_t                   *value, max_age;
    ngx_uint_t                   i;

    value = cf->args->elts;
    if (cf->args->nelts == 3) {
        if (value[2].len <= sizeof("max_age=") - 1
            || ngx_strncmp(value[2].data, "max_age=", sizeof("max_age=") - 1) != 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "auth_oidc optional parameter must be max_age=<duration>");
            return NGX_CONF_ERROR;
        }
        max_age.data = value[2].data + sizeof("max_age=") - 1;
        max_age.len = value[2].len - (sizeof("max_age=") - 1);
        olcf->max_age = ngx_parse_time(&max_age, 1);
        if (olcf->max_age == (time_t) NGX_ERROR || olcf->max_age <= 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "auth_oidc max_age must be a positive duration");
            return NGX_CONF_ERROR;
        }
    }

    omcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_oidc_module);
    p = omcf->providers.elts;

    for (i = 0; i < omcf->providers.nelts; i++) {
        if (p[i].name.len == value[1].len
            && ngx_strncmp(p[i].name.data, value[1].data, value[1].len) == 0)
        {
            olcf->provider = &p[i];
            return NGX_CONF_OK;
        }
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "auth_oidc: unknown provider \"%V\"", &value[1]);
    return NGX_CONF_ERROR;
}

/* ------------------------------------------------------------------ */

static ngx_int_t
ngx_http_oidc_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;
    ngx_http_variable_t        *var;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_oidc_access_handler;

    /* register $oidc_claim_* and $oidc_userinfo_* variables */
    var = ngx_http_add_variable(cf, &(ngx_str_t) ngx_string("oidc_claim"),
                                NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_PREFIX);
    if (var == NULL) {
        return NGX_ERROR;
    }
    var->get_handler = ngx_http_oidc_variable;
    var = ngx_http_add_variable(cf, &(ngx_str_t) ngx_string("oidc_userinfo"),
                                NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_PREFIX);
    if (var == NULL) {
        return NGX_ERROR;
    }
    var->get_handler = ngx_http_oidc_variable;

    return NGX_OK;
}

/* ------------------------------------------------------------------ */

static ngx_int_t
ngx_http_oidc_access_handler(ngx_http_request_t *r)
{
    ngx_http_oidc_loc_conf_t   *olcf;
    ngx_http_oidc_provider_t   *p;
    ngx_http_oidc_request_ctx_t  *ctx;
    ngx_int_t                     rc;

    olcf = ngx_http_get_module_loc_conf(r, ngx_http_oidc_module);
    p = olcf->provider;

    if (p == NULL) {
        return NGX_DECLINED;
    }

    /* internal callback location */
    if (r->uri.len == p->redirect_uri.len
        && ngx_strncmp(r->uri.data, p->redirect_uri.data,
                       p->redirect_uri.len) == 0)
    {
        return ngx_http_oidc_callback_handler(r);
    }

    /* logout */
    if (p->logout_uri.len > 0 && r->uri.len == p->logout_uri.len
        && ngx_strncmp(r->uri.data, p->logout_uri.data,
                       p->logout_uri.len) == 0)
    {
        return ngx_http_oidc_logout(r, p);
    }

    /* backchannel logout (IdP -> RP, no browser session) */
    if (p->backchannel_logout_uri.len > 0
        && r->uri.len == p->backchannel_logout_uri.len
        && ngx_strncmp(r->uri.data, p->backchannel_logout_uri.data,
                       p->backchannel_logout_uri.len) == 0)
    {
        return ngx_http_oidc_backchannel(r, p);
    }

    /* validate existing session */
    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_oidc_request_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_oidc_validate_session(r, p, &ctx->claims, &ctx->userinfo);
    if (rc == NGX_OK) {
        ngx_http_set_ctx(r, ctx, ngx_http_oidc_module);
        return NGX_OK;
    }

    /* no valid session -> start authorization code flow */
    return ngx_http_oidc_start_flow(r, p, olcf->max_age);
}

/* start authorization code flow: redirect to IdP */
ngx_int_t
ngx_http_oidc_start_flow(ngx_http_request_t *r, ngx_http_oidc_provider_t *p,
    time_t max_age)
{
    ngx_str_t  state, nonce, verifier, state_b64, nonce_b64, verifier_b64, return_b64;
    ngx_str_t  digest_str, challenge, redirect_uri, redirect_uri_enc, scopes_enc, url;
    u_char    digest[EVP_MAX_MD_SIZE], *q;
    unsigned int  digest_len;
    size_t     len;

    if (p->authorization_endpoint.len == 0) {
        if (ngx_http_oidc_discover(p, r->connection->log) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc: discovery failed");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    /* 32 random bytes encode to a 43-character RFC 7636 code_verifier. */
    if (ngx_http_oidc_random(r->pool, 16, &state) != NGX_OK
        || ngx_http_oidc_random(r->pool, 16, &nonce) != NGX_OK
        || ngx_http_oidc_random(r->pool, 32, &verifier) != NGX_OK
        || ngx_http_oidc_b64url_encode(r->pool, &state, &state_b64) != NGX_OK
        || ngx_http_oidc_b64url_encode(r->pool, &nonce, &nonce_b64) != NGX_OK
        || ngx_http_oidc_b64url_encode(r->pool, &verifier, &verifier_b64) != NGX_OK
        || ngx_http_oidc_b64url_encode(r->pool, &r->unparsed_uri, &return_b64) != NGX_OK
        || EVP_Digest(verifier_b64.data, verifier_b64.len, digest, &digest_len,
                      EVP_sha256(), NULL) != 1)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    digest_str.data = digest;
    digest_str.len = digest_len;
    if (ngx_http_oidc_b64url_encode(r->pool, &digest_str, &challenge) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* state_cookie = "state.nonce.code_verifier.return_uri_b64" */
    {
        ngx_str_t  sn;
        sn.len = state_b64.len + 1 + nonce_b64.len + 1 + verifier_b64.len + 1
                 + return_b64.len + 1 + NGX_TIME_T_LEN;
        sn.data = ngx_pnalloc(r->pool, sn.len);
        if (sn.data == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        q = ngx_cpymem(sn.data, state_b64.data, state_b64.len);
        *q++ = '.';
        q = ngx_cpymem(q, nonce_b64.data, nonce_b64.len);
        *q++ = '.';
        q = ngx_cpymem(q, verifier_b64.data, verifier_b64.len);
        *q++ = '.';
        q = ngx_cpymem(q, return_b64.data, return_b64.len);
        *q++ = '.';
        q = ngx_sprintf(q, "%T", max_age);
        sn.len = q - sn.data;
        if (ngx_http_oidc_set_cookie(r, &p->state_cookie_name, &sn,
                &(ngx_str_t) ngx_string("/"), 300) != NGX_OK)
        {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    if (ngx_http_oidc_build_redirect_uri(r, p, &redirect_uri) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    redirect_uri_enc.data = ngx_pnalloc(r->pool, redirect_uri.len * 3);
    scopes_enc.data = ngx_pnalloc(r->pool, p->scopes.len * 3);
    if (redirect_uri_enc.data == NULL || scopes_enc.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    redirect_uri_enc.len = (u_char *) ngx_escape_uri(redirect_uri_enc.data,
        redirect_uri.data, redirect_uri.len, NGX_ESCAPE_URI_COMPONENT)
        - redirect_uri_enc.data;
    scopes_enc.len = (u_char *) ngx_escape_uri(scopes_enc.data, p->scopes.data,
        p->scopes.len, NGX_ESCAPE_URI_COMPONENT) - scopes_enc.data;

    len = p->authorization_endpoint.len + 320 + redirect_uri_enc.len
          + scopes_enc.len + state_b64.len + nonce_b64.len + challenge.len
          + p->client_id.len + NGX_TIME_T_LEN;
    url.data = ngx_pnalloc(r->pool, len);
    if (url.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    q = ngx_cpymem(url.data, p->authorization_endpoint.data,
                   p->authorization_endpoint.len);
    q = ngx_cpymem(q, "?response_type=code&client_id=", 30);
    q = ngx_cpymem(q, p->client_id.data, p->client_id.len);
    q = ngx_cpymem(q, "&redirect_uri=", 14);
    q = ngx_cpymem(q, redirect_uri_enc.data, redirect_uri_enc.len);
    q = ngx_cpymem(q, "&scope=", 7);
    q = ngx_cpymem(q, scopes_enc.data, scopes_enc.len);
    q = ngx_cpymem(q, "&state=", 7);
    q = ngx_cpymem(q, state_b64.data, state_b64.len);
    q = ngx_cpymem(q, "&nonce=", 7);
    q = ngx_cpymem(q, nonce_b64.data, nonce_b64.len);
    q = ngx_cpymem(q, "&code_challenge_method=S256&code_challenge=", 43);
    q = ngx_cpymem(q, challenge.data, challenge.len);
    if (max_age > 0) {
        q = ngx_sprintf(q, "&max_age=%T", max_age);
    }
    url.len = q - url.data;

    return ngx_http_oidc_redirect(r, &url);
}

static ngx_int_t
ngx_http_oidc_callback_handler(ngx_http_request_t *r)
{
    ngx_http_oidc_loc_conf_t   *olcf;
    ngx_http_oidc_provider_t   *p;
    ngx_str_t                   code, state, id_token, access_token, refresh_token;
    ngx_str_t                   state_cookie, expected_state, nonce, verifier, return_b64, return_uri, max_age_s, claims, userinfo;
    time_t                      max_age, access_expires;
    ngx_int_t                   rc;

    olcf = ngx_http_get_module_loc_conf(r, ngx_http_oidc_module);
    p = olcf->provider;
    ngx_str_null(&userinfo);
    ngx_str_null(&refresh_token);
    access_expires = 0;

    if (p == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* error from IdP */
    if (ngx_http_oidc_get_query_arg(r, &(ngx_str_t) ngx_string("error"),
                                    &code) == NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc: IdP returned error: %V", &code);
        return NGX_HTTP_UNAUTHORIZED;
    }

    if (ngx_http_oidc_get_query_arg(r, &(ngx_str_t) ngx_string("code"),
                                    &code) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc: callback missing code");
        return NGX_HTTP_BAD_REQUEST;
    }

    if (ngx_http_oidc_get_query_arg(r, &(ngx_str_t) ngx_string("state"),
                                    &state) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc: callback missing state");
        return NGX_HTTP_BAD_REQUEST;
    }

    /* validate state against cookie */
    if (ngx_http_oidc_get_cookie(r, &p->state_cookie_name,
                                 &state_cookie) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc: missing state cookie");
        return NGX_HTTP_BAD_REQUEST;
    }

    /* state_cookie = "state.nonce.code_verifier.return_uri_b64" */
    {
        u_char  *dot, *dot2, *dot3, *dot4;

        dot = ngx_strlchr(state_cookie.data,
                           state_cookie.data + state_cookie.len, '.');
        if (dot == NULL) {
            return NGX_HTTP_BAD_REQUEST;
        }
        dot2 = ngx_strlchr(dot + 1, state_cookie.data + state_cookie.len, '.');
        dot3 = dot2 ? ngx_strlchr(dot2 + 1,
                                  state_cookie.data + state_cookie.len, '.') : NULL;
        dot4 = dot3 ? ngx_strlchr(dot3 + 1,
                                  state_cookie.data + state_cookie.len, '.') : NULL;
        if (dot2 == NULL || dot3 == NULL || dot4 == NULL || dot2 == dot + 1
            || dot3 == dot2 + 1 || dot4 == dot3 + 1
            || dot4 + 1 == state_cookie.data + state_cookie.len)
        {
            return NGX_HTTP_BAD_REQUEST;
        }
        expected_state.data = state_cookie.data;
        expected_state.len = dot - state_cookie.data;
        nonce.data = dot + 1;
        nonce.len = dot2 - dot - 1;
        verifier.data = dot2 + 1;
        verifier.len = dot3 - dot2 - 1;
        return_b64.data = dot3 + 1;
        return_b64.len = dot4 - dot3 - 1;
        max_age_s.data = dot4 + 1;
        max_age_s.len = state_cookie.data + state_cookie.len - dot4 - 1;
        max_age = ngx_atotm(max_age_s.data, max_age_s.len);
        if (max_age == (time_t) NGX_ERROR || max_age < 0) {
            return NGX_HTTP_BAD_REQUEST;
        }
    }

    if (state.len != expected_state.len
        || CRYPTO_memcmp(state.data, expected_state.data, state.len) != 0)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc: state mismatch (CSRF)");
        return NGX_HTTP_BAD_REQUEST;
    }

    if (ngx_http_oidc_b64url_decode(r->pool, &return_b64, &return_uri) != NGX_OK
        || return_uri.len == 0 || return_uri.data[0] != '/'
        || (return_uri.len > 1 && return_uri.data[1] == '/'))
    {
        return NGX_HTTP_BAD_REQUEST;
    }

    if (ngx_http_oidc_set_cookie(r, &p->state_cookie_name,
            &(ngx_str_t) ngx_string(""), &(ngx_str_t) ngx_string("/"), 0)
        != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* exchange code for tokens */
    rc = ngx_http_oidc_exchange_code(r, p, &code, &verifier, &id_token,
                                     &access_token, &refresh_token,
                                     &access_expires);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc: token exchange failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* validate id_token */
    if (p->jwks.len == 0) {
        if (ngx_http_oidc_fetch_jwks(p, r->connection->log) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    rc = ngx_http_oidc_jwt_verify(r->connection->log, r->pool, &id_token, &p->jwks,
                                  &p->issuer, &p->client_id, &nonce, max_age, 1, &claims);
    if (rc == NGX_DECLINED) {
        p->jwks.len = 0;
        if (ngx_http_oidc_fetch_jwks(p, r->connection->log) == NGX_OK) {
            rc = ngx_http_oidc_jwt_verify(r->connection->log, r->pool, &id_token,
                                           &p->jwks, &p->issuer, &p->client_id,
                                           &nonce, max_age, 1, &claims);
        }
    }
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc: id_token validation failed");
        return NGX_HTTP_UNAUTHORIZED;
    }

    if (p->userinfo
        && ngx_http_oidc_fetch_userinfo(r, p, &access_token, &claims, &userinfo)
           != NGX_OK)
    {
        return NGX_HTTP_UNAUTHORIZED;
    }

    /* issue session cookie */
    rc = ngx_http_oidc_issue_session(r, p, &id_token, &claims, &userinfo,
                                     &refresh_token, access_expires);
    if (rc != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return ngx_http_oidc_redirect(r, &return_uri);
}

/* ------------------------------------------------------------------ */

static ngx_int_t
ngx_http_oidc_discover(ngx_http_oidc_provider_t *p, ngx_log_t *log)
{
    ngx_str_t  url, body;
    ngx_http_oidc_http_resp_t  resp;
    ngx_str_t  v;

    if (p->config_url.len > 0) {
        url = p->config_url;
    } else {
        url.len = p->issuer.len + sizeof("/.well-known/openid-configuration") - 1;
        url.data = ngx_pnalloc(ngx_cycle->pool, url.len);
        if (url.data == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(url.data, p->issuer.data, p->issuer.len);
        ngx_memcpy(url.data + p->issuer.len,
                   "/.well-known/openid-configuration",
                   sizeof("/.well-known/openid-configuration") - 1);
    }

    if (ngx_http_oidc_http_get(ngx_cycle->pool, log, &url, &p->ssl_trusted_certificate, NULL,
                               &resp) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, log, 0, "oidc: http_get failed for %V", &url);
        return NGX_ERROR;
    }
    if (resp.status != 200) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "oidc: discovery returned %d", resp.status);
        return NGX_ERROR;
    }

    body = resp.body;
    if (ngx_http_oidc_json_get_string(ngx_cycle->pool, &body,
            &(ngx_str_t) ngx_string("issuer"), &v) != NGX_OK
        || v.len != p->issuer.len
        || ngx_strncmp(v.data, p->issuer.data, v.len) != 0)
    {
        ngx_log_error(NGX_LOG_ERR, log, 0, "oidc: discovery issuer mismatch");
        return NGX_ERROR;
    }

    if (ngx_http_oidc_json_get_string(ngx_cycle->pool, &body,
            &(ngx_str_t) ngx_string("authorization_endpoint"), &v) == NGX_OK)
    {
        p->authorization_endpoint = v;
    }
    if (ngx_http_oidc_json_get_string(ngx_cycle->pool, &body,
            &(ngx_str_t) ngx_string("token_endpoint"), &v) == NGX_OK)
    {
        p->token_endpoint = v;
    }
    if (ngx_http_oidc_json_get_string(ngx_cycle->pool, &body,
            &(ngx_str_t) ngx_string("jwks_uri"), &v) == NGX_OK)
    {
        p->jwks_uri = v;
    }
    if (ngx_http_oidc_json_get_string(ngx_cycle->pool, &body,
            &(ngx_str_t) ngx_string("revocation_endpoint"), &v) == NGX_OK)
    {
        p->revocation_endpoint = v;
    }
    if (ngx_http_oidc_json_get_string(ngx_cycle->pool, &body,
            &(ngx_str_t) ngx_string("end_session_endpoint"), &v) == NGX_OK)
    {
        p->end_session_endpoint = v;
    }
    if (ngx_http_oidc_json_get_string(ngx_cycle->pool, &body,
            &(ngx_str_t) ngx_string("userinfo_endpoint"), &v) == NGX_OK)
    {
        p->userinfo_endpoint = v;
    }

    if (p->authorization_endpoint.len == 0 || p->token_endpoint.len == 0
        || p->jwks_uri.len == 0)
    {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "oidc: discovery document incomplete");
        return NGX_ERROR;
    }

    /* every endpoint must stay on the issuer's host (https): the token and
     * revocation endpoints carry the client secret, the rest carry tokens */
    if (ngx_http_oidc_endpoint_matches_issuer(&p->issuer,
            &p->authorization_endpoint) != NGX_OK
        || ngx_http_oidc_endpoint_matches_issuer(&p->issuer,
            &p->token_endpoint) != NGX_OK
        || ngx_http_oidc_endpoint_matches_issuer(&p->issuer,
            &p->jwks_uri) != NGX_OK
        || (p->revocation_endpoint.len > 0
            && ngx_http_oidc_endpoint_matches_issuer(&p->issuer,
                &p->revocation_endpoint) != NGX_OK)
        || (p->end_session_endpoint.len > 0
            && ngx_http_oidc_endpoint_matches_issuer(&p->issuer,
                &p->end_session_endpoint) != NGX_OK)
        || (p->userinfo_endpoint.len > 0
            && ngx_http_oidc_endpoint_matches_issuer(&p->issuer,
                &p->userinfo_endpoint) != NGX_OK))
    {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "oidc: discovery endpoint outside issuer host");
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_oidc_fetch_jwks(ngx_http_oidc_provider_t *p, ngx_log_t *log)
{
    ngx_http_oidc_http_resp_t  resp;

    if (p->jwks.len > 0 && ngx_time() - p->jwks_fetched < NGX_OIDC_JWKS_TTL) {
        return NGX_OK;
    }

    if (p->jwks_uri.len == 0) {
        if (ngx_http_oidc_discover(p, log) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (ngx_http_oidc_http_get(ngx_cycle->pool, log, &p->jwks_uri, &p->ssl_trusted_certificate,
                               NULL, &resp) != NGX_OK)
    {
        return NGX_ERROR;
    }
    if (resp.status != 200) {
        return NGX_ERROR;
    }

    p->jwks = resp.body;
    p->jwks_fetched = ngx_time();

    return NGX_OK;
}

static ngx_int_t
ngx_http_oidc_exchange_code(ngx_http_request_t *r,
    ngx_http_oidc_provider_t *p, ngx_str_t *code, ngx_str_t *code_verifier,
    ngx_str_t *id_token_out, ngx_str_t *access_token_out,
    ngx_str_t *refresh_token_out, time_t *access_expires_out)
{
    ngx_str_t  body, redirect_uri, redirect_uri_enc;
    ngx_str_t  auth_header, auth_b64;
    ngx_http_oidc_http_resp_t  resp;
    u_char    *q;
    size_t     len;
    ngx_str_t  v;

    if (p->token_endpoint.len == 0) {
        if (ngx_http_oidc_discover(p, r->connection->log) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (ngx_http_oidc_build_redirect_uri(r, p, &redirect_uri) != NGX_OK) {
        return NGX_ERROR;
    }
    redirect_uri_enc.data = ngx_pnalloc(r->pool, redirect_uri.len * 3);
    if (redirect_uri_enc.data == NULL) {
        return NGX_ERROR;
    }
    redirect_uri_enc.len = (u_char *) ngx_escape_uri(redirect_uri_enc.data,
        redirect_uri.data, redirect_uri.len, NGX_ESCAPE_URI_COMPONENT)
        - redirect_uri_enc.data;

    /* build form body */
    len = 80 + code->len + redirect_uri_enc.len + code_verifier->len;
    body.data = ngx_pnalloc(r->pool, len);
    if (body.data == NULL) {
        return NGX_ERROR;
    }
    q = ngx_cpymem(body.data, "grant_type=authorization_code&code=", 35);
    q = ngx_cpymem(q, code->data, code->len);
    q = ngx_cpymem(q, "&redirect_uri=", 14);
    q = ngx_cpymem(q, redirect_uri_enc.data, redirect_uri_enc.len);
    q = ngx_cpymem(q, "&code_verifier=", 15);
    q = ngx_cpymem(q, code_verifier->data, code_verifier->len);
    body.len = q - body.data;

    /* build basic auth header */
    {
        ngx_str_t  cred;
        cred.len = p->client_id.len + 1 + p->client_secret.len;
        cred.data = ngx_pnalloc(r->pool, cred.len);
        if (cred.data == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(cred.data, p->client_id.data, p->client_id.len);
        cred.data[p->client_id.len] = ':';
        ngx_memcpy(cred.data + p->client_id.len + 1, p->client_secret.data,
                   p->client_secret.len);

        auth_b64.data = ngx_pnalloc(r->pool,
                                    ngx_base64_encoded_length(cred.len));
        if (auth_b64.data == NULL) {
            return NGX_ERROR;
        }
        ngx_encode_base64(&auth_b64, &cred);

        auth_header.len = 6 + auth_b64.len;
        auth_header.data = ngx_pnalloc(r->pool, auth_header.len);
        if (auth_header.data == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(auth_header.data, "Basic ", 6);
        ngx_memcpy(auth_header.data + 6, auth_b64.data, auth_b64.len);
    }

    if (ngx_http_oidc_http_post_form(r->pool, r->connection->log, &p->token_endpoint,
                                     &p->ssl_trusted_certificate, &auth_header,
                                     &body, &resp) != NGX_OK)
    {
        return NGX_ERROR;
    }
    if (resp.status != 200) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc: token endpoint returned %d", resp.status);
        return NGX_ERROR;
    }

    if (ngx_http_oidc_json_get_string(r->pool, &resp.body,
            &(ngx_str_t) ngx_string("id_token"), &v) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc: token response missing id_token");
        return NGX_ERROR;
    }
    *id_token_out = v;
    if (ngx_http_oidc_json_get_string(r->pool, &resp.body,
            &(ngx_str_t) ngx_string("access_token"), &v) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc: token response missing access_token");
        return NGX_ERROR;
    }
    *access_token_out = v;
    ngx_str_null(refresh_token_out);
    *access_expires_out = 0;
    if (ngx_http_oidc_json_get_string(r->pool, &resp.body,
            &(ngx_str_t) ngx_string("refresh_token"), &v) == NGX_OK)
    {
        *refresh_token_out = v;
    }
    if (ngx_http_oidc_json_get_string(r->pool, &resp.body,
            &(ngx_str_t) ngx_string("expires_in"), &v) == NGX_OK)
    {
        *access_expires_out = ngx_time() + ngx_atotm(v.data, v.len);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_oidc_fetch_userinfo(ngx_http_request_t *r, ngx_http_oidc_provider_t *p,
    ngx_str_t *access_token, ngx_str_t *id_claims, ngx_str_t *userinfo_out)
{
    ngx_http_oidc_http_resp_t  resp;
    ngx_str_t  auth, id_sub, userinfo_sub;
    u_char    *q;

    if (p->userinfo_endpoint.len == 0
        && ngx_http_oidc_discover(p, r->connection->log) != NGX_OK)
    {
        return NGX_ERROR;
    }
    if (p->userinfo_endpoint.len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc: discovery missing userinfo_endpoint");
        return NGX_ERROR;
    }

    auth.len = sizeof("Bearer ") - 1 + access_token->len;
    auth.data = ngx_pnalloc(r->pool, auth.len);
    if (auth.data == NULL) {
        return NGX_ERROR;
    }
    q = ngx_cpymem(auth.data, "Bearer ", sizeof("Bearer ") - 1);
    ngx_memcpy(q, access_token->data, access_token->len);

    if (ngx_http_oidc_http_get(r->pool, r->connection->log, &p->userinfo_endpoint,
            &p->ssl_trusted_certificate, &auth, &resp) != NGX_OK
        || resp.status != 200
        || ngx_http_oidc_json_get_string(r->pool, id_claims,
               &(ngx_str_t) ngx_string("sub"), &id_sub) != NGX_OK
        || ngx_http_oidc_json_get_string(r->pool, &resp.body,
               &(ngx_str_t) ngx_string("sub"), &userinfo_sub) != NGX_OK
        || id_sub.len != userinfo_sub.len
        || ngx_strncmp(id_sub.data, userinfo_sub.data, id_sub.len) != 0)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc: UserInfo response invalid or subject mismatch");
        return NGX_ERROR;
    }

    *userinfo_out = resp.body;
    return NGX_OK;
}

/* session cookie = base64url(nonce || AES-256-GCM(id_token.userinfo_b64)) */
static ngx_int_t
ngx_http_oidc_issue_session(ngx_http_request_t *r,
    ngx_http_oidc_provider_t *p, ngx_str_t *id_token, ngx_str_t *claims,
    ngx_str_t *userinfo, ngx_str_t *refresh_token, time_t access_expires)
{
    ngx_str_t  userinfo_b64, session, cookie, refresh_blob, exp_s, sid, sub;
    u_char    *q;
    time_t     max_age;

    ngx_str_null(&sid);
    if (ngx_http_oidc_json_get_string(r->pool, claims,
            &(ngx_str_t) ngx_string("sub"), &sub) != NGX_OK)
    {
        return NGX_ERROR;
    }
    if (ngx_http_oidc_json_get_string(r->pool, claims,
            &(ngx_str_t) ngx_string("sid"), &sid) != NGX_OK)
    {
        ngx_str_null(&sid);
    }

    if (p->session_max_age > 0) {
        max_age = p->session_max_age;
    } else {
        if (ngx_http_oidc_json_get_string(r->pool, claims,
                &(ngx_str_t) ngx_string("exp"), &exp_s) != NGX_OK)
        {
            return NGX_ERROR;
        }
        max_age = ngx_atotm(exp_s.data, exp_s.len) - ngx_time();
    }
    if (max_age <= 0) {
        return NGX_ERROR;
    }

    if (ngx_http_oidc_b64url_encode(r->pool, userinfo, &userinfo_b64) != NGX_OK) {
        return NGX_ERROR;
    }
    session.len = id_token->len + 1 + userinfo_b64.len;
    session.data = ngx_pnalloc(r->pool, session.len);
    if (session.data == NULL) {
        return NGX_ERROR;
    }
    q = ngx_cpymem(session.data, id_token->data, id_token->len);
    *q++ = '.';
    ngx_memcpy(q, userinfo_b64.data, userinfo_b64.len);

    if (ngx_http_oidc_session_encrypt(r->pool, p, &session, &cookie) != NGX_OK) {
        return NGX_ERROR;
    }
    if (p->session_store.len > 0) {
        ngx_str_t  session_id;

        if (ngx_http_oidc_session_encrypt(r->pool, p, refresh_token,
                                          &refresh_blob) != NGX_OK
            || ngx_http_oidc_session_db_store(r, p, &cookie, &refresh_blob,
                                               access_expires,
                                               ngx_time() + max_age,
                                               &sid, &sub, &session_id) != NGX_OK)
        {
            return NGX_ERROR;
        }
        return ngx_http_oidc_set_cookie(r, &p->cookie_name, &session_id,
                                        &(ngx_str_t) ngx_string("/"), max_age);
    }
    if (cookie.len > NGX_OIDC_MAX_COOKIE_LEN) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc: session cookie exceeds %uz bytes", cookie.len);
        return NGX_ERROR;
    }
    return ngx_http_oidc_set_cookie(r, &p->cookie_name, &cookie,
                                    &(ngx_str_t) ngx_string("/"), max_age);
}

static ngx_int_t
ngx_http_oidc_validate_session(ngx_http_request_t *r,
    ngx_http_oidc_provider_t *p, ngx_str_t *claims_out, ngx_str_t *userinfo_out)
{
    ngx_str_t  cookie, session, id_token, userinfo_b64, refresh_blob, refresh;
    time_t     access_expires;
    u_char    *last_dot;
    ngx_int_t  rc;

    ngx_str_null(&refresh);

    if (ngx_http_oidc_get_cookie(r, &p->cookie_name, &cookie) != NGX_OK) {
        return NGX_DECLINED;
    }
    if (p->session_store.len > 0) {
        if (ngx_http_oidc_session_db_load(r, p, &cookie, &session,
                                          &refresh_blob, &access_expires) != NGX_OK
            || ngx_http_oidc_session_decrypt(r->pool, p, &session, &session)
               != NGX_OK)
        {
            return NGX_DECLINED;
        }
        if (access_expires > 0 && access_expires - ngx_time() <= 60
            && (ngx_http_oidc_session_decrypt(r->pool, p, &refresh_blob,
                                              &refresh) != NGX_OK
                || refresh.len == 0))
        {
            return NGX_DECLINED;
        }
        if (refresh.len > 0 && access_expires > 0
            && access_expires - ngx_time() <= 60
            && ngx_http_oidc_refresh_session(r, p, &cookie, &refresh) != NGX_OK)
        {
            ngx_http_oidc_session_db_delete(p, &cookie);
            return NGX_DECLINED;
        }
    } else if (ngx_http_oidc_session_decrypt(r->pool, p, &cookie, &session)
               != NGX_OK)
    {
        return NGX_DECLINED;
    }
    last_dot = session.data + session.len;
    while (last_dot > session.data && *--last_dot != '.') { }
    if (last_dot == session.data) {
        return NGX_DECLINED;
    }
    id_token.data = session.data;
    id_token.len = last_dot - session.data;
    userinfo_b64.data = last_dot + 1;
    userinfo_b64.len = session.data + session.len - last_dot - 1;


    if (p->jwks.len == 0
        && ngx_http_oidc_fetch_jwks(p, r->connection->log) != NGX_OK)
    {
        return NGX_DECLINED;
    }
    rc = ngx_http_oidc_jwt_verify(r->connection->log, r->pool, &id_token, &p->jwks,
                                  &p->issuer, &p->client_id, NULL, 0, 0, claims_out);
    if (rc == NGX_DECLINED) {
        p->jwks.len = 0;
        if (ngx_http_oidc_fetch_jwks(p, r->connection->log) == NGX_OK) {
            rc = ngx_http_oidc_jwt_verify(r->connection->log, r->pool, &id_token,
                                           &p->jwks, &p->issuer, &p->client_id,
                                           NULL, 0, 0, claims_out);
        }
    }
    if (rc != NGX_OK) {
        return NGX_DECLINED;
    }
    if (userinfo_b64.len > 0
        && ngx_http_oidc_b64url_decode(r->pool, &userinfo_b64, userinfo_out)
           != NGX_OK)
    {
        return NGX_DECLINED;
    }

    return NGX_OK;
}

/* ------------------------------------------------------------------ */

static ngx_int_t
ngx_http_oidc_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_oidc_request_ctx_t  *ctx;
    ngx_str_t  *claims, *name;
    ngx_str_t   key, val;

    ctx = ngx_http_get_module_ctx(r, ngx_http_oidc_module);
    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    name = (ngx_str_t *) data;
    if (name->len >= sizeof("oidc_userinfo_") - 1
        && ngx_strncmp(name->data, "oidc_userinfo_",
                       sizeof("oidc_userinfo_") - 1) == 0)
    {
        claims = &ctx->userinfo;
        key.data = name->data + sizeof("oidc_userinfo_") - 1;
        key.len = name->len - (sizeof("oidc_userinfo_") - 1);
    } else {
        claims = &ctx->claims;
        key.data = name->data + sizeof("oidc_claim_") - 1;
        key.len = name->len - (sizeof("oidc_claim_") - 1);
    }

    if (claims->len == 0
        || ngx_http_oidc_json_get_string(r->pool, claims, &key, &val) != NGX_OK) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = val.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = val.data;

    return NGX_OK;
}

/* ------------------------------------------------------------------ */

static ngx_int_t
ngx_http_oidc_redirect(ngx_http_request_t *r, ngx_str_t *url)
{
    ngx_table_elt_t  *h;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    h->hash = 1;
    ngx_str_set(&h->key, "Location");
    h->value = *url;

    r->headers_out.status = NGX_HTTP_MOVED_TEMPORARILY;
    r->headers_out.content_length_n = 0;

    return NGX_HTTP_MOVED_TEMPORARILY;
}

static ngx_int_t
ngx_http_oidc_logout(ngx_http_request_t *r, ngx_http_oidc_provider_t *p)
{
    ngx_str_t  redirect_uri, redirect_uri_enc, client_id_enc, id_token, id_token_enc, url;
    u_char    *q, *dot;
    ngx_flag_t  have_id_token = 0;
    ngx_str_null(&id_token_enc);

    {
        ngx_str_t  cookie;
        if (p->session_store.len > 0
            && ngx_http_oidc_get_cookie(r, &p->cookie_name, &cookie) == NGX_OK)
        {
            ngx_str_t  session, refresh_blob;
            time_t     access_expires;

            if (ngx_http_oidc_session_db_load(r, p, &cookie, &session,
                                              &refresh_blob, &access_expires) == NGX_OK
                && ngx_http_oidc_session_decrypt(r->pool, p, &session, &session)
                   == NGX_OK)
            {
                dot = session.data + session.len;
                while (dot > session.data && *--dot != '.') { }
                if (dot > session.data) {
                    id_token.data = session.data;
                    id_token.len = dot - session.data;
                    have_id_token = 1;
                }
            }
            ngx_http_oidc_revoke_refresh_token(r, p, &cookie);
            ngx_http_oidc_session_db_delete(p, &cookie);
        }
    }
    if (ngx_http_oidc_set_cookie(r, &p->cookie_name,
            &(ngx_str_t) ngx_string(""), &(ngx_str_t) ngx_string("/"), 0)
        != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (p->end_session_endpoint.len == 0
        && ngx_http_oidc_discover(p, r->connection->log) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (p->end_session_endpoint.len == 0) {
        if (p->post_logout_uri.len > 0) {
            return ngx_http_oidc_redirect(r, &p->post_logout_uri);
        }
        return NGX_HTTP_OK;
    }

    if (p->post_logout_uri.len == 0) {
        return ngx_http_oidc_redirect(r, &p->end_session_endpoint);
    }

    redirect_uri = p->post_logout_uri;
    redirect_uri_enc.data = ngx_pnalloc(r->pool, redirect_uri.len * 3);
    client_id_enc.data = ngx_pnalloc(r->pool, p->client_id.len * 3);
    if (redirect_uri_enc.data == NULL || client_id_enc.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    redirect_uri_enc.len = (u_char *) ngx_escape_uri(redirect_uri_enc.data,
        redirect_uri.data, redirect_uri.len, NGX_ESCAPE_URI_COMPONENT)
        - redirect_uri_enc.data;
    client_id_enc.len = (u_char *) ngx_escape_uri(client_id_enc.data,
        p->client_id.data, p->client_id.len, NGX_ESCAPE_URI_COMPONENT)
        - client_id_enc.data;

    if (have_id_token) {
        id_token_enc.data = ngx_pnalloc(r->pool, id_token.len * 3);
        if (id_token_enc.data == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        id_token_enc.len = (u_char *) ngx_escape_uri(id_token_enc.data,
            id_token.data, id_token.len, NGX_ESCAPE_URI_COMPONENT)
            - id_token_enc.data;
    }

    /* always send client_id: with no valid session there is no id_token_hint,
     * and the end_session endpoint still needs client_id + redirect URI */
    url.len = p->end_session_endpoint.len + sizeof("?client_id=") - 1
              + client_id_enc.len
              + sizeof("&post_logout_redirect_uri=") - 1 + redirect_uri_enc.len;
    if (have_id_token) {
        url.len += sizeof("&id_token_hint=") - 1 + id_token_enc.len;
    }
    url.data = ngx_pnalloc(r->pool, url.len);
    if (url.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    q = ngx_cpymem(url.data, p->end_session_endpoint.data,
                   p->end_session_endpoint.len);
    q = ngx_cpymem(q, "?client_id=", 11);
    q = ngx_cpymem(q, client_id_enc.data, client_id_enc.len);
    q = ngx_cpymem(q, "&post_logout_redirect_uri=", 26);
    q = ngx_cpymem(q, redirect_uri_enc.data, redirect_uri_enc.len);
    if (have_id_token) {
        q = ngx_cpymem(q, "&id_token_hint=", 15);
        q = ngx_cpymem(q, id_token_enc.data, id_token_enc.len);
    }
    url.len = q - url.data;

    return ngx_http_oidc_redirect(r, &url);
}

static ngx_int_t
ngx_http_oidc_build_redirect_uri(ngx_http_request_t *r,
    ngx_http_oidc_provider_t *p, ngx_str_t *out)
{
    ngx_str_t  scheme, host;
    u_char    *q;
    size_t     len;

    ngx_str_set(&scheme, "https");
    if (r->connection->ssl == NULL) {
        ngx_str_set(&scheme, "http");
    }

    /* headers_in.server carries no port; the raw Host header does. Providers
     * compare redirect_uri exactly, so a listener on a non-default port needs
     * "host:port" here. */
    if (r->headers_in.host != NULL) {
        host = r->headers_in.host->value;
    } else {
        host = r->headers_in.server;
    }

    len = scheme.len + 3 + host.len + p->redirect_uri.len;
    out->data = ngx_pnalloc(r->pool, len);
    if (out->data == NULL) {
        return NGX_ERROR;
    }
    q = ngx_cpymem(out->data, scheme.data, scheme.len);
    q = ngx_cpymem(q, "://", 3);
    q = ngx_cpymem(q, host.data, host.len);
    q = ngx_cpymem(q, p->redirect_uri.data, p->redirect_uri.len);
    out->len = q - out->data;

    return NGX_OK;
}

static ngx_int_t
ngx_http_oidc_session_db_open(ngx_http_oidc_provider_t *p, ngx_log_t *log)
{
    const char  *path;
    int  rc;

    if (p->session_db != NULL) {
        return NGX_OK;
    }
    path = (const char *) p->session_store.data;
    if (p->session_store.len > sizeof("sqlite:") - 1
        && ngx_strncmp(p->session_store.data, "sqlite:", sizeof("sqlite:") - 1) == 0)
    {
        path += sizeof("sqlite:") - 1;
    }
    rc = sqlite3_open_v2(path, &p->session_db,
                          SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                          NULL);
    if (rc != SQLITE_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "oidc: SQLite open failed: %s",
                      p->session_db ? sqlite3_errmsg(p->session_db) : "unknown");
        if (p->session_db) sqlite3_close(p->session_db);
        p->session_db = NULL;
        return NGX_ERROR;
    }
    sqlite3_busy_timeout(p->session_db, 5000);
    if (sqlite3_exec(p->session_db, "PRAGMA journal_mode=WAL;"
        "CREATE TABLE IF NOT EXISTS oidc_sessions ("
        "id TEXT PRIMARY KEY, session BLOB NOT NULL, refresh_token BLOB, "
        "access_expires_at INTEGER, expires_at INTEGER NOT NULL, "
        "sid TEXT, sub TEXT);"
        /* ponytail: no column migration; delete the db file when upgrading
         * from a pre-refresh/pre-backchannel schema */
        "CREATE INDEX IF NOT EXISTS oidc_sessions_expiry ON oidc_sessions(expires_at);"
        "CREATE INDEX IF NOT EXISTS oidc_sessions_sid ON oidc_sessions(sid);"
        "CREATE INDEX IF NOT EXISTS oidc_sessions_sub ON oidc_sessions(sub);",
        NULL, NULL, NULL) != SQLITE_OK)
    {
        ngx_log_error(NGX_LOG_ERR, log, 0, "oidc: SQLite schema setup failed: %s",
                      sqlite3_errmsg(p->session_db));
        sqlite3_close(p->session_db);
        p->session_db = NULL;
        return NGX_ERROR;
    }
    return NGX_OK;
}

static ngx_int_t
ngx_http_oidc_session_db_store(ngx_http_request_t *r, ngx_http_oidc_provider_t *p,
    ngx_str_t *session, ngx_str_t *refresh_token, time_t access_expires,
    time_t expires, ngx_str_t *sid, ngx_str_t *sub, ngx_str_t *cookie)
{
    sqlite3_stmt  *stmt = NULL;
    ngx_str_t  random;
    int  rc;

    if (ngx_http_oidc_session_db_open(p, r->connection->log) != NGX_OK
        || ngx_http_oidc_random(r->pool, 32, &random) != NGX_OK
        || ngx_http_oidc_b64url_encode(r->pool, &random, cookie) != NGX_OK)
    {
        return NGX_ERROR;
    }
    rc = sqlite3_prepare_v2(p->session_db,
        "INSERT INTO oidc_sessions(id, session, refresh_token, access_expires_at, expires_at, sid, sub) VALUES(?, ?, ?, ?, ?, ?, ?)",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK
        || sqlite3_bind_text(stmt, 1, (const char *) cookie->data, cookie->len,
                             SQLITE_TRANSIENT) != SQLITE_OK
        || sqlite3_bind_blob(stmt, 2, session->data, session->len,
                             SQLITE_TRANSIENT) != SQLITE_OK
        || sqlite3_bind_blob(stmt, 3, refresh_token->data, refresh_token->len,
                             SQLITE_TRANSIENT) != SQLITE_OK
        || sqlite3_bind_int64(stmt, 4, access_expires) != SQLITE_OK
        || sqlite3_bind_int64(stmt, 5, expires) != SQLITE_OK
        || sqlite3_bind_text(stmt, 6, (const char *) sid->data, sid->len,
                             SQLITE_TRANSIENT) != SQLITE_OK
        || sqlite3_bind_text(stmt, 7, (const char *) sub->data, sub->len,
                             SQLITE_TRANSIENT) != SQLITE_OK
        || sqlite3_step(stmt) != SQLITE_DONE)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "oidc: SQLite insert failed: %s",
                      sqlite3_errmsg(p->session_db));
        if (stmt) sqlite3_finalize(stmt);
        return NGX_ERROR;
    }
    sqlite3_finalize(stmt);
    sqlite3_exec(p->session_db, "DELETE FROM oidc_sessions WHERE expires_at < strftime('%s','now')",
                 NULL, NULL, NULL);
    return NGX_OK;
}

static void
ngx_http_oidc_revoke_refresh_token(ngx_http_request_t *r,
    ngx_http_oidc_provider_t *p, ngx_str_t *cookie)
{
    sqlite3_stmt               *stmt = NULL;
    const void                 *blob;
    int                         len;
    ngx_http_oidc_http_resp_t  resp;
    ngx_str_t                   encrypted, refresh, body, cred, cred_b64, auth;
    u_char                     *q;

    if (p->revocation_endpoint.len == 0
        && ngx_http_oidc_discover(p, r->connection->log) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "oidc: refresh-token revocation skipped: discovery failed");
        return;
    }
    if (p->revocation_endpoint.len == 0
        || ngx_http_oidc_session_db_open(p, r->connection->log) != NGX_OK
        || sqlite3_prepare_v2(p->session_db,
            "SELECT refresh_token FROM oidc_sessions WHERE id = ?", -1,
            &stmt, NULL) != SQLITE_OK
        || sqlite3_bind_text(stmt, 1, (const char *) cookie->data, cookie->len,
                             SQLITE_TRANSIENT) != SQLITE_OK)
    {
        if (stmt) sqlite3_finalize(stmt);
        return;
    }
    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return;
    }
    blob = sqlite3_column_blob(stmt, 0);
    len = sqlite3_column_bytes(stmt, 0);
    encrypted.data = ngx_pnalloc(r->pool, len ? len : 1);
    if (encrypted.data == NULL) {
        sqlite3_finalize(stmt);
        return;
    }
    ngx_memcpy(encrypted.data, blob, len);
    encrypted.len = len;
    sqlite3_finalize(stmt);

    if (len == 0 || ngx_http_oidc_session_decrypt(r->pool, p, &encrypted,
                                                   &refresh) != NGX_OK
        || refresh.len == 0)
    {
        return;
    }

    body.len = sizeof("token=&token_type_hint=refresh_token") - 1 + refresh.len * 3;
    body.data = ngx_pnalloc(r->pool, body.len);
    if (body.data == NULL) {
        return;
    }
    q = ngx_cpymem(body.data, "token=", 6);
    q = (u_char *) ngx_escape_uri(q, refresh.data, refresh.len,
                                  NGX_ESCAPE_URI_COMPONENT);
    q = ngx_cpymem(q, "&token_type_hint=refresh_token", 30);
    body.len = q - body.data;

    cred.len = p->client_id.len + 1 + p->client_secret.len;
    cred.data = ngx_pnalloc(r->pool, cred.len);
    cred_b64.data = ngx_pnalloc(r->pool, ngx_base64_encoded_length(cred.len));
    if (cred.data == NULL || cred_b64.data == NULL) {
        return;
    }
    q = ngx_cpymem(cred.data, p->client_id.data, p->client_id.len);
    *q++ = ':';
    ngx_memcpy(q, p->client_secret.data, p->client_secret.len);
    ngx_encode_base64(&cred_b64, &cred);
    auth.len = 6 + cred_b64.len;
    auth.data = ngx_pnalloc(r->pool, auth.len);
    if (auth.data == NULL) {
        return;
    }
    ngx_memcpy(auth.data, "Basic ", 6);
    ngx_memcpy(auth.data + 6, cred_b64.data, cred_b64.len);

    if (ngx_http_oidc_http_post_form(r->pool, r->connection->log,
            &p->revocation_endpoint, &p->ssl_trusted_certificate, &auth,
            &body, &resp) != NGX_OK || (resp.status != 200 && resp.status != 204))
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "oidc: refresh-token revocation failed");
    }
}

static ngx_int_t
ngx_http_oidc_session_db_load(ngx_http_request_t *r, ngx_http_oidc_provider_t *p,
    ngx_str_t *cookie, ngx_str_t *session, ngx_str_t *refresh_token,
    time_t *access_expires)
{
    sqlite3_stmt  *stmt = NULL;
    const void  *blob;
    int  len, rc;

    if (ngx_http_oidc_session_db_open(p, r->connection->log) != NGX_OK
        || sqlite3_prepare_v2(p->session_db,
            "SELECT session, refresh_token, access_expires_at FROM oidc_sessions WHERE id = ? AND expires_at >= ?", -1,
            &stmt, NULL) != SQLITE_OK
        || sqlite3_bind_text(stmt, 1, (const char *) cookie->data, cookie->len,
                             SQLITE_TRANSIENT) != SQLITE_OK
        || sqlite3_bind_int64(stmt, 2, ngx_time()) != SQLITE_OK)
    {
        if (stmt) sqlite3_finalize(stmt);
        return NGX_ERROR;
    }
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return NGX_DECLINED;
    }
    blob = sqlite3_column_blob(stmt, 0);
    len = sqlite3_column_bytes(stmt, 0);
    session->data = ngx_pnalloc(r->pool, len);
    if (session->data == NULL) {
        sqlite3_finalize(stmt);
        return NGX_ERROR;
    }
    ngx_memcpy(session->data, blob, len);
    session->len = len;
    {
        const void  *rb = sqlite3_column_blob(stmt, 1);
        int  rlen = sqlite3_column_bytes(stmt, 1);
        refresh_token->data = ngx_pnalloc(r->pool, rlen ? rlen : 1);
        if (refresh_token->data == NULL) {
            sqlite3_finalize(stmt);
            return NGX_ERROR;
        }
        ngx_memcpy(refresh_token->data, rb, rlen);
        refresh_token->len = rlen;
    }
    *access_expires = sqlite3_column_int64(stmt, 2);
    sqlite3_finalize(stmt);
    return NGX_OK;
}

static ngx_int_t
ngx_http_oidc_refresh_session(ngx_http_request_t *r, ngx_http_oidc_provider_t *p,
    ngx_str_t *cookie, ngx_str_t *refresh_token)
{
    sqlite3_stmt  *stmt = NULL;
    ngx_http_oidc_http_resp_t  resp;
    ngx_str_t  body, credentials, credentials_b64, auth, next_refresh,
               encrypted_refresh, expires_s;
    u_char  *q;
    time_t  expires;

    if (p->token_endpoint.len == 0
        && ngx_http_oidc_discover(p, r->connection->log) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_http_oidc_session_db_open(p, r->connection->log) != NGX_OK) {
        return NGX_ERROR;
    }

    body.len = sizeof("grant_type=refresh_token&refresh_token=") - 1
               + refresh_token->len;
    body.data = ngx_pnalloc(r->pool, body.len);
    credentials.len = p->client_id.len + 1 + p->client_secret.len;
    credentials.data = ngx_pnalloc(r->pool, credentials.len);
    credentials_b64.data = ngx_pnalloc(r->pool,
                        ngx_base64_encoded_length(credentials.len));
    if (body.data == NULL || credentials.data == NULL
        || credentials_b64.data == NULL)
    {
        return NGX_ERROR;
    }
    q = ngx_cpymem(body.data, "grant_type=refresh_token&refresh_token=",
                   sizeof("grant_type=refresh_token&refresh_token=") - 1);
    ngx_memcpy(q, refresh_token->data, refresh_token->len);

    q = ngx_cpymem(credentials.data, p->client_id.data, p->client_id.len);
    *q++ = ':';
    ngx_memcpy(q, p->client_secret.data, p->client_secret.len);
    ngx_encode_base64(&credentials_b64, &credentials);

    auth.len = sizeof("Basic ") - 1 + credentials_b64.len;
    auth.data = ngx_pnalloc(r->pool, auth.len);
    if (auth.data == NULL) {
        return NGX_ERROR;
    }
    q = ngx_cpymem(auth.data, "Basic ", sizeof("Basic ") - 1);
    ngx_memcpy(q, credentials_b64.data, credentials_b64.len);

    if (ngx_http_oidc_http_post_form(r->pool, r->connection->log, &p->token_endpoint,
            &p->ssl_trusted_certificate, &auth, &body, &resp) != NGX_OK
        || resp.status != 200
        || ngx_http_oidc_json_get_string(r->pool, &resp.body,
               &(ngx_str_t) ngx_string("refresh_token"), &next_refresh) != NGX_OK
        || ngx_http_oidc_json_get_string(r->pool, &resp.body,
               &(ngx_str_t) ngx_string("expires_in"), &expires_s) != NGX_OK
        || ngx_http_oidc_session_encrypt(r->pool, p, &next_refresh,
                                         &encrypted_refresh) != NGX_OK)
    {
        return NGX_ERROR;
    }

    expires = ngx_time() + ngx_atotm(expires_s.data, expires_s.len);

    /* Transaktion erst jetzt: ein langsamer IdP darf keinen SQLite-Write-Lock
     * halten, sonst laufen andere Worker in das busy_timeout. */
    if (sqlite3_exec(p->session_db, "BEGIN IMMEDIATE", NULL, NULL, NULL)
        != SQLITE_OK
        || sqlite3_prepare_v2(p->session_db,
            "UPDATE oidc_sessions SET refresh_token = ?, access_expires_at = ? "
            "WHERE id = ?", -1, &stmt, NULL) != SQLITE_OK
        || sqlite3_bind_blob(stmt, 1, encrypted_refresh.data,
                             encrypted_refresh.len, SQLITE_TRANSIENT) != SQLITE_OK
        || sqlite3_bind_int64(stmt, 2, expires) != SQLITE_OK
        || sqlite3_bind_text(stmt, 3, (const char *) cookie->data, cookie->len,
                             SQLITE_TRANSIENT) != SQLITE_OK
        || sqlite3_step(stmt) != SQLITE_DONE)
    {
        if (stmt) sqlite3_finalize(stmt);
        sqlite3_exec(p->session_db, "ROLLBACK", NULL, NULL, NULL);
        return NGX_ERROR;
    }
    sqlite3_finalize(stmt);
    if (sqlite3_exec(p->session_db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

static ngx_int_t
ngx_http_oidc_get_body_arg(ngx_http_request_t *r, ngx_str_t *name,
    ngx_str_t *value)
{
    ngx_chain_t  *cl;
    u_char       *p, *end, *vstart, *vend, *dst;
    size_t        len = 0;
    ngx_str_t     body;

    if (r->request_body == NULL || r->request_body->bufs == NULL) {
        return NGX_DECLINED;
    }

    for (cl = r->request_body->bufs; cl; cl = cl->next) {
        len += ngx_buf_size(cl->buf);
    }
    if (len == 0) {
        return NGX_DECLINED;
    }
    body.data = ngx_pnalloc(r->pool, len);
    if (body.data == NULL) {
        return NGX_ERROR;
    }
    p = body.data;
    for (cl = r->request_body->bufs; cl; cl = cl->next) {
        p = ngx_cpymem(p, cl->buf->pos, ngx_buf_size(cl->buf));
    }
    body.len = len;

    p = body.data;
    end = body.data + body.len;
    while (p < end) {
        vstart = (p == body.data || *(p - 1) == '&') ? p : NULL;
        vend = p;
        while (vend < end && *vend != '=' && *vend != '&') {
            vend++;
        }
        if (vstart != NULL && vend < end && *vend == '='
            && (size_t) (vend - vstart) == name->len
            && ngx_strncmp(vstart, name->data, name->len) == 0)
        {
            vstart = vend + 1;
            vend = vstart;
            while (vend < end && *vend != '&') {
                vend++;
            }
            dst = ngx_pnalloc(r->pool, vend - vstart + 1);
            if (dst == NULL) {
                return NGX_ERROR;
            }
            value->data = dst;
            ngx_unescape_uri(&dst, &vstart, vend - vstart, 0);
            value->len = dst - value->data;
            return NGX_OK;
        }
        p = vend < end ? vend + 1 : end;
    }

    return NGX_DECLINED;
}

static ngx_int_t
ngx_http_oidc_session_db_delete_sub(ngx_http_oidc_provider_t *p, ngx_str_t *sid,
    ngx_str_t *sub, ngx_log_t *log)
{
    sqlite3_stmt  *stmt = NULL;
    const char  *sql;

    if (ngx_http_oidc_session_db_open(p, log) != NGX_OK) {
        return NGX_ERROR;
    }

    if (sid->len > 0) {
        sql = "DELETE FROM oidc_sessions WHERE sid = ?";
    } else {
        sql = "DELETE FROM oidc_sessions WHERE sub = ?";
    }

    if (sqlite3_prepare_v2(p->session_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return NGX_ERROR;
    }
    if (sid->len > 0) {
        sqlite3_bind_text(stmt, 1, (const char *) sid->data, sid->len,
                          SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_text(stmt, 1, (const char *) sub->data, sub->len,
                          SQLITE_TRANSIENT);
    }
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return NGX_ERROR;
    }
    sqlite3_finalize(stmt);
    return NGX_OK;
}

static ngx_int_t
ngx_http_oidc_backchannel(ngx_http_request_t *r, ngx_http_oidc_provider_t *p)
{
    ngx_http_oidc_request_ctx_t  *ctx;

    if (!(r->method & NGX_HTTP_POST)) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_oidc_request_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ctx->provider = p;
    ngx_http_set_ctx(r, ctx, ngx_http_oidc_module);

    {
        ngx_int_t rc = ngx_http_read_client_request_body(r,
                                             ngx_http_oidc_backchannel_done);
        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }
    }

    return NGX_DONE;
}

static void
ngx_http_oidc_backchannel_done(ngx_http_request_t *r)
{
    ngx_http_oidc_request_ctx_t  *ctx;
    ngx_http_oidc_provider_t    *p;
    ngx_str_t  token = ngx_null_string, sid, sub, claims;
    ngx_uint_t  status = NGX_HTTP_OK;

    ctx = ngx_http_get_module_ctx(r, ngx_http_oidc_module);
    p = ctx != NULL ? ctx->provider : NULL;
    if (p == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (ngx_http_oidc_get_body_arg(r, &(ngx_str_t) ngx_string("logout_token"),
                                   &token) != NGX_OK
        || token.len == 0)
    {
        status = NGX_HTTP_BAD_REQUEST;
    }

    if (status == NGX_HTTP_OK
        && p->jwks.len == 0
        && ngx_http_oidc_fetch_jwks(p, r->connection->log) != NGX_OK)
    {
        status = NGX_HTTP_BAD_REQUEST;
    }

    if (status == NGX_HTTP_OK
        && ngx_http_oidc_jwt_verify(r->connection->log, r->pool, &token, &p->jwks,
                                    &p->issuer, &p->client_id, NULL, 0, 1,
                                    &claims) != NGX_OK)
    {
        status = NGX_HTTP_BAD_REQUEST;
    }

    /* spec: logout token must not carry nonce */
    if (status == NGX_HTTP_OK
        && ngx_http_oidc_json_has_key(&claims,
                &(ngx_str_t) ngx_string("nonce")) == NGX_OK)
    {
        status = NGX_HTTP_BAD_REQUEST;
    }

    if (status == NGX_HTTP_OK
        && ngx_http_oidc_json_object_has_key(&claims,
                &(ngx_str_t) ngx_string("events"),
                &(ngx_str_t)
                ngx_string("http://schemas.openid.net/event/backchannel-logout"))
           != NGX_OK)
    {
        status = NGX_HTTP_BAD_REQUEST;
    }

    ngx_str_null(&sid);
    ngx_str_null(&sub);
    if (status == NGX_HTTP_OK) {
        if (ngx_http_oidc_json_get_string(r->pool, &claims,
                &(ngx_str_t) ngx_string("sid"), &sid) != NGX_OK)
        {
            ngx_str_null(&sid);
        }
        if (ngx_http_oidc_json_get_string(r->pool, &claims,
                &(ngx_str_t) ngx_string("sub"), &sub) != NGX_OK)
        {
            ngx_str_null(&sub);
        }
        if (sid.len == 0 && sub.len == 0) {
            status = NGX_HTTP_BAD_REQUEST;
        } else {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "oidc: backchannel logout (sid=%V sub=%V)",
                          &sid, &sub);
            if (ngx_http_oidc_session_db_delete_sub(p, &sid, &sub,
                                                    r->connection->log)
                != NGX_OK)
            {
                status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    }

    if (status != NGX_HTTP_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc: backchannel logout rejected");
    }

    r->headers_out.status = status;
    r->headers_out.content_length_n = 0;
    {
        ngx_buf_t   *b;
        ngx_chain_t  out;

        r->headers_out.status = status;
        r->headers_out.content_length_n = 0;
        if (ngx_http_send_header(r) == NGX_ERROR) {
            ngx_http_finalize_request(r, NGX_ERROR);
            return;
        }
        b = ngx_calloc_buf(r->pool);
        if (b == NULL) {
            ngx_http_finalize_request(r, NGX_ERROR);
            return;
        }
        b->last_buf = 1;
        out.buf = b;
        out.next = NULL;
        ngx_http_finalize_request(r, ngx_http_output_filter(r, &out));
    }
}

static void
ngx_http_oidc_session_db_delete(ngx_http_oidc_provider_t *p, ngx_str_t *cookie)
{
    sqlite3_stmt  *stmt = NULL;

    if (ngx_http_oidc_session_db_open(p, ngx_cycle->log) != NGX_OK
        || sqlite3_prepare_v2(p->session_db, "DELETE FROM oidc_sessions WHERE id = ?",
                              -1, &stmt, NULL) != SQLITE_OK)
    {
        if (stmt) sqlite3_finalize(stmt);
        return;
    }
    sqlite3_bind_text(stmt, 1, (const char *) cookie->data, cookie->len,
                      SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

static ngx_int_t
ngx_http_oidc_session_encrypt(ngx_pool_t *pool, ngx_http_oidc_provider_t *p,
    ngx_str_t *plaintext, ngx_str_t *out)
{
    u_char  key[EVP_MAX_MD_SIZE], nonce[12], tag[16];
    unsigned int  key_len;
    EVP_CIPHER_CTX *ctx;
    ngx_str_t  raw;
    int  len, total;

    if (EVP_Digest(p->session_encryption_key.data, p->session_encryption_key.len,
                   key, &key_len, EVP_sha256(), NULL) != 1 || key_len != 32
        || RAND_bytes(nonce, sizeof(nonce)) != 1)
    {
        return NGX_ERROR;
    }
    raw.len = sizeof(nonce) + plaintext->len + sizeof(tag);
    raw.data = ngx_pnalloc(pool, raw.len);
    if (raw.data == NULL) {
        return NGX_ERROR;
    }
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return NGX_ERROR;
    }
    total = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, nonce) != 1
        || EVP_EncryptUpdate(ctx, raw.data + sizeof(nonce), &len,
                             plaintext->data, plaintext->len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return NGX_ERROR;
    }
    total += len;
    if (EVP_EncryptFinal_ex(ctx, raw.data + sizeof(nonce) + total, &len) != 1
        || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return NGX_ERROR;
    }
    total += len;
    ngx_memcpy(raw.data, nonce, sizeof(nonce));
    ngx_memcpy(raw.data + sizeof(nonce) + total, tag, sizeof(tag));
    raw.len = sizeof(nonce) + total + sizeof(tag);
    EVP_CIPHER_CTX_free(ctx);

    return ngx_http_oidc_b64url_encode(pool, &raw, out);
}

static ngx_int_t
ngx_http_oidc_session_decrypt(ngx_pool_t *pool, ngx_http_oidc_provider_t *p,
    ngx_str_t *in, ngx_str_t *plaintext)
{
    u_char  key[EVP_MAX_MD_SIZE];
    unsigned int  key_len;
    EVP_CIPHER_CTX *ctx;
    ngx_str_t  raw;
    size_t  ciphertext_len;
    int  len, total;

    if (ngx_http_oidc_b64url_decode(pool, in, &raw) != NGX_OK
        || raw.len < 12 + 16
        || EVP_Digest(p->session_encryption_key.data, p->session_encryption_key.len,
                      key, &key_len, EVP_sha256(), NULL) != 1 || key_len != 32)
    {
        return NGX_ERROR;
    }
    ciphertext_len = raw.len - 12 - 16;
    plaintext->data = ngx_pnalloc(pool, ciphertext_len);
    if (plaintext->data == NULL) {
        return NGX_ERROR;
    }
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return NGX_ERROR;
    }
    total = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, raw.data) != 1
        || EVP_DecryptUpdate(ctx, plaintext->data, &len, raw.data + 12,
                             ciphertext_len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return NGX_ERROR;
    }
    total += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                            raw.data + 12 + ciphertext_len) != 1
        || EVP_DecryptFinal_ex(ctx, plaintext->data + total, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return NGX_ERROR;
    }
    plaintext->len = total + len;
    EVP_CIPHER_CTX_free(ctx);
    return NGX_OK;
}

static ngx_int_t
ngx_http_oidc_random(ngx_pool_t *pool, size_t len, ngx_str_t *out)
{
    out->data = ngx_pnalloc(pool, len);
    if (out->data == NULL) {
        return NGX_ERROR;
    }

    if (RAND_bytes(out->data, len) != 1) {
        return NGX_ERROR;
    }

    out->len = len;
    return NGX_OK;
}

static ngx_int_t
ngx_http_oidc_get_cookie(ngx_http_request_t *r, ngx_str_t *name,
    ngx_str_t *value)
{
    ngx_str_t   cookie;
    u_char     *p, *end, *eq, *semi;

    if (r->headers_in.cookie == NULL) {
        return NGX_DECLINED;
    }

    cookie = r->headers_in.cookie->value;
    p = cookie.data;
    end = cookie.data + cookie.len;

    while (p < end) {
        while (p < end && (*p == ' ' || *p == ';')) {
            p++;
        }
        eq = ngx_strlchr(p, end, '=');
        if (eq == NULL) {
            break;
        }
        semi = ngx_strlchr(eq, end, ';');
        if (semi == NULL) {
            semi = end;
        }

        if ((size_t) (eq - p) == name->len
            && ngx_strncmp(p, name->data, name->len) == 0)
        {
            value->data = eq + 1;
            value->len = semi - eq - 1;
            return NGX_OK;
        }

        p = semi;
    }

    return NGX_DECLINED;
}

static ngx_int_t
ngx_http_oidc_set_cookie(ngx_http_request_t *r, ngx_str_t *name,
    ngx_str_t *value, ngx_str_t *path, time_t max_age)
{
    ngx_table_elt_t  *h;
    u_char           *p;
    size_t            len;

    len = name->len + 1 + value->len + sizeof("; Path=") - 1 + path->len
          + sizeof("; HttpOnly; SameSite=Lax") - 1 + 32;
    if (r->connection->ssl != NULL) {
        len += sizeof("; Secure") - 1;
    }
    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    h->hash = 1;
    ngx_str_set(&h->key, "Set-Cookie");

    h->value.data = ngx_pnalloc(r->pool, len);
    if (h->value.data == NULL) {
        return NGX_ERROR;
    }
    p = ngx_cpymem(h->value.data, name->data, name->len);
    *p++ = '=';
    p = ngx_cpymem(p, value->data, value->len);
    p = ngx_cpymem(p, "; Path=", 7);
    p = ngx_cpymem(p, path->data, path->len);
    p = ngx_cpymem(p, "; HttpOnly; SameSite=Lax", 24);
    if (r->connection->ssl != NULL) {
        p = ngx_cpymem(p, "; Secure", sizeof("; Secure") - 1);
    }
    if (max_age > 0) {
        p = ngx_sprintf(p, "; Max-Age=%T", max_age);
    }
    h->value.len = p - h->value.data;

    return NGX_OK;
}

static ngx_int_t
ngx_http_oidc_get_query_arg(ngx_http_request_t *r, ngx_str_t *name,
    ngx_str_t *value)
{
    u_char  *p, *end, *eq, *amp;

    if (r->args.len == 0) {
        return NGX_DECLINED;
    }

    p = r->args.data;
    end = r->args.data + r->args.len;

    while (p < end) {
        eq = ngx_strlchr(p, end, '=');
        if (eq == NULL) {
            break;
        }
        amp = ngx_strlchr(eq, end, '&');
        if (amp == NULL) {
            amp = end;
        }

        if ((size_t) (eq - p) == name->len
            && ngx_strncmp(p, name->data, name->len) == 0)
        {
            value->data = eq + 1;
            value->len = amp - eq - 1;
            return NGX_OK;
        }

        p = amp + 1;
    }

    return NGX_DECLINED;
}
