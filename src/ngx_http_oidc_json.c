#include "ngx_http_oidc.h"

#define NGX_OIDC_JSON_KEY_MAX  128

static ngx_int_t
ngx_http_oidc_json_load(ngx_str_t *json, json_t **root)
{
    json_error_t  error;

    *root = json_loadb((const char *) json->data, json->len,
                       JSON_REJECT_DUPLICATES, &error);
    return *root ? NGX_OK : NGX_DECLINED;
}

/* Strip control characters (CR, LF, NUL, ...) in place. Claim values end up
 * in proxied headers; a newline in a claim must never break header framing. */
static size_t
ngx_http_oidc_json_sanitize(u_char *p, size_t len)
{
    size_t  i, j;

    for (i = 0, j = 0; i < len; i++) {
        if (p[i] >= 0x20 && p[i] != 0x7F) {
            p[j++] = p[i];
        }
    }
    return j;
}

static json_t *
ngx_http_oidc_json_object_get(json_t *object, ngx_str_t *key)
{
    u_char  name[NGX_OIDC_JSON_KEY_MAX];

    if (key->len == 0 || key->len + 1 > sizeof(name)) {
        return NULL;
    }
    ngx_memcpy(name, key->data, key->len);
    name[key->len] = '\0';
    return json_object_get(object, (const char *) name);
}

ngx_int_t
ngx_http_oidc_json_get_string(ngx_pool_t *pool, ngx_str_t *json, ngx_str_t *key,
    ngx_str_t *out)
{
    json_t  *root, *value;
    const char  *string;

    if (ngx_http_oidc_json_load(json, &root) != NGX_OK) {
        return NGX_DECLINED;
    }
    value = ngx_http_oidc_json_object_get(root, key);
    if (json_is_string(value)) {
        string = json_string_value(value);
        out->len = json_string_length(value);
        out->data = ngx_pnalloc(pool, out->len);
        if (out->data == NULL) {
            json_decref(root);
            return NGX_ERROR;
        }
        ngx_memcpy(out->data, string, out->len);
        out->len = ngx_http_oidc_json_sanitize(out->data, out->len);
    } else if (json_is_integer(value)) {
        out->data = ngx_pnalloc(pool, NGX_INT_T_LEN);
        if (out->data == NULL) {
            json_decref(root);
            return NGX_ERROR;
        }
        out->len = ngx_sprintf(out->data, "%L", (int64_t) json_integer_value(value))
                   - out->data;
    } else {
        json_decref(root);
        return NGX_DECLINED;
    }
    json_decref(root);
    return NGX_OK;
}

ngx_int_t
ngx_http_oidc_json_has_key(ngx_str_t *json, ngx_str_t *key)
{
    json_t  *root, *value;
    ngx_int_t  rc;

    if (ngx_http_oidc_json_load(json, &root) != NGX_OK) {
        return NGX_DECLINED;
    }
    value = ngx_http_oidc_json_object_get(root, key);
    rc = (value && !json_is_null(value)) ? NGX_OK : NGX_DECLINED;
    json_decref(root);
    return rc;
}

ngx_int_t
ngx_http_oidc_json_object_has_key(ngx_str_t *json, ngx_str_t *key,
    ngx_str_t *member)
{
    json_t  *root, *obj, *value;
    ngx_int_t  rc;

    if (ngx_http_oidc_json_load(json, &root) != NGX_OK) {
        return NGX_DECLINED;
    }
    obj = ngx_http_oidc_json_object_get(root, key);
    if (!json_is_object(obj)) {
        json_decref(root);
        return NGX_DECLINED;
    }
    value = ngx_http_oidc_json_object_get(obj, member);
    rc = (value && !json_is_null(value)) ? NGX_OK : NGX_DECLINED;
    json_decref(root);
    return rc;
}

ngx_int_t
ngx_http_oidc_json_array_contains(ngx_str_t *json, ngx_str_t *key,
    ngx_str_t *needle)
{
    json_t  *root, *array, *value;
    size_t   index;

    if (ngx_http_oidc_json_load(json, &root) != NGX_OK) {
        return NGX_DECLINED;
    }
    array = ngx_http_oidc_json_object_get(root, key);
    if (!json_is_array(array)) {
        json_decref(root);
        return NGX_DECLINED;
    }
    json_array_foreach(array, index, value) {
        if (json_is_string(value) && json_string_length(value) == needle->len
            && ngx_strncmp(json_string_value(value), needle->data, needle->len) == 0)
        {
            json_decref(root);
            return NGX_OK;
        }
    }
    json_decref(root);
    return NGX_DECLINED;
}
