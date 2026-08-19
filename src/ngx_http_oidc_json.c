#include "ngx_http_oidc.h"

static ngx_int_t
ngx_http_oidc_json_load(ngx_str_t *json, json_t **root)
{
    json_error_t  error;

    *root = json_loadb((const char *) json->data, json->len,
                       JSON_REJECT_DUPLICATES, &error);
    return *root ? NGX_OK : NGX_DECLINED;
}

ngx_int_t
ngx_http_oidc_json_get_string(ngx_str_t *json, ngx_str_t *key, ngx_str_t *out)
{
    json_t  *root, *value;
    const char  *string;

    if (ngx_http_oidc_json_load(json, &root) != NGX_OK) {
        return NGX_DECLINED;
    }
    value = json_object_getn(root, (const char *) key->data, key->len);
    if (json_is_string(value)) {
        string = json_string_value(value);
        out->len = json_string_length(value);
        out->data = ngx_pnalloc(ngx_cycle->pool, out->len);
        if (out->data == NULL) {
            json_decref(root);
            return NGX_ERROR;
        }
        ngx_memcpy(out->data, string, out->len);
    } else if (json_is_integer(value)) {
        out->data = ngx_pnalloc(ngx_cycle->pool, NGX_INT_T_LEN);
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
ngx_http_oidc_json_array_contains(ngx_str_t *json, ngx_str_t *key,
    ngx_str_t *needle)
{
    json_t  *root, *array, *value;
    size_t   index;

    if (ngx_http_oidc_json_load(json, &root) != NGX_OK) {
        return NGX_DECLINED;
    }
    array = json_object_getn(root, (const char *) key->data, key->len);
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
