#include "ngx_http_oidc.h"

ngx_int_t
ngx_http_oidc_b64url_decode(ngx_pool_t *pool, ngx_str_t *in, ngx_str_t *out)
{
    out->data = ngx_pnalloc(pool, ngx_base64_decoded_length(in->len));
    if (out->data == NULL) {
        return NGX_ERROR;
    }
    return ngx_decode_base64url(out, in);
}

ngx_int_t
ngx_http_oidc_b64url_encode(ngx_pool_t *pool, ngx_str_t *in, ngx_str_t *out)
{
    out->data = ngx_pnalloc(pool, ngx_base64_encoded_length(in->len));
    if (out->data == NULL) {
        return NGX_ERROR;
    }
    ngx_encode_base64url(out, in);
    return NGX_OK;
}

ngx_int_t
ngx_http_oidc_hmac_sha256(ngx_pool_t *pool, ngx_str_t *key, ngx_str_t *data,
    ngx_str_t *out)
{
    unsigned char  md[EVP_MAX_MD_SIZE];
    unsigned int   mdlen = 0;

    if (HMAC(EVP_sha256(), key->data, key->len, data->data, data->len,
             md, &mdlen) == NULL)
    {
        return NGX_ERROR;
    }

    out->len = mdlen;
    out->data = ngx_pnalloc(pool, mdlen);
    if (out->data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(out->data, md, mdlen);
    return NGX_OK;
}

/*
 * Verify an RS256-signed JWT against a JWKS document.
 * On success, extracts "sub" and the full payload (claims) JSON.
 */
ngx_int_t
ngx_http_oidc_jwt_verify(ngx_log_t *log, ngx_str_t *jwt, ngx_str_t *jwks,
    ngx_str_t *issuer, ngx_str_t *client_id, ngx_str_t *nonce, time_t max_age,
    ngx_str_t *claims_out)
{
    u_char  *dot1, *dot2;
    ngx_str_t  header_b64, payload_b64, sig_b64;
    ngx_str_t  header, payload, sig;
    ngx_str_t  kid, alg;
    ngx_str_t  n, e;
    ngx_str_t  exp_s, iss_s, aud_s, nonce_s, azp_s, auth_time_s;
    ngx_str_t  signing_input;
    u_char  *sp;
    size_t   slen;
    time_t   now, exp;
    ngx_int_t rc, aud_is_array;

    /* split into three parts */
    dot1 = ngx_strlchr(jwt->data, jwt->data + jwt->len, '.');
    if (dot1 == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "oidc: malformed JWT (no dot)");
        return NGX_ERROR;
    }
    dot2 = ngx_strlchr(dot1 + 1, jwt->data + jwt->len, '.');
    if (dot2 == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "oidc: malformed JWT (no 2nd dot)");
        return NGX_ERROR;
    }

    header_b64.data = jwt->data;
    header_b64.len = dot1 - jwt->data;
    payload_b64.data = dot1 + 1;
    payload_b64.len = dot2 - dot1 - 1;
    sig_b64.data = dot2 + 1;
    sig_b64.len = jwt->data + jwt->len - dot2 - 1;

    if (ngx_http_oidc_b64url_decode(ngx_cycle->pool, &header_b64, &header)
        != NGX_OK)
    {
        return NGX_ERROR;
    }
    if (ngx_http_oidc_b64url_decode(ngx_cycle->pool, &payload_b64, &payload)
        != NGX_OK)
    {
        return NGX_ERROR;
    }
    if (ngx_http_oidc_b64url_decode(ngx_cycle->pool, &sig_b64, &sig) != NGX_OK) {
        return NGX_ERROR;
    }

    /* header: alg + kid */
    if (ngx_http_oidc_json_get_string(&header, &(ngx_str_t) ngx_string("alg"),
                                      &alg) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, log, 0, "oidc: JWT header missing alg");
        return NGX_ERROR;
    }
    if (alg.len != 5 || ngx_strncmp(alg.data, "RS256", 5) != 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "oidc: unsupported JWT alg");
        return NGX_ERROR;
    }

    rc = ngx_http_oidc_json_get_string(&header,
                                       &(ngx_str_t) ngx_string("kid"), &kid);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "oidc: JWT header missing kid");
        return NGX_ERROR;
    }

    /* find matching key in JWKS */
    {
        u_char  *jp = jwks->data;
        u_char  *jend = jwks->data + jwks->len;
        ngx_str_t  jkid, jn, je;
        ngx_int_t  found = 0;

        while (jp < jend) {
            jp = ngx_strlchr(jp, jend, '{');
            if (jp == NULL) {
                break;
            }
            /* find matching "kid" within this object */
            {
                u_char  *close = ngx_strlchr(jp, jend, '}');
                ngx_str_t  obj;
                if (close == NULL) {
                    break;
                }
                obj.data = jp;
                obj.len = close - jp + 1;

                if (ngx_http_oidc_json_get_string(&obj,
                        &(ngx_str_t) ngx_string("kid"), &jkid) == NGX_OK
                    && jkid.len == kid.len
                    && ngx_strncmp(jkid.data, kid.data, kid.len) == 0)
                {
                    if (ngx_http_oidc_json_get_string(&obj,
                            &(ngx_str_t) ngx_string("n"), &jn) == NGX_OK
                        && ngx_http_oidc_json_get_string(&obj,
                            &(ngx_str_t) ngx_string("e"), &je) == NGX_OK)
                    {
                        n = jn;
                        e = je;
                        found = 1;
                        break;
                    }
                }
            }
            jp++;
        }

        if (!found) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "oidc: no matching JWK for kid");
            return NGX_DECLINED;
        }
    }

    /* build RSA public key and verify signature */
    {
        ngx_str_t  n_bin, e_bin;
        BIGNUM  *bn_n = NULL, *bn_e = NULL;
        RSA     *rsa = NULL;
        EVP_PKEY *pkey = NULL;
        EVP_MD_CTX *ctx = NULL;
        ngx_int_t  ok = NGX_ERROR;

        if (ngx_http_oidc_b64url_decode(ngx_cycle->pool, &n, &n_bin) != NGX_OK
            || ngx_http_oidc_b64url_decode(ngx_cycle->pool, &e, &e_bin)
               != NGX_OK)
        {
            goto done;
        }

        bn_n = BN_bin2bn(n_bin.data, n_bin.len, NULL);
        bn_e = BN_bin2bn(e_bin.data, e_bin.len, NULL);
        if (bn_n == NULL || bn_e == NULL) {
            goto done;
        }

        rsa = RSA_new();
        if (rsa == NULL) {
            goto done;
        }
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        if (RSA_set0_key(rsa, bn_n, bn_e, NULL) != 1) {
            goto done;
        }
        bn_n = NULL;
        bn_e = NULL;
#else
        rsa->n = bn_n;
        rsa->e = bn_e;
        bn_n = NULL;
        bn_e = NULL;
#endif

        pkey = EVP_PKEY_new();
        if (pkey == NULL || EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
            goto done;
        }
        rsa = NULL;

        ctx = EVP_MD_CTX_new();
        if (ctx == NULL) {
            goto done;
        }

        signing_input.data = jwt->data;
        signing_input.len = dot2 - jwt->data;

        if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
            goto done;
        }
        if (EVP_DigestVerifyUpdate(ctx, signing_input.data,
                                   signing_input.len) != 1)
        {
            goto done;
        }
        if (EVP_DigestVerifyFinal(ctx, sig.data, sig.len) != 1) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "oidc: JWT signature verification failed");
            goto done;
        }

        ok = NGX_OK;

done:
        if (ctx) EVP_MD_CTX_free(ctx);
        if (pkey) EVP_PKEY_free(pkey);
        if (rsa) RSA_free(rsa);
        if (bn_n) BN_free(bn_n);
        if (bn_e) BN_free(bn_e);

        if (ok != NGX_OK) {
            return NGX_ERROR;
        }
    }

    /* validate claims: exp, iss, aud, nonce */
    if (ngx_http_oidc_json_get_string(&payload,
            &(ngx_str_t) ngx_string("exp"), &exp_s) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, log, 0, "oidc: JWT missing exp");
        return NGX_ERROR;
    }
    exp = ngx_atotm(exp_s.data, exp_s.len);
    now = ngx_time();
    if (now >= exp) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "oidc: JWT expired");
        return NGX_ERROR;
    }

    if (ngx_http_oidc_json_get_string(&payload,
            &(ngx_str_t) ngx_string("iss"), &iss_s) != NGX_OK
        || iss_s.len != issuer->len
        || ngx_strncmp(iss_s.data, issuer->data, issuer->len) != 0)
    {
        ngx_log_error(NGX_LOG_ERR, log, 0, "oidc: JWT issuer mismatch");
        return NGX_ERROR;
    }

    aud_is_array = ngx_http_oidc_json_array_contains(&payload,
        &(ngx_str_t) ngx_string("aud"), client_id) == NGX_OK;
    if (!aud_is_array && (ngx_http_oidc_json_get_string(&payload,
            &(ngx_str_t) ngx_string("aud"), &aud_s) != NGX_OK
        || aud_s.len != client_id->len
        || ngx_strncmp(aud_s.data, client_id->data, client_id->len) != 0))
    {
        ngx_log_error(NGX_LOG_ERR, log, 0, "oidc: JWT audience mismatch");
        return NGX_ERROR;
    }
    if (aud_is_array && (ngx_http_oidc_json_get_string(&payload,
            &(ngx_str_t) ngx_string("azp"), &azp_s) != NGX_OK
        || azp_s.len != client_id->len
        || ngx_strncmp(azp_s.data, client_id->data, client_id->len) != 0))
    {
        ngx_log_error(NGX_LOG_ERR, log, 0, "oidc: JWT authorized party mismatch");
        return NGX_ERROR;
    }

    if (max_age > 0) {
        if (ngx_http_oidc_json_get_string(&payload,
                &(ngx_str_t) ngx_string("auth_time"), &auth_time_s) != NGX_OK
            || now - ngx_atotm(auth_time_s.data, auth_time_s.len) > max_age)
        {
            ngx_log_error(NGX_LOG_ERR, log, 0, "oidc: JWT authentication too old");
            return NGX_ERROR;
        }
    }

    if (nonce != NULL && nonce->len > 0) {
        if (ngx_http_oidc_json_get_string(&payload,
                &(ngx_str_t) ngx_string("nonce"), &nonce_s) != NGX_OK
            || nonce_s.len != nonce->len
            || ngx_strncmp(nonce_s.data, nonce->data, nonce->len) != 0)
        {
            ngx_log_error(NGX_LOG_ERR, log, 0, "oidc: JWT nonce mismatch");
            return NGX_ERROR;
        }
    }

    /* copy claims into request pool */
    slen = payload.len;
    sp = ngx_pnalloc(ngx_cycle->pool, slen + 1);
    if (sp == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(sp, payload.data, slen);
    sp[slen] = '\0';
    claims_out->data = sp;
    claims_out->len = slen;

    return NGX_OK;
}
