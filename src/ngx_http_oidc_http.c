#include "ngx_http_oidc.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

typedef struct {
    ngx_str_t  scheme;
    ngx_str_t  host;
    ngx_uint_t port;
    ngx_uint_t default_port;
    ngx_str_t  path;   /* includes query */
} ngx_http_oidc_url_t;

static ngx_int_t ngx_http_oidc_parse_url(ngx_str_t *url,
    ngx_http_oidc_url_t *u);
static ngx_int_t ngx_http_oidc_connect(ngx_log_t *log,
    ngx_http_oidc_url_t *u, int *fd);
static ngx_int_t ngx_http_oidc_tls(ngx_log_t *log, int fd, ngx_str_t *host,
    ngx_str_t *trusted_ca, SSL **ssl_out);
static ngx_int_t ngx_http_oidc_send_recv(ngx_pool_t *pool, ngx_log_t *log,
    SSL *ssl, int fd, ngx_str_t *request, ngx_http_oidc_http_resp_t *resp);

static ngx_int_t
ngx_http_oidc_parse_url(ngx_str_t *url, ngx_http_oidc_url_t *u)
{
    u_char  *p, *host_start, *path_start;

    ngx_memzero(u, sizeof(*u));

    if (url->len >= 8 && ngx_strncasecmp(url->data, (u_char *) "https://", 8) == 0) {
        u->scheme.data = (u_char *) "https";
        u->scheme.len = 5;
        u->port = 443;
        u->default_port = 443;
        host_start = url->data + 8;
    } else if (url->len >= 7
               && ngx_strncasecmp(url->data, (u_char *) "http://", 7) == 0)
    {
        u->scheme.data = (u_char *) "http";
        u->scheme.len = 4;
        u->port = 80;
        u->default_port = 80;
        host_start = url->data + 7;
    } else {
        return NGX_ERROR;
    }

    path_start = ngx_strlchr(host_start, url->data + url->len, '/');
    if (path_start == NULL) {
        path_start = url->data + url->len;
    }

    u->host.data = host_start;
    u->host.len = path_start - host_start;

    /* strip port if present */
    p = ngx_strlchr(host_start, path_start, ':');
    if (p != NULL) {
        u->host.len = p - host_start;
        u->port = (ngx_uint_t) ngx_atoi(p + 1, path_start - p - 1);
        if (u->port == (ngx_uint_t) NGX_ERROR) {
            return NGX_ERROR;
        }
    }

    if (path_start < url->data + url->len) {
        u->path.data = path_start;
        u->path.len = url->data + url->len - path_start;
    } else {
        u->path.data = (u_char *) "/";
        u->path.len = 1;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_oidc_connect(ngx_log_t *log, ngx_http_oidc_url_t *u, int *fd)
{
    struct addrinfo  hints, *res, *rp;
    char             host[256], port[16];
    int              s = -1, rc;
    u_char          *pp;

    if (u->host.len >= sizeof(host)) {
        return NGX_ERROR;
    }
    ngx_memcpy(host, u->host.data, u->host.len);
    host[u->host.len] = '\0';

    pp = ngx_sprintf((u_char *) port, "%d", (int) u->port);
    *pp = '\0';

    ngx_memzero(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    rc = getaddrinfo(host, port, &hints, &res);
    if (rc != 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "oidc: getaddrinfo failed for %s:%s (%s)",
                      host, port, gai_strerror(rc));
        return NGX_ERROR;
    }
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (s < 0) {
            continue;
        }
        if (connect(s, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;
        }
        close(s);
        s = -1;
    }

    freeaddrinfo(res);

    if (s < 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "oidc: connect failed to %s", host);
        return NGX_ERROR;
    }

    *fd = s;
    return NGX_OK;
}

static ngx_int_t
ngx_http_oidc_tls(ngx_log_t *log, int fd, ngx_str_t *host,
    ngx_str_t *trusted_ca, SSL **ssl_out)
{
    SSL_CTX  *ctx = NULL;
    SSL     *ssl = NULL;
    ngx_int_t  rc = NGX_ERROR;

    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        goto done;
    }

    if (trusted_ca != NULL && trusted_ca->len > 0) {
        char  ca[NGX_MAX_PATH];
        if (trusted_ca->len >= NGX_MAX_PATH) {
            goto done;
        }
        ngx_memcpy(ca, trusted_ca->data, trusted_ca->len);
        ca[trusted_ca->len] = '\0';

        if (SSL_CTX_load_verify_locations(ctx, ca, NULL) != 1) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "oidc: failed to load CA bundle %s", ca);
            goto done;
        }
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    } else {
        /* default system paths */
        SSL_CTX_set_default_verify_paths(ctx);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    }

    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        goto done;
    }

    if (host->len < 256) {
        char  h[256];
        ngx_memcpy(h, host->data, host->len);
        h[host->len] = '\0';
        SSL_set_tlsext_host_name(ssl, h);
        SSL_set1_host(ssl, h);
    }

    SSL_set_fd(ssl, fd);

    if (SSL_connect(ssl) != 1) {
        unsigned long  e = ERR_get_error();
        char  ebuf[256];
        ERR_error_string_n(e, ebuf, sizeof(ebuf));
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "oidc: TLS handshake failed: %s (verify=%ld)",
                      ebuf, SSL_get_verify_result(ssl));
        goto done;
    }

    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "oidc: TLS certificate verification failed");
        goto done;
    }

    *ssl_out = ssl;
    rc = NGX_OK;

done:
    if (rc != NGX_OK && ssl) {
        SSL_free(ssl);
    }
    if (ctx) {
        SSL_CTX_free(ctx);
    }
    return rc;
}

static ngx_int_t
ngx_http_oidc_send_recv(ngx_pool_t *pool, ngx_log_t *log, SSL *ssl, int fd,
    ngx_str_t *request, ngx_http_oidc_http_resp_t *resp)
{
    u_char   buf[16384];
    ssize_t  n;
    ngx_int_t rc = NGX_ERROR;
    struct pollfd pfd;
    int      ret;
    size_t   total = 0, cap = 0;
    u_char  *body = NULL;
    u_char  *sep;

    /* send */
    if (SSL_write(ssl, request->data, request->len) != (int) request->len) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "oidc: SSL_write failed");
        goto done;
    }

    /* receive with timeout, accumulating into a growing buffer */
    for (;;) {
        pfd.fd = fd;
        pfd.events = POLLIN;
        ret = poll(&pfd, 1, 10000); /* 10s */
        if (ret <= 0) {
            ngx_log_error(NGX_LOG_ERR, log, 0, "oidc: recv timeout");
            goto done;
        }

        n = SSL_read(ssl, buf, sizeof(buf));
        if (n <= 0) {
            break;
        }

        if (total + (size_t) n > cap) {
            size_t  ncap = cap ? cap * 2 : 16384;
            u_char *nb;
            while (ncap < total + (size_t) n) {
                ncap *= 2;
            }
            nb = ngx_pnalloc(pool, ncap);
            if (nb == NULL) {
                goto done;
            }
            if (body && total > 0) {
                ngx_memcpy(nb, body, total);
            }
            body = nb;
            cap = ncap;
        }
        ngx_memcpy(body + total, buf, n);
        total += n;
    }

    if (body == NULL || total == 0) {
        goto done;
    }

    /* find header/body separator */
    sep = ngx_strnstr(body, (char *) "\r\n\r\n", total);
    if (sep == NULL) {
        goto done;
    }

    /* status code: "HTTP/1.1 200 OK" */
    {
        u_char  *sp = body;
        u_char  *sp_end = ngx_strlchr(sp, body + total, '\r');
        u_char  *s1;
        if (sp_end == NULL) {
            goto done;
        }
        s1 = ngx_strlchr(sp, sp_end, ' ');
        if (s1 == NULL) {
            goto done;
        }
        /* status code is exactly 3 digits after the first space */
        if (sp_end - s1 - 1 < 3) {
            goto done;
        }
        resp->status = (ngx_int_t) ngx_atoi(s1 + 1, 3);
        if (resp->status == (ngx_int_t) NGX_ERROR) {
            goto done;
        }
    }

    resp->body.data = sep + 4;
    resp->body.len = body + total - (sep + 4);

    rc = NGX_OK;

done:
    return rc;
}

ngx_int_t
ngx_http_oidc_http_get(ngx_pool_t *pool, ngx_log_t *log, ngx_str_t *url,
    ngx_str_t *trusted_ca, ngx_str_t *auth_header,
    ngx_http_oidc_http_resp_t *resp)
{
    ngx_http_oidc_url_t  u;
    int      fd = -1;
    SSL     *ssl = NULL;
    ngx_str_t  req;
    u_char  *p;
    size_t   len;
    ngx_int_t rc = NGX_ERROR;

    if (ngx_http_oidc_parse_url(url, &u) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "oidc: bad URL");
        return NGX_ERROR;
    }

    if (ngx_http_oidc_connect(log, &u, &fd) != NGX_OK) {
        return NGX_ERROR;
    }

    if (u.scheme.len != 5) { /* https only */
        ngx_log_error(NGX_LOG_ERR, log, 0, "oidc: only https URLs supported");
        goto done;
    }

    if (ngx_http_oidc_tls(log, fd, &u.host, trusted_ca, &ssl) != NGX_OK) {
        goto done;
    }

    len = 96 + u.host.len + 8 + u.path.len
          + (auth_header ? auth_header->len : 0);
    req.data = ngx_pnalloc(pool, len);
    if (req.data == NULL) {
        goto done;
    }
    p = req.data;
    p = ngx_cpymem(p, "GET ", 4);
    p = ngx_cpymem(p, u.path.data, u.path.len);
    p = ngx_cpymem(p, " HTTP/1.1\r\nHost: ", 17);
    p = ngx_cpymem(p, u.host.data, u.host.len);
    if (u.port != u.default_port) {
        p = ngx_sprintf(p, ":%ui", u.port);
    }
    p = ngx_cpymem(p, "\r\nAccept: application/json\r\n", 28);
    if (auth_header) {
        p = ngx_cpymem(p, "Authorization: ", 15);
        p = ngx_cpymem(p, auth_header->data, auth_header->len);
        p = ngx_cpymem(p, "\r\n", 2);
    }
    p = ngx_cpymem(p, "Connection: close\r\n\r\n", 21);
    req.len = p - req.data;

    rc = ngx_http_oidc_send_recv(pool, log, ssl, fd, &req, resp);

done:
    if (ssl) {
        SSL_free(ssl);
    }
    if (fd >= 0) {
        close(fd);
    }
    return rc;
}

ngx_int_t
ngx_http_oidc_http_post_form(ngx_pool_t *pool, ngx_log_t *log, ngx_str_t *url,
    ngx_str_t *trusted_ca, ngx_str_t *auth_header, ngx_str_t *body,
    ngx_http_oidc_http_resp_t *resp)
{
    ngx_http_oidc_url_t  u;
    int      fd = -1;
    SSL     *ssl = NULL;
    ngx_str_t  req;
    u_char  *p;
    size_t   len;
    ngx_int_t rc = NGX_ERROR;

    if (ngx_http_oidc_parse_url(url, &u) != NGX_OK) {
        return NGX_ERROR;
    }
    if (ngx_http_oidc_connect(log, &u, &fd) != NGX_OK) {
        return NGX_ERROR;
    }
    if (u.scheme.len != 5) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "oidc: only https URLs supported");
        goto done;
    }
    if (ngx_http_oidc_tls(log, fd, &u.host, trusted_ca, &ssl) != NGX_OK) {
        goto done;
    }

    len = 128 + u.host.len + 8 + u.path.len
          + (auth_header ? auth_header->len : 0) + body->len;
    req.data = ngx_pnalloc(pool, len);
    if (req.data == NULL) {
        goto done;
    }
    p = req.data;
    p = ngx_cpymem(p, "POST ", 5);
    p = ngx_cpymem(p, u.path.data, u.path.len);
    p = ngx_cpymem(p, " HTTP/1.1\r\nHost: ", 17);
    p = ngx_cpymem(p, u.host.data, u.host.len);
    if (u.port != u.default_port) {
        p = ngx_sprintf(p, ":%ui", u.port);
    }
    p = ngx_cpymem(p, "\r\nContent-Type: application/x-www-form-urlencoded\r\n",
                   sizeof("\r\nContent-Type: application/x-www-form-urlencoded\r\n") - 1);
    p = ngx_sprintf(p, "Content-Length: %uz\r\n", body->len);
    if (auth_header) {
        p = ngx_cpymem(p, "Authorization: ", 15);
        p = ngx_cpymem(p, auth_header->data, auth_header->len);
        p = ngx_cpymem(p, "\r\n", 2);
    }
    p = ngx_cpymem(p, "Connection: close\r\n\r\n", 21);
    p = ngx_cpymem(p, body->data, body->len);
    req.len = p - req.data;

    rc = ngx_http_oidc_send_recv(pool, log, ssl, fd, &req, resp);

done:
    if (ssl) {
        SSL_free(ssl);
    }
    if (fd >= 0) {
        close(fd);
    }
    return rc;
}
