# Build stage: compile nginx 1.31.3 with the OIDC module
FROM debian:bookworm-slim AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libssl-dev \
        libjansson-dev \
        libsqlite3-dev \
        libpcre3-dev \
        zlib1g-dev \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

ARG NGINX_VERSION=1.31.3

WORKDIR /build

RUN curl -sO http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz \
    && tar xzf nginx-${NGINX_VERSION}.tar.gz

COPY src /build/ngx-oidc-module/src
COPY config /build/ngx-oidc-module/config

WORKDIR /build/nginx-${NGINX_VERSION}

RUN ./configure \
        --prefix=/usr/local/nginx \
        --with-http_ssl_module \
        --with-http_v2_module \
        --with-cc-opt="-O2" \
        --add-dynamic-module=/build/ngx-oidc-module \
    && make -j"$(nproc)" \
    && make install

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 \
        libjansson4 \
        libsqlite3-0 \
        libpcre3 \
        zlib1g \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /usr/local/nginx /usr/local/nginx
COPY --from=build /usr/local/nginx/modules/ngx_http_oidc_module.so \
     /usr/local/nginx/modules/ngx_http_oidc_module.so

COPY example/nginx.conf /usr/local/nginx/conf/nginx.conf

EXPOSE 80 443

CMD ["/usr/local/nginx/sbin/nginx", "-g", "daemon off;"]
