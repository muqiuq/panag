# PANAG container image – small Alpine + Apache (prefork) + mod_php.
# Targets: runtime (default, last stage) and dev (tooling: composer, phpunit, phpstan).
# Built for linux/amd64, linux/arm64 and linux/arm/v7 (MikroTik RouterOS container).

ARG ALPINE_VERSION=3.24

FROM docker.io/library/alpine:${ALPINE_VERSION} AS base
ARG PHP=php84
RUN apk add --no-cache \
        apache2 \
        su-exec \
        ${PHP} \
        ${PHP}-apache2 \
        ${PHP}-ctype \
        ${PHP}-curl \
        ${PHP}-opcache \
        ${PHP}-openssl \
        ${PHP}-pdo \
        ${PHP}-pdo_sqlite \
        ${PHP}-session \
    && ln -sf /usr/bin/${PHP} /usr/bin/php \
    && ln -sf /usr/lib/apache2/mod_${PHP}.so /usr/lib/apache2/mod_php.so \
    && ln -sf /etc/${PHP} /etc/php \
    && rm -rf /var/www/localhost /etc/apache2/conf.d/*

# --- Tooling image (used by run.sh / CI for unit tests, static analysis, composer) ---
FROM base AS dev
ARG PHP=php84
RUN apk add --no-cache \
        ${PHP}-dom ${PHP}-iconv ${PHP}-mbstring ${PHP}-phar ${PHP}-tokenizer \
        ${PHP}-xml ${PHP}-xmlwriter ${PHP}-simplexml ${PHP}-zip \
        git openssl shellcheck unzip
COPY --from=docker.io/library/composer:2 /usr/bin/composer /usr/bin/composer
WORKDIR /work

# --- Runtime image ---
FROM base AS runtime
COPY docker/httpd.conf /etc/apache2/httpd.conf
COPY docker/php.ini /etc/php/conf.d/zz-panag.ini
COPY docker/entrypoint.sh /usr/local/bin/panag-entrypoint
COPY VERSION /app/VERSION
COPY src /app/src
COPY bin /app/bin
COPY public /app/public
RUN chmod 0755 /usr/local/bin/panag-entrypoint \
    && mkdir -p /data \
    && chown apache:apache /data

ENV APP_ENV=production \
    DATA_DIR=/data \
    APACHE_MAX_WORKERS=5

WORKDIR /app
EXPOSE 8080
VOLUME ["/data"]
# Ignored by RouterOS, used by Docker/Podman.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz.php || exit 1

ENTRYPOINT ["panag-entrypoint"]
CMD ["httpd", "-D", "FOREGROUND", "-f", "/etc/apache2/httpd.conf"]
