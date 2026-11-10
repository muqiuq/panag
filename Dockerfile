# PANAG container image – Apache (prefork) + mod_php, small enough for a MikroTik RouterOS container.
# Targets: runtime (default, last stage) and dev (tooling: composer, phpunit, phpstan).
# Published for linux/amd64 and linux/arm64 (Alpine) and linux/arm/v7 (official php image, Debian bookworm).
# In RouterOS containers on 32-bit ARM (hEX S E60iUGS), Alpine armv7 and Debian trixie armel die at once with
# "exited with signal 4 (Illegal instruction)"; php:8.4-apache-bookworm was tested on the device and runs.
# Both runtime variants have the same paths, user and commands.

ARG ALPINE_VERSION=3.24
ARG PHP_DEBIAN_IMAGE=php:8.4-apache-bookworm
# Runtime OS, picked from the target platform (see below). RUNTIME_OS=alpine|debian overrides that, e.g. to
# test the Debian variant natively: PANAG_RUNTIME_OS=debian ./run.sh e2e
ARG RUNTIME_OS=""
ARG TARGETARCH
ARG TARGETVARIANT

FROM docker.io/library/alpine:${ALPINE_VERSION} AS base
ARG PHP=php84
RUN apk add --no-cache \
        apache2 \
        su-exec \
        ${PHP} \
        ${PHP}-apache2 \
        ${PHP}-bcmath \
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

# --- Runtime PHP libraries (MMDB reader, PHPMailer): pure PHP, so resolved once on the build platform ---
FROM --platform=$BUILDPLATFORM docker.io/library/composer:2 AS vendor
WORKDIR /app
COPY composer.json composer.lock ./
RUN composer install --no-dev --no-interaction --no-progress --no-scripts --classmap-authoritative --ignore-platform-reqs

# --- Runtime OS: Alpine (amd64, arm64) ---
FROM base AS os-alpine

# --- Runtime OS: 32-bit ARM – the official php image (Debian bookworm armhf), laid out like the Alpine image ---
FROM docker.io/library/${PHP_DEBIAN_IMAGE} AS debian-rootfs
RUN docker-php-ext-install bcmath \
    && mv "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini" \
    && apt-get update \
    && apt-get install -y --no-install-recommends busybox \
    && apt-get purge -y --auto-remove $PHPIZE_DEPS libc6-dev \
    && groupadd --system apache \
    && useradd --system --gid apache --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin apache \
    && ln -s /usr/sbin/apache2 /usr/local/bin/httpd \
    && ln -s /bin/busybox /usr/local/bin/wget \
    && mkdir -p /etc/php/conf.d \
    && ln -s /etc/php/conf.d/zz-panag.ini "$PHP_INI_DIR/conf.d/zz-panag.ini" \
    && ln -sf /etc/mime.types /etc/apache2/mime.types \
    # Only the Apache modules httpd.conf loads, under the Alpine paths.
    && cd /usr/lib/apache2/modules \
    && for m in *.so; do case "$m" in \
         mod_mpm_prefork.so|mod_authz_core.so|mod_dir.so|mod_mime.so|mod_headers.so|mod_setenvif.so|mod_alias.so|libphp.so) \
           ln -s "modules/$m" "/usr/lib/apache2/$m" ;; \
         *) rm "$m" ;; \
       esac; done \
    && ln -s modules/libphp.so /usr/lib/apache2/mod_php.so \
    # Not needed at runtime: PHP sources and headers, Perl (only for Apache's helper scripts), apt, gconv (PANAG
    # doesn't use iconv – the Alpine image has no iconv at all), PAM modules, package metadata.
    && rm -rf /usr/src/* /usr/local/include \
        /usr/bin/perl* /usr/share/perl* /usr/lib/*/perl* /usr/lib/*/libperl.so* \
        /usr/bin/apt* /usr/lib/apt /usr/lib/*/libapt-* /etc/apt /var/lib/apt /var/cache/apt \
        /usr/lib/*/gconv /usr/lib/*/security /var/lib/dpkg/info /var/cache/debconf /var/log/* \
        /usr/share/man /usr/share/info /usr/share/locale /usr/share/lintian /usr/share/zsh /usr/share/bash-completion

# Flattened, so the removed files don't stay in the base layer.
FROM scratch AS os-debian
COPY --from=debian-rootfs / /
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# --- Runtime OS per target platform ---
FROM os-alpine AS os-amd64
FROM os-alpine AS os-arm64
FROM os-alpine AS os-arm64v8
FROM os-debian AS os-armv7

# --- Runtime image ---
FROM os-${RUNTIME_OS:-${TARGETARCH}${TARGETVARIANT}} AS runtime
COPY docker/httpd.conf /etc/apache2/httpd.conf
COPY docker/php.ini /etc/php/conf.d/zz-panag.ini
COPY docker/entrypoint.sh /usr/local/bin/panag-entrypoint
COPY VERSION /app/VERSION
COPY --from=vendor /app/vendor /app/vendor
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
