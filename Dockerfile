# PANAG container image – Apache (prefork) + mod_php, small enough for a MikroTik RouterOS container.
# Targets: runtime (default, last stage) and dev (tooling: composer, phpunit, phpstan).
# Published for linux/amd64 and linux/arm64 (Alpine) and linux/arm/v5 (Debian armel). 32-bit ARM routers can't
# run hard-float binaries in a container – Alpine's armv7 build dies with SIGILL there – and soft-float armel
# runs on every 32-bit ARM CPU. Both runtime variants have the same paths, user and commands.

ARG ALPINE_VERSION=3.24
ARG DEBIAN_VERSION=trixie
# Runtime OS, picked from the target platform (see the end of this file). RUNTIME_OS=alpine|debian overrides
# that, e.g. to run the Debian variant natively: PANAG_RUNTIME_OS=debian ./run.sh e2e
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

# --- Runtime OS: Debian armel (32-bit ARM), laid out like the Alpine image ---
FROM docker.io/library/debian:${DEBIAN_VERSION}-slim AS debian-rootfs
ARG PHP=8.4
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        apache2-bin \
        busybox \
        ca-certificates \
        libapache2-mod-php${PHP} \
        media-types \
        php${PHP}-bcmath \
        php${PHP}-cli \
        php${PHP}-curl \
        php${PHP}-opcache \
        php${PHP}-sqlite3 \
    && groupadd --system apache \
    && useradd --system --gid apache --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin apache \
    && ln -s /usr/sbin/apache2 /usr/local/bin/httpd \
    && ln -s /bin/busybox /usr/local/bin/wget \
    && mkdir -p /etc/apache2 /etc/php/conf.d \
    && ln -s /etc/mime.types /etc/apache2/mime.types \
    && for sapi in apache2 cli; do ln -s /etc/php/conf.d/zz-panag.ini /etc/php/${PHP}/$sapi/conf.d/zz-panag.ini; done \
    # Same PHP extensions as the Alpine image (tests run there). Without iconv, glibc's gconv modules can go too.
    && extra="calendar exif ffi fileinfo ftp gettext iconv phar posix shmop sockets sqlite3 sysvmsg sysvsem sysvshm tokenizer" \
    && phpdismod $extra \
    && for x in $extra; do rm /usr/lib/php/*/$x.so /etc/php/${PHP}/mods-available/$x.ini; done \
    # Only the Apache modules httpd.conf loads, under the Alpine paths.
    && cd /usr/lib/apache2/modules \
    && for m in *.so; do case "$m" in \
         mod_mpm_prefork.so|mod_authz_core.so|mod_dir.so|mod_mime.so|mod_headers.so|mod_setenvif.so|mod_alias.so|libphp${PHP}.so) \
           ln -s "modules/$m" "/usr/lib/apache2/$m" ;; \
         *) rm "$m" ;; \
       esac; done \
    && ln -s modules/libphp${PHP}.so /usr/lib/apache2/mod_php.so \
    # Not needed at runtime: Perl (only for Apache's helper scripts), apt, gconv, PAM modules, package metadata.
    && rm -rf /usr/bin/perl* /usr/share/perl* /usr/lib/*/perl* /usr/lib/*/libperl.so* \
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
# Not published: runs on ARMv7 Linux boards, but not in a RouterOS container.
FROM os-alpine AS os-armv7
FROM os-debian AS os-armv5

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
