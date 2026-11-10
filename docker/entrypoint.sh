#!/bin/sh
# PANAG container entrypoint: prepare /data, initialise the database, then exec the CMD.
set -eu

DATA_DIR="${DATA_DIR:-/data}"
export DATA_DIR
export APACHE_MAX_WORKERS="${APACHE_MAX_WORKERS:-5}"

as_app() {
    if [ "$(id -u)" != "0" ]; then
        "$@"
    elif command -v su-exec >/dev/null 2>&1; then
        su-exec apache:apache "$@"
    else
        # Debian image (32-bit ARM): setpriv from util-linux instead of su-exec.
        setpriv --reuid=apache --regid=apache --init-groups -- "$@"
    fi
}

mkdir -p "$DATA_DIR"
if [ "$(id -u)" = "0" ]; then
    # RouterOS/Docker mounts are usually root-owned; Apache children run as "apache".
    chown apache:apache "$DATA_DIR"
    find "$DATA_DIR" -maxdepth 1 -name 'panag.sqlite*' -exec chown apache:apache {} +
fi

if [ "${APP_ENV:-production}" = "dev" ]; then
    echo "WARNING: APP_ENV=dev – client IP override is enabled. Never use this in production." >&2
fi

if [ "${1:-}" = "httpd" ]; then
    as_app php /app/bin/migrate.php
    as_app php /app/bin/config-check.php
    if [ "${SEED_DEMO:-0}" = "1" ]; then
        as_app php /app/bin/seed-demo.php --if-empty
    fi
    echo "PANAG $(cat /app/VERSION 2>/dev/null || echo dev) listening on :8080 (data: $DATA_DIR)"
fi

exec "$@"
