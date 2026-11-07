#!/usr/bin/env bash
# shellcheck disable=SC2119,SC2120  # commands take optional pass-through args; calling them without is intended
# PANAG developer entry point – everything runs in containers (Podman by default, Docker as fallback).
# No PHP, Node or npm needed on the host.
#
#   ./run.sh help
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

IMAGE="${PANAG_IMAGE:-localhost/panag:dev}"
TOOLS_IMAGE="localhost/panag-tools:dev"
DEV_PROJECT="panag"
E2E_PROJECT="panag-e2e"
DEV_PORT="${PANAG_PORT:-8080}"
E2E_PORT="${PANAG_E2E_PORT:-18080}"
VERSION="$(tr -d '[:space:]' < VERSION)"
DEMO_SECRET="JBSWY3DPEHPK3PXP"
export PANAG_IMAGE="$IMAGE"
export PODMAN_COMPOSE_WARNING_LOGS=false  # silence the "external compose provider" banner

# --- helpers -------------------------------------------------------------------------------------

info() { printf '\033[1;34m==>\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[1;33mWARN:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

detect_engine() {
    if [ -n "${CONTAINER_ENGINE:-}" ]; then
        ENGINE="$CONTAINER_ENGINE"
    elif command -v podman >/dev/null 2>&1; then
        ENGINE=podman
    elif command -v docker >/dev/null 2>&1; then
        ENGINE=docker
    else
        die "Neither podman nor docker found. Install Podman: https://podman.io"
    fi
    command -v "$ENGINE" >/dev/null 2>&1 || die "$ENGINE not found"

    if [ "$ENGINE" = podman ] && [ "$(uname -s)" = Darwin ]; then
        if ! podman info >/dev/null 2>&1; then
            info "Starting podman machine..."
            podman machine start >/dev/null || die "Could not start podman machine (podman machine init?)"
        fi
    fi
}

compose() {
    # compose <project> <files...> -- <args...>
    local project="$1"; shift
    local files=()
    while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do files+=(-f "$1"); shift; done
    [ "${1:-}" = "--" ] && shift
    "$ENGINE" compose -p "$project" ${files[@]+"${files[@]}"} "$@"
}

dev_compose() { compose "$DEV_PROJECT" compose.yml compose.dev.yml compose.live.yml -- "$@"; }
e2e_compose() { PANAG_PORT="$E2E_PORT" PANAG_BIND=127.0.0.1 MOCK_PORT="${PANAG_E2E_MOCK_PORT:-18081}" PANAG_SUBNET="${PANAG_E2E_SUBNET:-172.30.98.0/24}" compose "$E2E_PROJECT" compose.yml compose.dev.yml -- "$@"; }

build_flags() {
    # Podman defaults to OCI format, which drops HEALTHCHECK; RouterOS also expects docker archives.
    if [ "$ENGINE" = podman ]; then echo "--format docker"; fi
}

native_platform() {
    local arch
    if [ "$ENGINE" = podman ]; then
        arch="$(podman info --format '{{.Host.Arch}}')"
    else
        arch="$(docker version --format '{{.Server.Arch}}')"
    fi
    echo "linux/$arch"
}

build_image() {
    info "Building $IMAGE"
    # Explicit platform: a previous cross-arch build may have re-tagged the base image to another architecture.
    # shellcheck disable=SC2046
    "$ENGINE" build $(build_flags) --platform "$(native_platform)" --target runtime -t "$IMAGE" .
}

build_tools() {
    if [ "${PANAG_REBUILD_TOOLS:-0}" = 1 ] || ! "$ENGINE" image inspect "$TOOLS_IMAGE" >/dev/null 2>&1; then
        info "Building $TOOLS_IMAGE"
        # shellcheck disable=SC2046
        "$ENGINE" build $(build_flags) --target dev -t "$TOOLS_IMAGE" .
    fi
}

tools_run() {
    build_tools
    local tty=()
    [ -t 0 ] && [ -t 1 ] && tty=(-it)
    "$ENGINE" run --rm ${tty[@]+"${tty[@]}"} -v "$ROOT:/work" -w /work "$TOOLS_IMAGE" "$@"
}

ensure_vendor() {
    if [ ! -f vendor/autoload.php ] || [ composer.json -nt vendor/autoload.php ]; then
        info "Installing PHP dev dependencies (composer)"
        tools_run composer install --no-interaction --no-progress --quiet
    fi
}

wait_for_http() {
    local url="$1" tries="${2:-60}"
    for _ in $(seq 1 "$tries"); do
        if curl -fsS -o /dev/null "$url" 2>/dev/null; then return 0; fi
        sleep 1
    done
    return 1
}

check_clock() {
    # TOTP needs a correct clock; podman machines on macOS sometimes drift after sleep.
    local host container skew
    host="$(date -u +%s)"
    container="$("$ENGINE" run --rm "$IMAGE" date -u +%s 2>/dev/null || echo "$host")"
    skew=$(( host > container ? host - container : container - host ))
    if [ "$skew" -gt 20 ]; then
        warn "Container clock is off by ${skew}s – OTP logins from your phone will fail."
        warn "Fix: podman machine ssh 'sudo chronyc makestep'   (or restart the podman machine)"
    fi
}

arch_platform() {
    case "$1" in
        amd64) echo linux/amd64 ;;
        arm64) echo linux/arm64 ;;
        armv7|arm) echo linux/arm/v7 ;;
        *) die "Unknown architecture '$1' (use amd64, arm64 or armv7)" ;;
    esac
}

# --- commands ------------------------------------------------------------------------------------

cmd_up() {
    build_image
    check_clock
    info "Starting app + mock RouterOS"
    PANAG_BIND=127.0.0.1 dev_compose up -d --force-recreate app mock-routeros
    if wait_for_http "http://127.0.0.1:$DEV_PORT/healthz.php" 60; then
        info "PANAG is running: http://localhost:$DEV_PORT"
        info "You act as 127.0.0.1 (admin 'Local Tester'). OTP code: ./run.sh otp"
        info "Mock RouterOS: http://127.0.0.1:${MOCK_PORT:-8081}/_mock/state"
    else
        dev_compose logs --tail 50 app
        die "App did not become healthy"
    fi
}

cmd_down() { dev_compose down; }

cmd_reset() {
    info "Removing dev containers and data volume"
    dev_compose down -v
    cmd_up
}

cmd_logs() { dev_compose logs -f "${@:-app}"; }

cmd_otp() {
    local secret="${1:-$DEMO_SECRET}"
    if dev_compose ps --status running app 2>/dev/null | grep -q app; then
        dev_compose exec -T app php bin/otp.php "$secret"
    else
        "$ENGINE" run --rm --entrypoint php "$IMAGE" /app/bin/otp.php "$secret"
    fi
}

cmd_shell() {
    local svc="${1:-app}"
    if [ "$svc" = tools ]; then
        tools_run sh
    else
        dev_compose exec "$svc" sh
    fi
}

cmd_lint() {
    info "php -l"
    tools_run sh -c 'find public src bin dev tests -name "*.php" -not -path "*/vendor/*" -print0 | xargs -0 -n1 php -l >/dev/null'
    info "shellcheck"
    tools_run shellcheck run.sh docker/entrypoint.sh
    ensure_vendor
    info "phpstan"
    tools_run php -d memory_limit=512M vendor/bin/phpstan analyse --no-progress
}

cmd_unit() {
    ensure_vendor
    info "phpunit"
    tools_run php vendor/bin/phpunit "$@"
}

cmd_e2e() {
    build_image
    info "Starting fresh E2E stack ($E2E_PROJECT)"
    e2e_compose down -v --remove-orphans >/dev/null 2>&1 || true
    e2e_compose up -d app mock-routeros
    local rc=0
    e2e_compose run --rm playwright "npm ci --no-audit --no-fund --loglevel=error && npx playwright test $*" || rc=$?
    if [ "$rc" -ne 0 ]; then
        e2e_compose logs --tail 80 app mock-routeros || true
    fi
    if [ "${PANAG_KEEP_E2E:-0}" != 1 ]; then
        e2e_compose down -v >/dev/null 2>&1 || true
    fi
    [ "$rc" -eq 0 ] && info "E2E passed (report: playwright-report/index.html)"
    return "$rc"
}

cmd_test() {
    cmd_lint
    cmd_unit
    cmd_e2e
}

cmd_report() {
    [ -f playwright-report/index.html ] || die "No report yet – run ./run.sh e2e first"
    echo "$ROOT/playwright-report/index.html"
    if command -v open >/dev/null 2>&1; then open playwright-report/index.html || true; fi
}

cmd_npm() {
    local tty=()
    [ -t 0 ] && [ -t 1 ] && tty=(-it)
    "$ENGINE" run --rm ${tty[@]+"${tty[@]}"} -v "$ROOT:/work" -v "${E2E_PROJECT}_node-modules:/work/node_modules" -w /work \
        mcr.microsoft.com/playwright:v1.57.0-noble npm "$@"
}

cmd_composer() { tools_run composer "$@"; }

cmd_build() {
    local arch="${1:-}"
    if [ -z "$arch" ]; then
        build_image
        return
    fi
    local platform tag
    platform="$(arch_platform "$arch")"
    tag="localhost/panag:${VERSION}-${arch}"
    info "Building $tag for $platform"
    if [ "$ENGINE" = podman ]; then
        if [ "$platform" != "$(native_platform)" ] && ! podman run --rm --platform "$platform" docker.io/library/busybox:stable true >/dev/null 2>&1; then
            warn "This podman machine cannot run $platform binaries (no QEMU binfmt; arm/v7 is not possible on Apple Silicon)."
            die "Use the image built by CI (ghcr.io/muqiuq/panag or the release .tar), or build on a Linux host with qemu-user-static."
        fi
        podman build --format docker --platform "$platform" --target runtime -t "$tag" .
    else
        docker buildx build --platform "$platform" --target runtime -t "$tag" --load .
    fi
    "$ENGINE" image inspect "$tag" --format '{{.Size}}' | awk '{printf "Image size: %.1f MB\n", $1/1024/1024}'
}

cmd_export() {
    local arch="${1:-}"
    [ -n "$arch" ] || die "Usage: ./run.sh export <arm64|armv7|amd64>"
    cmd_build "$arch"
    local tag="localhost/panag:${VERSION}-${arch}"
    mkdir -p dist
    local out="dist/panag-${VERSION}-${arch}.tar"
    info "Saving $out (docker-archive, for /container add file=...)"
    if [ "$ENGINE" = podman ]; then
        podman save --format docker-archive -o "$out" "$tag"
    else
        docker save -o "$out" "$tag"
    fi
    ls -lh "$out"
}

cmd_help() {
    cat <<'EOF'
PANAG dev tool – everything runs in containers.

  ./run.sh up              Build image, start app + mock RouterOS → http://localhost:8080
  ./run.sh down            Stop the dev stack
  ./run.sh reset           Delete dev data, start fresh with demo data
  ./run.sh logs [svc]      Follow logs (app | mock-routeros)
  ./run.sh otp [secret]    Current TOTP code (demo users share one secret)
  ./run.sh shell [svc]     Shell in a container (app | mock-routeros | tools)

  ./run.sh test            lint + unit + e2e
  ./run.sh lint            php -l, shellcheck, phpstan
  ./run.sh unit [args]     PHPUnit (unit + integration against the mock router)
  ./run.sh e2e [args]      Playwright against a fresh stack (args go to `playwright test`)
  ./run.sh report          Open the last Playwright report

  ./run.sh npm <args>      npm in the Playwright container
  ./run.sh composer <args> composer in the tools container
  ./run.sh build [arch]    Build the runtime image (arch: amd64 | arm64 | armv7)
  ./run.sh export <arch>   Build and save dist/panag-<version>-<arch>.tar for RouterOS

Environment: CONTAINER_ENGINE=docker|podman, PANAG_PORT (8080), MOCK_PORT (8081),
             PANAG_KEEP_E2E=1 keeps the E2E stack running, PANAG_REBUILD_TOOLS=1.
EOF
}

main() {
    local cmd="${1:-help}"
    [ "$#" -gt 0 ] && shift
    case "$cmd" in
        help|-h|--help) cmd_help; return ;;
    esac
    detect_engine
    case "$cmd" in
        up|down|reset|logs|otp|shell|lint|unit|e2e|test|report|npm|composer|build|export) "cmd_$cmd" "$@" ;;
        *) cmd_help; die "Unknown command: $cmd" ;;
    esac
}

main "$@"
