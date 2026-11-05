<?php
// Client IP resolution. PANAG identifies users by their source IP, so this must be correct.

const DEV_IP_COOKIE = 'panag_dev_ip';

/**
 * Pure resolver (unit-tested).
 *
 * - Dev mode only: an IP from the dev cookie (or the configured default) overrides everything.
 * - If REMOTE_ADDR is a trusted proxy, walk X-Forwarded-For from right to left and return the
 *   first address that is not itself a trusted proxy.
 * - Otherwise REMOTE_ADDR.
 */
function resolve_client_ip(array $server, array $cookies, array $trustedProxies, bool $devMode, string $devDefaultIp = ''): string
{
    $remote = (string)($server['REMOTE_ADDR'] ?? '');

    if ($devMode) {
        $devIp = (string)($cookies[DEV_IP_COOKIE] ?? '');
        if ($devIp === '' || !filter_var($devIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $devIp = $devDefaultIp;
        }
        if ($devIp !== '' && filter_var($devIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            // Requests carrying X-Forwarded-For from a trusted proxy (e.g. Playwright) still win.
            $forwarded = $server['HTTP_X_FORWARDED_FOR'] ?? '';
            if ($forwarded === '' || !ip_in_any_cidr($remote, $trustedProxies)) {
                return $devIp;
            }
        }
    }

    if ($remote !== '' && !empty($trustedProxies) && ip_in_any_cidr($remote, $trustedProxies)) {
        $forwarded = (string)($server['HTTP_X_FORWARDED_FOR'] ?? '');
        if ($forwarded !== '') {
            $hops = array_reverse(array_map('trim', explode(',', $forwarded)));
            foreach ($hops as $hop) {
                if (!filter_var($hop, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                    break; // malformed chain – stop trusting it
                }
                if (!ip_in_any_cidr($hop, $trustedProxies)) {
                    return $hop;
                }
            }
        }
    }

    return $remote;
}

function ip_in_any_cidr(string $ip, array $cidrs): bool
{
    foreach ($cidrs as $cidr) {
        if (ip_in_cidr($ip, (string)$cidr)) {
            return true;
        }
    }
    return false;
}

function is_dev_mode(): bool
{
    return defined('APP_ENV') && APP_ENV === 'dev';
}

function client_ip(): string
{
    static $cached = null;
    if ($cached === null) {
        $cached = resolve_client_ip($_SERVER, $_COOKIE, TRUSTED_PROXIES, is_dev_mode(), (string)DEV_DEFAULT_IP);
    }
    return $cached;
}

function ip_in_cidr(string $ip, string $cidr): bool
{
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return false;
    }
    if (strpos($cidr, '/') === false) {
        return $ip === $cidr;
    }
    [$subnet, $mask] = explode('/', $cidr, 2);
    if (!filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) || !ctype_digit($mask)) {
        return false;
    }
    $mask = (int)$mask;
    if ($mask < 0 || $mask > 32) {
        return false;
    }
    $ipBin = inet_pton($ip);
    $subnetBin = inet_pton($subnet);
    if ($ipBin === false || $subnetBin === false) {
        return false;
    }

    // Build binary mask without integer bit shifts to avoid float conversions.
    $fullBytes = intdiv($mask, 8);
    $remainingBits = $mask % 8;
    $maskBin = str_repeat("\xFF", $fullBytes);
    if ($remainingBits > 0) {
        $maskBin .= chr((0xFF << (8 - $remainingBits)) & 0xFF);
    }
    $maskBin = str_pad($maskBin, 4, "\x00");

    return ($ipBin & $maskBin) === ($subnetBin & $maskBin);
}
