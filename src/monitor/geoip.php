<?php
// GeoIP: country and network operator (ASN) of public IPs from local MMDB files – DB-IP Lite (CC BY 4.0,
// "IP Geolocation by DB-IP", https://db-ip.com) or MaxMind GeoLite2. No online lookups.

use MaxMind\Db\Reader;

const GEOIP_ATTRIBUTION = 'IP Geolocation by DB-IP (https://db-ip.com)';

interface GeoLookup
{
    /**
     * @return array{country: ?string, asn: ?int, asn_org: ?string, available: bool}|null null = not a public
     *         address (private, CGNAT, loopback …). available false = no country database: the location rules
     *         must not run (an unknown country would otherwise alert for every connection).
     */
    public function lookup(string $ip): ?array;
}

final class MmdbGeoLookup implements GeoLookup
{
    private ?Reader $country = null;
    private ?Reader $asn = null;
    private bool $opened = false;

    public function __construct(private string $countryPath, private string $asnPath)
    {
    }

    private function open(): void
    {
        if ($this->opened) {
            return;
        }
        $this->opened = true;
        $this->country = geoip_open_reader($this->countryPath);
        $this->asn = geoip_open_reader($this->asnPath);
    }

    public function lookup(string $ip): ?array
    {
        if (!geoip_is_public_ip($ip)) {
            return null;
        }
        $this->open();
        $country = null;
        $asn = null;
        $org = null;
        try {
            $rec = $this->country ? $this->country->get($ip) : null;
            $country = $rec['country']['iso_code'] ?? $rec['registered_country']['iso_code'] ?? null;
        } catch (Throwable $e) {
            // invalid lookup (e.g. IPv6 in an IPv4-only database) = unknown
        }
        try {
            $rec = $this->asn ? $this->asn->get($ip) : null;
            $asn = isset($rec['autonomous_system_number']) ? (int)$rec['autonomous_system_number'] : null;
            $org = $rec['autonomous_system_organization'] ?? null;
        } catch (Throwable $e) {
            // unknown
        }
        return [
            'country' => is_string($country) && preg_match('/^[A-Za-z]{2}$/', $country) ? strtoupper($country) : null,
            'asn' => $asn,
            'asn_org' => is_string($org) ? mb_substr_safe($org, 80) : null,
            'available' => $this->country !== null,
        ];
    }
}

/**
 * Cut to $length characters without breaking UTF-8 (the runtime image has no mbstring) and drop control
 * characters. Invalid UTF-8 is reduced to printable ASCII, so json_encode() never fails on it.
 */
function mb_substr_safe(string $value, int $length): string
{
    if (preg_match('//u', $value) !== 1) {
        $value = (string)preg_replace('/[^\x20-\x7E]/', '', $value);
    }
    $value = (string)preg_replace('/[\x00-\x1F\x7F]/u', '', $value);
    return preg_match('/^.{0,' . max(0, $length) . '}/us', $value, $m) ? $m[0] : '';
}

function geoip_open_reader(string $path): ?Reader
{
    if ($path === '' || !is_readable($path)) {
        return null;
    }
    try {
        return new Reader($path);
    } catch (Throwable $e) {
        error_log('PANAG GeoIP: cannot open ' . $path . ': ' . $e->getMessage());
        return null;
    }
}

function geoip(): GeoLookup
{
    if (!isset($GLOBALS['PANAG_GEOIP'])) {
        $GLOBALS['PANAG_GEOIP'] = new MmdbGeoLookup((string)GEOIP_COUNTRY_DB, (string)GEOIP_ASN_DB);
    }
    return $GLOBALS['PANAG_GEOIP'];
}

/** Replace the lookup (tests). */
function set_geoip(?GeoLookup $lookup): void
{
    if ($lookup === null) {
        unset($GLOBALS['PANAG_GEOIP']);
        return;
    }
    $GLOBALS['PANAG_GEOIP'] = $lookup;
}

/**
 * Not private, loopback, link-local, CGNAT, multicast or reserved. Documentation ranges (TEST-NET) count
 * as public so the dev/test GeoIP fixtures can use them.
 */
function geoip_is_public_ip(string $ip): bool
{
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return !ip_in_any_cidr($ip, ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/4', '240.0.0.0/4']);
    }
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        return false;
    }
    $bin = (string)inet_pton($ip);
    $first = ord($bin[0]);
    if ($bin === str_repeat("\0", 15) . "\1" || $bin === str_repeat("\0", 16)) {
        return false; // ::1, ::
    }
    if (($first & 0xFE) === 0xFC || $first === 0xFF) {
        return false; // fc00::/7 unique local, ff00::/8 multicast
    }
    if ($first === 0xFE && (ord($bin[1]) & 0xC0) === 0x80) {
        return false; // fe80::/10 link-local
    }
    if (substr($bin, 0, 12) === str_repeat("\0", 10) . "\xFF\xFF") {
        return geoip_is_public_ip((string)inet_ntop(substr($bin, 12))); // IPv4-mapped
    }
    return true;
}

/** @return list<array{kind: string, path: string, exists: bool, size: ?int, modified: ?int, type: ?string, built: ?int, error: ?string}> */
function geoip_status(): array
{
    $out = [];
    foreach (['country' => (string)GEOIP_COUNTRY_DB, 'asn' => (string)GEOIP_ASN_DB] as $kind => $path) {
        $row = ['kind' => $kind, 'path' => $path, 'exists' => is_file($path), 'size' => null, 'modified' => null, 'type' => null, 'built' => null, 'error' => null];
        if ($row['exists']) {
            $row['size'] = (int)filesize($path);
            $row['modified'] = (int)filemtime($path);
            try {
                $reader = new Reader($path);
                $meta = $reader->metadata();
                $row['type'] = (string)$meta->databaseType;
                $row['built'] = (int)$meta->buildEpoch;
                $reader->close();
            } catch (Throwable $e) {
                $row['error'] = $e->getMessage();
            }
        }
        $out[] = $row;
    }
    return $out;
}

/** Check a file is a readable MMDB of the expected kind. @return string|null error */
function geoip_validate_file(string $file, string $kind): ?string
{
    try {
        $reader = new Reader($file);
        $type = strtolower((string)$reader->metadata()->databaseType);
        $reader->close();
    } catch (Throwable $e) {
        return 'Not a valid MMDB file: ' . $e->getMessage();
    }
    if ($kind === 'asn' && strpos($type, 'asn') === false) {
        return 'Database type "' . $type . '" is not an ASN database.';
    }
    if ($kind === 'country' && strpos($type, 'asn') !== false) {
        return 'Database type "' . $type . '" is an ASN database, not a country database.';
    }
    return null;
}

/** Install a validated MMDB file atomically. @return string|null error */
function geoip_install_file(string $source, string $kind): ?string
{
    $target = $kind === 'asn' ? (string)GEOIP_ASN_DB : (string)GEOIP_COUNTRY_DB;
    if (($error = geoip_validate_file($source, $kind)) !== null) {
        return $error;
    }
    $dir = dirname($target);
    if (!is_dir($dir) && !@mkdir($dir, 0775, true)) {
        return 'Cannot create ' . $dir;
    }
    $tmp = $target . '.new';
    if (!@copy($source, $tmp) || !@rename($tmp, $target)) {
        @unlink($tmp);
        return 'Cannot write ' . $target;
    }
    @chmod($target, 0644);
    set_geoip(null); // reopen with the new file
    return null;
}

/** Download one DB-IP Lite database (current month, else previous). @return string|null error */
function geoip_download(string $kind, int $now): ?string
{
    $name = $kind === 'asn' ? 'asn' : 'country';
    $errors = [];
    foreach ([date('Y-m', $now), date('Y-m', strtotime('first day of last month', $now))] as $month) {
        $url = 'https://download.db-ip.com/free/dbip-' . $name . '-lite-' . $month . '.mmdb.gz';
        $gz = tempnam(sys_get_temp_dir(), 'geoip');
        $out = $gz . '.mmdb';
        $fh = fopen($gz, 'wb');
        $ch = curl_init($url);
        curl_setopt_array($ch, [CURLOPT_FILE => $fh, CURLOPT_FOLLOWLOCATION => true, CURLOPT_TIMEOUT => 120, CURLOPT_CONNECTTIMEOUT => 10, CURLOPT_FAILONERROR => true]);
        $ok = curl_exec($ch);
        $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);
        fclose($fh);
        if ($ok && $status === 200) {
            $in = gzopen($gz, 'rb');
            $dst = fopen($out, 'wb');
            if ($in && $dst) {
                while (!gzeof($in)) {
                    fwrite($dst, (string)gzread($in, 1 << 20));
                }
            }
            if ($in) {
                gzclose($in);
            }
            if ($dst) {
                fclose($dst);
            }
            $error = geoip_install_file($out, $kind);
            @unlink($gz);
            @unlink($out);
            if ($error === null) {
                return null;
            }
            $errors[] = $month . ': ' . $error;
            continue;
        }
        @unlink($gz);
        $errors[] = $month . ': HTTP ' . $status . ($curlError ? ' ' . $curlError : '');
    }
    return 'Download of the ' . $kind . ' database failed (' . implode('; ', $errors) . ')';
}

/** Monthly auto-update (GEOIP_AUTO_UPDATE); failed attempts are retried after 6 h. @return list<string> messages */
function geoip_maybe_update(int $now, bool $force = false): array
{
    if (!GEOIP_AUTO_UPDATE && !$force) {
        return [];
    }
    $updated = (int)monitor_state('geoip.updated_at', is_file((string)GEOIP_COUNTRY_DB) ? (int)filemtime((string)GEOIP_COUNTRY_DB) : 0);
    $attempt = (int)monitor_state('geoip.attempt_at', 0);
    if (!$force && ($now - $updated < 30 * 86400 || $now - $attempt < 6 * 3600)) {
        return [];
    }
    monitor_state_set('geoip.attempt_at', $now);
    $messages = [];
    foreach (['country', 'asn'] as $kind) {
        $error = geoip_download($kind, $now);
        $messages[] = $error ?? ('GeoIP ' . $kind . ' database updated.');
    }
    if (!array_filter($messages, fn($m) => strpos($m, 'failed') !== false)) {
        monitor_state_set('geoip.updated_at', $now);
    }
    monitor_state_set('geoip.last_result', $messages);
    return $messages;
}
