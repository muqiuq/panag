<?php
// RouterOS v7 REST API client (https://help.mikrotik.com/docs/spaces/ROS/pages/47579162/REST+API).

final class RestRouterClient implements RouterClient
{
    private string $baseUrl;
    private string $username;
    private string $password;
    private string $pinnedFingerprint;
    private int $connectTimeout;
    private int $timeout;

    public function __construct(string $baseUrl, string $username, string $password, string $certFingerprint = '', int $connectTimeout = 5, int $timeout = 15)
    {
        $this->baseUrl = rtrim($baseUrl, '/');
        $this->username = $username;
        $this->password = $password;
        $this->pinnedFingerprint = self::normalizeFingerprint($certFingerprint);
        $this->connectTimeout = max(1, $connectTimeout);
        $this->timeout = max($this->connectTimeout, $timeout);
    }

    public function listAddressList(?string $list = null): array
    {
        $path = '/ip/firewall/address-list';
        if ($list !== null) {
            $path .= '?list=' . rawurlencode($list);
        }
        $resp = $this->request('GET', $path);
        if (!$resp['success'] || !is_array($resp['data'])) {
            return router_result(false, [], $resp['error'] ?? 'API error', $resp['status'], $resp['fingerprint']);
        }
        $entries = array_values(array_filter($resp['data'], 'is_array'));
        if ($list !== null) {
            // Filter again locally in case the router ignored the query parameter.
            $entries = array_values(array_filter($entries, static fn($e) => ($e['list'] ?? null) === $list));
        }
        return router_result(true, $entries, null, $resp['status'], $resp['fingerprint']);
    }

    public function addAddressListEntry(string $list, string $address, string $comment, string $timeout): array
    {
        // RouterOS REST creates a single record via PUT.
        return $this->request('PUT', '/ip/firewall/address-list', [
            'list' => $list,
            'address' => $address,
            'comment' => $comment,
            'timeout' => $timeout,
        ]);
    }

    public function updateAddressListEntry(string $id, array $fields): array
    {
        if (!self::isValidId($id)) {
            return router_result(false, null, 'Invalid entry id');
        }
        return $this->request('PATCH', '/ip/firewall/address-list/' . $id, $fields);
    }

    public function removeAddressListEntry(string $id): array
    {
        if (!self::isValidId($id)) {
            return router_result(false, null, 'Invalid entry id');
        }
        return $this->request('DELETE', '/ip/firewall/address-list/' . $id);
    }

    public function identity(): array
    {
        return $this->getSingle('/system/identity');
    }

    public function clock(): array
    {
        return $this->getSingle('/system/clock');
    }

    public function resource(): array
    {
        return $this->getSingle('/system/resource');
    }

    public function wireguardPeers(): array
    {
        $resp = $this->request('GET', '/interface/wireguard/peers');
        if (!$resp['success'] || !is_array($resp['data'])) {
            return router_result(false, [], $resp['error'] ?? 'API error', $resp['status'], $resp['fingerprint']);
        }
        return router_result(true, array_values(array_filter($resp['data'], 'is_array')), null, $resp['status'], $resp['fingerprint']);
    }

    /** RouterOS returns either an object or a one-element array for singleton menus. */
    private function getSingle(string $path): array
    {
        $resp = $this->request('GET', $path);
        if (!$resp['success'] || empty($resp['data']) || !is_array($resp['data'])) {
            return router_result(false, null, $resp['error'] ?? 'API error', $resp['status'], $resp['fingerprint']);
        }
        $data = $resp['data'];
        $row = array_is_list($data) ? ($data[0] ?? null) : $data;
        return router_result(is_array($row), is_array($row) ? $row : null, is_array($row) ? null : 'Empty response', $resp['status'], $resp['fingerprint']);
    }

    private static function isValidId(string $id): bool
    {
        return (bool)preg_match('/^\*[0-9A-Fa-f]+$/', $id);
    }

    private static function normalizeFingerprint(string $fp): string
    {
        $fp = trim($fp);
        return $fp === '' ? '' : strtoupper((string)preg_replace('/[^A-Fa-f0-9]/', '', $fp));
    }

    public function request(string $method, string $path, ?array $body = null): array
    {
        $url = $this->baseUrl . '/' . ltrim($path, '/');
        $isHttps = strncasecmp($url, 'https://', 8) === 0;

        $ch = $this->newHandle($url, $method);
        if ($isHttps) {
            // Always collect certificate info so fingerprints can be shown in errors.
            curl_setopt($ch, CURLOPT_CERTINFO, true);
            // With a pinned fingerprint, CA/hostname checks are replaced by the fingerprint check
            // (typical for RouterOS self-signed certificates); otherwise verify strictly.
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, $this->pinnedFingerprint === '' ? 2 : 0);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $this->pinnedFingerprint === '');
        }
        if ($body !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($body));
        }
        $resp = curl_exec($ch);
        $err = curl_error($ch);
        $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $certInfo = $isHttps ? curl_getinfo($ch, CURLINFO_CERTINFO) : null;
        unset($ch); // handles are freed automatically (curl_close is a no-op since PHP 8)

        $fingerprint = $isHttps ? self::extractFingerprint($certInfo) : null;
        $ok = $resp !== false && $err === '' && $status >= 200 && $status < 300;

        // Verify the pinned fingerprint *before* trusting any response data.
        if ($isHttps && $this->pinnedFingerprint !== '') {
            if ($fingerprint === null && $resp !== false) {
                return router_result(false, null, 'Could not read server certificate to verify fingerprint', $status, null);
            }
            if ($fingerprint !== null && self::normalizeFingerprint($fingerprint) !== $this->pinnedFingerprint) {
                return router_result(false, null, 'SSL certificate fingerprint mismatch. Expected ' . $this->pinnedFingerprint . ', got ' . $fingerprint, $status, $fingerprint);
            }
        }

        if ($isHttps && !$ok && $fingerprint === null) {
            // Re-probe without verification only to display the fingerprint to the admin.
            $fingerprint = $this->probeFingerprint($url);
        }

        if ($resp === false || $err !== '') {
            $msg = $err !== '' ? $err : 'unknown error';
            if ($fingerprint) {
                $msg .= ' (cert fingerprint: ' . $fingerprint . ')';
            }
            return router_result(false, null, $msg, $status ?: null, $fingerprint);
        }

        $data = $resp === '' ? null : json_decode((string)$resp, true);
        if (!$ok) {
            $detail = is_array($data) ? trim(($data['message'] ?? '') . (isset($data['detail']) ? ': ' . $data['detail'] : '')) : '';
            $msg = 'HTTP ' . $status . ($detail !== '' ? ' ' . $detail : '');
            if ($fingerprint) {
                $msg .= ' (cert fingerprint: ' . $fingerprint . ')';
            }
            return router_result(false, $data, $msg, $status, $fingerprint);
        }
        return router_result(true, $data, null, $status, $fingerprint);
    }

    /** @return \CurlHandle */
    private function newHandle(string $url, string $method)
    {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, strtoupper($method));
        curl_setopt($ch, CURLOPT_USERPWD, $this->username . ':' . $this->password);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $this->connectTimeout);
        curl_setopt($ch, CURLOPT_TIMEOUT, $this->timeout);
        return $ch;
    }

    private function probeFingerprint(string $url): ?string
    {
        $probe = $this->newHandle($url, 'HEAD');
        curl_setopt($probe, CURLOPT_NOBODY, true);
        curl_setopt($probe, CURLOPT_CERTINFO, true);
        curl_setopt($probe, CURLOPT_SSL_VERIFYHOST, 0);
        curl_setopt($probe, CURLOPT_SSL_VERIFYPEER, false); // capture even if untrusted – display only
        curl_setopt($probe, CURLOPT_TIMEOUT, min(5, $this->timeout));
        curl_exec($probe);
        $info = curl_getinfo($probe, CURLINFO_CERTINFO);
        unset($probe);
        return self::extractFingerprint($info);
    }

    private static function extractFingerprint($certInfo): ?string
    {
        if (!is_array($certInfo)) {
            return null;
        }
        foreach ($certInfo as $cert) {
            if (!empty($cert['Cert'])) {
                $fp = @openssl_x509_fingerprint($cert['Cert'], 'sha256');
                if ($fp !== false) {
                    return strtoupper($fp);
                }
            }
        }
        return null;
    }
}
