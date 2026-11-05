<?php
// Fake RouterOS v7 REST API for development and tests.
// Run: php -S 0.0.0.0:8080 dev/mock-routeros/router.php
//
// Implements the subset PANAG uses:
//   GET/PUT            /rest/ip/firewall/address-list            (GET supports ?prop=value filters)
//   GET/PATCH/DELETE   /rest/ip/firewall/address-list/{.id}
//   GET                /rest/system/identity | /rest/system/clock | /rest/system/resource
//   GET                /rest/interface/wireguard/peers
// Test control (no auth):
//   POST /_mock/reset              clear state (address list, faults)
//   GET  /_mock/state              raw state incl. absolute expiry times
//   POST /_mock/fault              {"mode":"none|500|401|timeout","latency_ms":0}
//
// Behaviour mirrors RouterOS where it matters: Basic auth, ".id" values like "*1A", all values are strings,
// timeouts count down and expired dynamic entries disappear, duplicates are rejected with HTTP 400.
//
// Environment: MOCK_USERNAME (admin), MOCK_PASSWORD (mock), MOCK_STATE_FILE, MOCK_IDENTITY, MOCK_TIMEOUT_SECONDS (30)

$username = getenv('MOCK_USERNAME') ?: 'admin';
$password = getenv('MOCK_PASSWORD') ?: 'mock';
$stateFile = getenv('MOCK_STATE_FILE') ?: sys_get_temp_dir() . '/panag-mock-routeros.json';
$identity = getenv('MOCK_IDENTITY') ?: 'mock-router';

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$uri = $_SERVER['REQUEST_URI'] ?? '/';
$path = rawurldecode((string)parse_url($uri, PHP_URL_PATH));
parse_str((string)parse_url($uri, PHP_URL_QUERY), $query);

function respond(int $status, $body = null): void
{
    http_response_code($status);
    if ($body !== null) {
        header('Content-Type: application/json');
        echo json_encode($body, JSON_UNESCAPED_SLASHES);
    }
    exit;
}

function ros_error(int $status, string $message, ?string $detail = null): void
{
    $body = ['error' => $status, 'message' => $message];
    if ($detail !== null) {
        $body['detail'] = $detail;
    }
    respond($status, $body);
}

/** Parse RouterOS durations: "01:00:00", "1d2h3m4s", "1w", "90" (seconds). */
function parse_duration(string $value): ?int
{
    $value = trim($value);
    if (preg_match('/^(\d+):(\d{1,2}):(\d{1,2})$/', $value, $m)) {
        return (int)$m[1] * 3600 + (int)$m[2] * 60 + (int)$m[3];
    }
    if (preg_match('/^\d+$/', $value)) {
        return (int)$value;
    }
    if (preg_match('/^(?:(\d+)w)?(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$/', $value, $m) && $value !== '') {
        return (int)($m[1] ?? 0) * 604800 + (int)($m[2] ?? 0) * 86400 + (int)($m[3] ?? 0) * 3600 + (int)($m[4] ?? 0) * 60 + (int)($m[5] ?? 0);
    }
    return null;
}

/** Format like RouterOS does in REST output, e.g. "59m58s", "1d2h". */
function format_duration(int $seconds): string
{
    $seconds = max(0, $seconds);
    $parts = ['w' => 604800, 'd' => 86400, 'h' => 3600, 'm' => 60, 's' => 1];
    $out = '';
    foreach ($parts as $suffix => $len) {
        if ($seconds >= $len) {
            $out .= intdiv($seconds, $len) . $suffix;
            $seconds %= $len;
        }
    }
    return $out === '' ? '0s' : $out;
}

function default_state(): array
{
    return [
        'next_id' => 1,
        'started_at' => time(),
        'entries' => [],
        'fault' => ['mode' => 'none', 'latency_ms' => 0],
        'peers' => [
            ['.id' => '*1', 'interface' => 'wg0', 'name' => 'peer1', 'comment' => 'Demo laptop', 'public-key' => 'mOcKpUbLiCkEy1mOcKpUbLiCkEy1mOcKpUbLiCkEy1=', 'allowed-address' => '10.0.0.2/32', 'endpoint-address' => '198.51.100.10', 'endpoint-port' => '51820', 'last-handshake' => '1m12s', 'rx' => '5242880', 'tx' => '1048576', 'disabled' => 'false'],
            ['.id' => '*2', 'interface' => 'wg0', 'name' => 'peer2', 'comment' => 'Demo phone', 'public-key' => 'mOcKpUbLiCkEy2mOcKpUbLiCkEy2mOcKpUbLiCkEy2=', 'allowed-address' => '10.0.0.3/32', 'endpoint-address' => '', 'endpoint-port' => '0', 'rx' => '0', 'tx' => '0', 'disabled' => 'false'],
            ['.id' => '*3', 'interface' => 'wg-other', 'name' => 'peer3', 'comment' => 'Other interface', 'public-key' => 'mOcKpUbLiCkEy3mOcKpUbLiCkEy3mOcKpUbLiCkEy3=', 'allowed-address' => '10.1.0.2/32', 'rx' => '0', 'tx' => '0', 'disabled' => 'false'],
        ],
    ];
}

/**
 * Run $fn with exclusive access to the state; $fn may modify the state by reference.
 * @return mixed
 */
function with_state(string $file, callable $fn)
{
    $fh = fopen($file, 'c+');
    if ($fh === false) {
        ros_error(500, 'Internal Server Error', 'mock cannot open state file');
    }
    flock($fh, LOCK_EX);
    $raw = stream_get_contents($fh);
    $state = $raw ? json_decode($raw, true) : null;
    if (!is_array($state)) {
        $state = default_state();
    }
    // Expire dynamic entries like RouterOS does.
    $now = time();
    $state['entries'] = array_values(array_filter($state['entries'], fn($e) => $e['expires_at'] === null || $e['expires_at'] > $now));
    $result = $fn($state);
    ftruncate($fh, 0);
    rewind($fh);
    fwrite($fh, json_encode($state, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    fflush($fh);
    flock($fh, LOCK_UN);
    fclose($fh);
    return $result;
}

function present_entry(array $e): array
{
    $out = [
        '.id' => $e['.id'],
        'list' => $e['list'],
        'address' => $e['address'],
        'creation-time' => date('Y-m-d H:i:s', $e['created_at']),
        'dynamic' => $e['expires_at'] !== null ? 'true' : 'false',
        'disabled' => 'false',
    ];
    if ($e['comment'] !== '') {
        $out['comment'] = $e['comment'];
    }
    if ($e['expires_at'] !== null) {
        $out['timeout'] = format_duration($e['expires_at'] - time());
    }
    return $out;
}

function matches_query(array $item, array $query): bool
{
    foreach ($query as $key => $value) {
        if ((string)($item[$key] ?? '') !== (string)$value) {
            return false;
        }
    }
    return true;
}

function request_body(): array
{
    $raw = file_get_contents('php://input');
    $data = $raw === '' || $raw === false ? [] : json_decode($raw, true);
    if (!is_array($data)) {
        ros_error(400, 'Bad Request', 'invalid JSON');
    }
    return $data;
}

// ---------------------------------------------------------------------------
// Test control endpoints
// ---------------------------------------------------------------------------
if (strpos($path, '/_mock/') === 0) {
    switch ($method . ' ' . $path) {
        case 'POST /_mock/reset':
            with_state($stateFile, function (array &$state) {
                $state = default_state();
            });
            respond(200, ['ok' => true]);
            // no break (respond exits)
        case 'GET /_mock/state':
            respond(200, with_state($stateFile, fn(array &$state) => $state));
            // no break
        case 'POST /_mock/fault':
            $body = request_body();
            $mode = (string)($body['mode'] ?? 'none');
            if (!in_array($mode, ['none', '500', '401', 'timeout'], true)) {
                respond(400, ['error' => 'mode must be none, 500, 401 or timeout']);
            }
            $fault = ['mode' => $mode, 'latency_ms' => max(0, (int)($body['latency_ms'] ?? 0))];
            with_state($stateFile, function (array &$state) use ($fault) {
                $state['fault'] = $fault;
            });
            respond(200, ['ok' => true, 'fault' => $fault]);
            // no break
        default:
            respond(404, ['error' => 'unknown mock control endpoint']);
    }
}

// ---------------------------------------------------------------------------
// RouterOS REST API
// ---------------------------------------------------------------------------
if (strpos($path, '/rest/') !== 0) {
    respond(200, ['mock' => 'PANAG mock RouterOS', 'see' => 'dev/mock-routeros/router.php']);
}

$fault = with_state($stateFile, fn(array &$state) => $state['fault'] ?? ['mode' => 'none', 'latency_ms' => 0]);
if (($fault['latency_ms'] ?? 0) > 0) {
    usleep((int)$fault['latency_ms'] * 1000);
}
switch ($fault['mode'] ?? 'none') {
    case 'timeout':
        sleep((int)(getenv('MOCK_TIMEOUT_SECONDS') ?: 30));
        ros_error(504, 'Gateway Timeout');
        // no break
    case '500':
        ros_error(500, 'Internal Server Error', 'mock fault injection');
        // no break
    case '401':
        ros_error(401, 'Unauthorized');
}

if (($_SERVER['PHP_AUTH_USER'] ?? null) !== $username || ($_SERVER['PHP_AUTH_PW'] ?? null) !== $password) {
    header('WWW-Authenticate: Basic realm="mock-routeros"');
    ros_error(401, 'Unauthorized');
}

$resource = substr($path, strlen('/rest'));

if ($resource === '/ip/firewall/address-list') {
    if ($method === 'GET') {
        $items = with_state($stateFile, fn(array &$state) => array_map('present_entry', $state['entries']));
        respond(200, array_values(array_filter($items, fn($item) => matches_query($item, $query))));
    }
    if ($method === 'PUT') {
        $body = request_body();
        $list = trim((string)($body['list'] ?? ''));
        $address = trim((string)($body['address'] ?? ''));
        if ($list === '' || $address === '') {
            ros_error(400, 'Bad Request', 'missing list or address');
        }
        $timeout = null;
        if (isset($body['timeout']) && (string)$body['timeout'] !== '') {
            $timeout = parse_duration((string)$body['timeout']);
            if ($timeout === null) {
                ros_error(400, 'Bad Request', 'value of timeout out of range');
            }
        }
        $created = with_state($stateFile, function (array &$state) use ($list, $address, $timeout, $body) {
            foreach ($state['entries'] as $e) {
                if ($e['list'] === $list && $e['address'] === $address) {
                    return null;
                }
            }
            $entry = [
                '.id' => '*' . strtoupper(dechex($state['next_id']++)),
                'list' => $list,
                'address' => $address,
                'comment' => (string)($body['comment'] ?? ''),
                'created_at' => time(),
                'expires_at' => $timeout !== null ? time() + $timeout : null,
            ];
            $state['entries'][] = $entry;
            return $entry;
        });
        if ($created === null) {
            ros_error(400, 'Bad Request', 'failure: already have such entry');
        }
        respond(201, present_entry($created));
    }
    ros_error(400, 'Bad Request', 'unsupported method');
}

if (preg_match('#^/ip/firewall/address-list/(\*[0-9A-Fa-f]+)$#', $resource, $m)) {
    $id = strtoupper($m[1]);
    $result = with_state($stateFile, function (array &$state) use ($id, $method) {
        foreach ($state['entries'] as $idx => $e) {
            if (strtoupper($e['.id']) !== $id) {
                continue;
            }
            if ($method === 'DELETE') {
                array_splice($state['entries'], $idx, 1);
                return ['deleted' => true];
            }
            if ($method === 'PATCH') {
                $body = request_body();
                if (array_key_exists('timeout', $body)) {
                    $seconds = parse_duration((string)$body['timeout']);
                    if ($seconds === null) {
                        return ['error' => 'value of timeout out of range'];
                    }
                    $state['entries'][$idx]['expires_at'] = time() + $seconds;
                }
                if (array_key_exists('comment', $body)) {
                    $state['entries'][$idx]['comment'] = (string)$body['comment'];
                }
                return ['entry' => $state['entries'][$idx]];
            }
            return ['entry' => $e];
        }
        return null;
    });
    if ($result === null) {
        ros_error(404, 'Not Found', 'no such item');
    }
    if (isset($result['error'])) {
        ros_error(400, 'Bad Request', $result['error']);
    }
    if (!empty($result['deleted'])) {
        respond(204);
    }
    respond(200, present_entry($result['entry']));
}

if ($method !== 'GET') {
    ros_error(400, 'Bad Request', 'unsupported method');
}

switch ($resource) {
    case '/system/identity':
        respond(200, ['name' => $identity]);
        // no break
    case '/system/clock':
        respond(200, [
            'date' => date('Y-m-d'),
            'time' => date('H:i:s'),
            'time-zone-name' => date_default_timezone_get(),
            'time-zone-autodetect' => 'false',
            'gmt-offset' => date('P'),
            'dst-active' => date('I') ? 'true' : 'false',
        ]);
        // no break
    case '/system/resource':
        $startedAt = with_state($stateFile, fn(array &$state) => (int)$state['started_at']);
        respond(200, [
            'uptime' => format_duration(time() - $startedAt),
            'version' => '7.99 (mock)',
            'board-name' => 'hEX S (mock)',
            'architecture-name' => 'arm',
            'cpu-load' => '3',
            'free-memory' => '402653184',
            'total-memory' => '536870912',
        ]);
        // no break
    case '/interface/wireguard/peers':
        $peers = with_state($stateFile, fn(array &$state) => $state['peers']);
        respond(200, array_values(array_filter($peers, fn($p) => matches_query($p, $query))));
}

ros_error(404, 'Not Found', 'no such command or directory (' . $resource . ')');
