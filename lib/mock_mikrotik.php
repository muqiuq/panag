<?php
// Helpers for mocking Mikrotik API calls during tests.

function is_mock_mikrotik(): bool
{
    static $cached = null;
    if ($cached !== null) {
        return $cached;
    }
    $env = getenv('MOCK_MIKROTIK');
    $cached = $env === '1' || $env === 'true';
    return $cached;
}

function mock_store_path(): string
{
    $root = dirname(__DIR__);
    $dir = $root . '/data';
    if (!is_dir($dir)) {
        mkdir($dir, 0775, true);
    }
    return $dir . '/mock_address_list.json';
}

function mock_load_address_list(): array
{
    $path = mock_store_path();
    if (!file_exists($path)) {
        return [];
    }
    $json = file_get_contents($path);
    $data = json_decode($json, true);
    return is_array($data) ? $data : [];
}

function mock_save_address_list(array $items): void
{
    $path = mock_store_path();
    file_put_contents($path, json_encode(array_values($items), JSON_PRETTY_PRINT));
}

function mock_get_current_address_list_entries(string $listName): array
{
    if (function_exists('is_valid_address_list_name') && !is_valid_address_list_name($listName)) {
        return [];
    }
    $all = mock_load_address_list();
    return array_values(array_filter($all, function ($entry) use ($listName) {
        return isset($entry['list']) && $entry['list'] === $listName;
    }));
}

function mock_get_all_address_list_entries(): array
{
    return ['success' => true, 'data' => mock_load_address_list()];
}

function mock_add_address_list_entry(string $listName, array $network, string $timeout): array
{
    if (function_exists('is_valid_address_list_name') && !is_valid_address_list_name($listName)) {
        return ['success' => false, 'status' => null, 'message' => 'Invalid address list'];
    }
    $all = mock_load_address_list();
    $existing = array_filter($all, function ($item) use ($listName, $network) {
        return ($item['list'] ?? '') === $listName && ($item['address'] ?? '') === ($network['address'] ?? '');
    });
    if (!empty($existing)) {
        return ['success' => true, 'status' => null, 'message' => 'Already present'];
    }
    $all[] = [
        '.id' => uniqid('mock_', true),
        'list' => $listName,
        'address' => $network['address'],
        'comment' => $network['name'] ?? 'network',
        'timeout' => $timeout,
    ];
    mock_save_address_list($all);
    return ['success' => true, 'status' => 200, 'message' => 'Applied'];
}

function mock_remove_address_list_entries(string $listName): array
{
    if (function_exists('is_valid_address_list_name') && !is_valid_address_list_name($listName)) {
        return ['success' => false, 'message' => 'Invalid address list', 'deleted' => 0, 'total' => 0, 'errors' => []];
    }
    $all = mock_load_address_list();
    $remaining = array_values(array_filter($all, function ($entry) use ($listName) {
        return ($entry['list'] ?? '') !== $listName;
    }));
    $deleted = count($all) - count($remaining);
    mock_save_address_list($remaining);
    return [
        'success' => true,
        'message' => 'Entries removed.',
        'deleted' => $deleted,
        'total' => $deleted,
        'errors' => [],
    ];
}

function mock_mikrotik_identity(): array
{
    return ['success' => true, 'data' => ['name' => 'mock-router']];
}

function mock_mikrotik_clock(): array
{
    return [
        'success' => true,
        'data' => [
            'time' => '12:34:56',
            'date' => '2024-01-01',
            'time_zone' => 'UTC',
            'gmt_offset' => '+00:00',
        ],
    ];
}

function mock_mikrotik_uptime(): array
{
    return ['success' => true, 'data' => ['uptime' => '1w2d3h4m5s']];
}

function mock_mikrotik_wireguard_peers(): array
{
    return [
        'success' => true,
        'data' => [
            [
                'public-key' => 'mock-public-key-1',
                'comment' => 'Demo peer 1',
                'name' => 'peer1',
                'last-handshake' => '2024-01-01T12:00:00Z',
                'tx' => 123456,
                'rx' => 654321,
            ],
        ],
    ];
}
