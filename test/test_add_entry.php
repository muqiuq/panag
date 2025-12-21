<?php
require_once __DIR__ . '/../functions.php';

if (!defined('ALLOW_TESTS') || !ALLOW_TESTS) {
    http_response_code(403);
    echo 'Tests are disabled.';
    exit;
}

header('Content-Type: text/html; charset=UTF-8');

// Simple harness to exercise add_address_list_entry and clean up after itself.
$userIp = $_GET['user_ip'] ?? 'testuser';
$address = $_GET['address'] ?? '10.0.0.0/24';
$name = $_GET['name'] ?? 'TestNet';
$timeout = $_GET['timeout'] ?? DEFAULT_TIMEOUT;

$network = ['name' => $name, 'address' => $address];

// Helpers
$deleteAddressEntries = function (string $userIp, string $address): array {
    $entries = get_current_address_list_entries($userIp);
    $listName = address_list_name($userIp);
    $targets = array_values(array_filter($entries, function ($entry) use ($address, $listName) {
        return isset($entry['address'], $entry['.id'], $entry['list'])
            && $entry['list'] === $listName
            && $entry['address'] === $address;
    }));
    $deleted = 0;
    $errors = [];
    foreach ($targets as $entry) {
        $del = mikrotik_request('DELETE', '/ip/firewall/address-list/' . $entry['.id']);
        if ($del['success']) {
            $deleted++;
        } else {
            $errors[] = $del['error'] ?? ('Delete failed for ' . $entry['.id']);
        }
    }
    return ['deleted' => $deleted, 'errors' => $errors, 'attempted' => count($targets)];
};

// Step 1: pre-clean any existing test entry for this address.
$preCleanup = $deleteAddressEntries($userIp, $address);

// Step 2: attempt to create.
$createResult = add_address_list_entry($userIp, $network, $timeout);
$createOk = $createResult['success'] ?? false;

// Step 3: cleanup (always try to remove the address after the test).
$postCleanup = $deleteAddressEntries($userIp, $address);

$overallOk = $createOk && empty($postCleanup['errors']);
$status = $createResult['status'] ?? null;
$message = $createResult['message'] ?? ($createOk ? 'Applied' : 'Failed');

$steps = [
    [
        'title' => 'Pre-clean existing entries',
        'ok' => empty($preCleanup['errors']),
        'message' => 'Deleted ' . $preCleanup['deleted'] . ' of ' . $preCleanup['attempted'],
        'status' => null,
        'data' => $preCleanup,
    ],
    [
        'title' => 'Create entry',
        'ok' => $createOk,
        'message' => $message,
        'status' => $status,
        'data' => $createResult,
    ],
    [
        'title' => 'Post-clean cleanup',
        'ok' => empty($postCleanup['errors']),
        'message' => 'Deleted ' . $postCleanup['deleted'] . ' of ' . $postCleanup['attempted'],
        'status' => null,
        'data' => $postCleanup,
    ],
];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>MikroTik add entry test</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 2rem; color: #222; }
        .card { border: 1px solid #ddd; border-radius: 8px; padding: 1.5rem; max-width: 720px; }
        .status { display: inline-block; padding: 0.3rem 0.75rem; border-radius: 999px; font-weight: bold; color: #fff; }
        .ok { background: #28a745; }
        .fail { background: #dc3545; }
        table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
        td { padding: 0.5rem 0.25rem; vertical-align: top; }
        td:first-child { font-weight: bold; width: 30%; }
        pre { background: #f8f9fa; padding: 1rem; border-radius: 6px; overflow: auto; }
    </style>
</head>
<body>
    <div class="card">
        <h1 style="margin-top: 0; margin-bottom: 0.5rem;">Add address-list entry</h1>
        <p class="status <?= $overallOk ? 'ok' : 'fail' ?>"><?= $overallOk ? 'OK' : 'FAIL' ?></p>
        <p><?= htmlspecialchars($message) ?></p>
        <table>
            <tr><td><strong>User IP</strong></td><td><?= htmlspecialchars($userIp) ?></td></tr>
            <tr><td><strong>Network</strong></td><td><?= htmlspecialchars($network['name'] . ' (' . $network['address'] . ')') ?></td></tr>
            <tr><td><strong>Timeout</strong></td><td><?= htmlspecialchars((string)$timeout) ?></td></tr>
        </table>

        <h3>Steps</h3>
        <ul class="list-unstyled">
            <?php foreach ($steps as $step): ?>
                <li style="margin-bottom: 0.75rem; padding: 0.75rem; border: 1px solid #eee; border-radius: 6px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; gap: 1rem;">
                        <strong><?= htmlspecialchars($step['title']) ?></strong>
                        <span class="status <?= $step['ok'] ? 'ok' : 'fail' ?>"><?= $step['ok'] ? 'OK' : 'FAIL' ?></span>
                    </div>
                    <div><?= htmlspecialchars($step['message']) ?><?php if ($step['status'] !== null): ?> (API status: <?= htmlspecialchars((string)$step['status']) ?>)<?php endif; ?></div>
                    <pre><?= htmlspecialchars(json_encode($step['data'], JSON_PRETTY_PRINT), ENT_QUOTES, 'UTF-8') ?></pre>
                </li>
            <?php endforeach; ?>
        </ul>
    </div>
</body>
</html>
