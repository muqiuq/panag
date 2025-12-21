<?php
require_once __DIR__ . '/../functions.php';

if (!defined('ALLOW_TESTS') || !ALLOW_TESTS) {
    http_response_code(403);
    echo 'Tests are disabled.';
    exit;
}

header('Content-Type: text/html; charset=UTF-8');

// Lightweight health check for MikroTik API availability; no authentication required.
$response = mikrotik_request('GET', '/system/identity');
$ok = $response['success'];
$httpStatus = $response['status'] ?? null;
$title = $ok ? 'MikroTik API reachable' : 'MikroTik API unreachable';
$error = $response['error'] ?? null;
$data = $response['data'] ?? null;
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?= htmlspecialchars($title) ?></title>
    <style>
        body { font-family: Arial, sans-serif; margin: 2rem; color: #222; }
        .card { border: 1px solid #ddd; border-radius: 8px; padding: 1.5rem; max-width: 640px; }
        .status { display: inline-block; padding: 0.3rem 0.75rem; border-radius: 999px; font-weight: bold; color: #fff; }
        .ok { background: #28a745; }
        .fail { background: #dc3545; }
        pre { background: #f8f9fa; padding: 1rem; border-radius: 6px; overflow: auto; }
    </style>
</head>
<body>
    <div class="card">
        <h1 style="margin-top: 0; margin-bottom: 0.5rem;">MikroTik API Health</h1>
        <p class="status <?= $ok ? 'ok' : 'fail' ?>"><?= $ok ? 'OK' : 'FAIL' ?></p>
        <p><?= htmlspecialchars($title) ?></p>
        <ul>
            <li>HTTP status: <?= htmlspecialchars($httpStatus !== null ? (string)$httpStatus : 'n/a') ?></li>
            <?php if ($error): ?><li>Error: <?= htmlspecialchars($error) ?></li><?php endif; ?>
        </ul>
        <?php if ($data !== null): ?>
            <h3>Response data</h3>
            <pre><?= htmlspecialchars(json_encode($data, JSON_PRETTY_PRINT), ENT_QUOTES, 'UTF-8') ?></pre>
        <?php endif; ?>
    </div>
</body>
</html>
