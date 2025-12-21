<?php
require_once __DIR__ . '/functions.php';

header('Content-Type: application/json');

// Lightweight health check for MikroTik API availability; no authentication required.
$response = mikrotik_request('GET', '/system/identity');

if ($response['success']) {
    echo json_encode([
        'status' => true,
        'message' => 'MikroTik API reachable',
        'http_status' => $response['status'] ?? null,
        'data' => $response['data'] ?? null,
    ]);
    exit;
}

http_response_code($response['status'] ?? 500);
echo json_encode([
    'status' => false,
    'message' => 'MikroTik API unreachable',
    'http_status' => $response['status'] ?? null,
    'error' => $response['error'] ?? 'unknown error',
]);
exit;
?>
