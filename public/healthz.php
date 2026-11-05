<?php
// Liveness/readiness probe (container HEALTHCHECK, RouterOS Netwatch http-get).
// GET /healthz.php          -> checks the database
// GET /healthz.php?deep=1   -> additionally checks the RouterOS REST API
require_once __DIR__ . '/../src/bootstrap.php';

header('Content-Type: application/json');
header('Cache-Control: no-store');

$result = ['status' => 'ok', 'version' => APP_VERSION, 'db' => 'ok'];
$healthy = true;

try {
    db()->query('SELECT 1')->fetchColumn();
} catch (Throwable $e) {
    $result['db'] = 'error';
    $healthy = false;
}

if (!empty($_GET['deep'])) {
    $identity = router()->identity();
    $result['router'] = $identity['success'] ? 'ok' : 'error';
    $healthy = $healthy && $identity['success'];
}

if (!$healthy) {
    $result['status'] = 'error';
    http_response_code(503);
}
echo json_encode($result);
