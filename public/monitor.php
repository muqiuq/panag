<?php
// Trigger one monitor cycle. Called every 5 min by the RouterOS scheduler, which reads the token from the data mount:
//   /tool fetch url="http://<container>:8080/monitor.php" http-method=post http-header-field=("X-Monitor-Token: " . [/file/get "<mount>/monitor.token" contents]) output=none
// Protected by the monitor token (MONITOR_TOKEN or generated DATA_DIR/monitor.token) and MONITOR_ALLOWED_SOURCES
// (checked against the TCP source address, never X-Forwarded-For).
require_once __DIR__ . '/../src/bootstrap.php';
header('Content-Type: application/json');
header('Cache-Control: no-store');

function monitor_respond(int $status, array $body): void
{
    http_response_code($status);
    echo json_encode($body);
    exit;
}

if (($problem = monitor_config_problem()) !== null) {
    monitor_respond(503, ['status' => 'disabled', 'message' => $problem]);
}
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    monitor_respond(405, ['status' => 'error', 'message' => 'POST required']);
}
$source = (string)($_SERVER['REMOTE_ADDR'] ?? '');
$token = (string)($_SERVER['HTTP_X_MONITOR_TOKEN'] ?? '');
if (!monitor_request_allowed($source, $token)) {
    monitor_respond(403, ['status' => 'forbidden']);
}
ignore_user_abort(true);
set_time_limit(120);
$stats = run_monitor_cycle();
monitor_respond($stats['status'] === 'busy' ? 409 : 200, $stats);
