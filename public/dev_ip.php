<?php
// Dev only: switch the simulated client IP (see src/views/partials/dev_banner.php).
require_once __DIR__ . '/../src/bootstrap.php';
if (!is_dev_mode()) {
    http_response_code(404);
    exit;
}
ensure_session();
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit;
}
require_csrf_token($_POST['csrf_token'] ?? null);
$ip = trim((string)($_POST['ip'] ?? ''));
if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
    setcookie(DEV_IP_COOKIE, $ip, ['path' => '/', 'httponly' => true, 'samesite' => 'Strict']);
} else {
    setcookie(DEV_IP_COOKIE, '', ['path' => '/', 'expires' => time() - 3600]);
}
logout_user();
header('Location: ' . url_for('login.php'));
exit;
