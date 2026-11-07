<?php
// End an admin impersonation and return to the admin account.
require_once __DIR__ . '/../src/bootstrap.php';
ensure_session();
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit;
}
require_csrf_token($_POST['csrf_token'] ?? null);
$admin = stop_impersonation();
header('Location: ' . url_for($admin ? 'admin/users.php' : 'login.php'));
exit;
