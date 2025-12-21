<?php
require_once __DIR__ . '/functions.php';
ensure_session();

$remoteIp = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_csrf_token($_POST['csrf_token'] ?? null);
    $otp = $_POST['otp'] ?? '';
    if (login_rate_limited($remoteIp, $remoteIp)) {
        $message = 'Too many failed attempts. Try again later.';
        log_event('login_rate_limited', 'Too many failed attempts', null, $remoteIp);
    } elseif (login_user($remoteIp, $otp, $remoteIp)) {
        header('Location: ' . url_for('index.php'));
        exit;
    } else {
        $message = 'Invalid OTP or user not found.';
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?= htmlspecialchars(APP_NAME) ?> Login</title>
    <link rel="stylesheet" href="<?= htmlspecialchars(url_for('css/bootstrap.min.css')) ?>">
    <link rel="stylesheet" href="<?= htmlspecialchars(url_for('css/main.css')) ?>">
</head>
<body class="bg-light">
<div class="container d-flex justify-content-center align-items-center min-vh-100">
    <div class="card shadow-sm" style="max-width: 420px; width: 100%;">
        <div class="card-body">
            <h4 class="card-title text-center mb-3">Login to <?= htmlspecialchars(APP_NAME) ?></h4>
            <?php if ($message): ?>
                <div class="alert alert-danger" role="alert"><?= htmlspecialchars($message) ?></div>
            <?php endif; ?>
            <form method="post" novalidate>
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
                <div class="mb-3">
                    <label class="form-label">Username (IP)</label>
                    <input type="text" class="form-control" value="<?= htmlspecialchars($remoteIp) ?>" readonly>
                </div>
                <div class="mb-3">
                    <label class="form-label">One-Time Password</label>
                    <input type="text" name="otp" class="form-control" maxlength="6" pattern="\d{6}" required>
                </div>
                <button type="submit" class="btn btn-primary w-100">Login</button>
            </form>
        </div>
    </div>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
