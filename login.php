<?php
require_once __DIR__ . '/lib/functions.php';
ensure_session();

$remoteIp = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
$ipAllowed = login_ip_allowed($remoteIp);
$message = '';
$setupPending = defined('SETUP_FLAG_PATH') ? !file_exists(SETUP_FLAG_PATH) : !file_exists(__DIR__ . '/setup-completed.txt');
$resetFile = defined('RESET_LOGIN_FILE') ? RESET_LOGIN_FILE : (__DIR__ . '/reset_login_attempts.txt');

// Pick hero image based on configured schedule (hour in 24h, start inclusive, end exclusive)
$heroImage = 'panag-logo.png';
if (defined('LOGIN_HERO_IMAGES') && is_array(LOGIN_HERO_IMAGES)) {
    $hourNow = (int)date('G');
    foreach (LOGIN_HERO_IMAGES as $slot) {
        $s = isset($slot['start']) ? (int)$slot['start'] : 0;
        $e = isset($slot['end']) ? (int)$slot['end'] : 24;
        $file = isset($slot['file']) ? (string)$slot['file'] : '';
        if ($file !== '' && $hourNow >= $s && $hourNow < $e) {
            $heroImage = $file;
            break;
        }
    }
}

// Allow a manual reset of failed login attempts via flag file.
if (file_exists($resetFile)) {
    try {
        $pdo = db();
        $pdo->exec('DELETE FROM login_attempts');
    } catch (Throwable $e) {
        // Swallow errors to avoid breaking login; optionally log if needed.
    }
    @unlink($resetFile);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!$ipAllowed) {
        http_response_code(403);
        echo 'Forbidden';
        exit;
    }
    require_csrf_token($_POST['csrf_token'] ?? null);
    $otp = $_POST['otp'] ?? '';
    if (login_rate_limited($remoteIp, $remoteIp)) {
        $message = 'Too many failed attempts. Try again later.';
            log_event('login_rate_limited', 'Too many failed attempts', null, null, $remoteIp);
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
    <?php if ($ipAllowed): ?>
                <div class="d-flex flex-column align-items-center w-100" style="max-width: 420px;">
                    <div class="mb-3 text-center" style="max-width: 280px; width: 100%; margin: 0 auto;">
                        <img src="<?= htmlspecialchars(url_for('img/' . $heroImage)) ?>" alt="PANAG logo" style="max-width: 280px; width: 100%; height: auto; aspect-ratio: 1 / 1; object-fit: contain;">
                    </div>
          <div class="card shadow-sm w-100">
              <div class="card-body">
                                <h4 class="card-title text-center mb-3">Login to <?= htmlspecialchars(APP_NAME) ?></h4>
                                <?php if ($setupPending): ?>
                                    <div class="alert alert-warning py-2" role="alert">
                                        Initial setup not completed. <a href="<?= htmlspecialchars(url_for('setup.php')) ?>" class="alert-link">Go to setup</a>.
                                    </div>
                                <?php endif; ?>
                  <?php if ($message): ?>
                      <div class="alert alert-danger" role="alert"><?= htmlspecialchars($message) ?></div>
                  <?php endif; ?>
                  <form method="post" autocomplete="off" novalidate>
                      <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
                      <div class="mb-3">
                          <label class="form-label">User IP</label>
                          <input type="text" class="form-control" value="<?= htmlspecialchars($remoteIp) ?>" readonly>
                      </div>
                      <div class="mb-3">
                          <label class="form-label">One-Time Password</label>
                          <input type="text" name="otp" class="form-control" maxlength="6" pattern="\d{6}" autocomplete="one-time-code" inputmode="numeric" required>
                      </div>
                      <button type="submit" class="btn btn-primary w-100">Login</button>
                  </form>
              </div>
          </div>
          <div class="text-center text-muted small mt-2">Server time: <?= htmlspecialchars(date('Y-m-d H:i:s')) ?></div>
        </div>
    <?php else: ?>
        <div class="text-center text-muted" style="font-size: 1.1rem;">
            <div style="font-size: 3rem; line-height: 1;">🤏</div>
            <div>There is nothing here.</div>
        </div>
    <?php endif; ?>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
