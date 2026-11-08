<?php
require_once __DIR__ . '/../src/bootstrap.php';
ensure_session();

$remoteIp = client_ip();
$ipAllowed = login_ip_allowed($remoteIp);
$message = '';
$setupPending = !admin_exists();
$resetFile = RESET_LOGIN_FILE;

// Pick hero image based on configured schedule (hour in 24h, start inclusive, end exclusive)
$heroImage = 'panag-logo-noon.jpg';
$hourNow = (int)date('G');
foreach (LOGIN_HERO_IMAGES as $slot) {
    if ($hourNow >= $slot['start'] && $hourNow < $slot['end']) {
        $heroImage = $slot['file'];
        break;
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
<?php $theme = current_theme(null); ?>
<html lang="en" <?= theme_attributes($theme) ?>>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?= htmlspecialchars(APP_NAME) ?> Login</title>
    <link rel="stylesheet" href="<?= htmlspecialchars(url_for('css/bootstrap.min.css')) ?>">
    <link rel="stylesheet" href="<?= htmlspecialchars(url_for('css/main.css')) ?>">
    <link rel="stylesheet" href="<?= htmlspecialchars(url_for('css/themes.css')) ?>">
</head>
<body>
<?php include view_path('partials/dev_banner'); ?>
<div class="container d-flex justify-content-center align-items-center min-vh-100">
    <?php if ($ipAllowed): ?>
                <div class="d-flex flex-column align-items-center w-100 login-column">
                    <div class="mb-3 text-center login-hero">
                        <img src="<?= htmlspecialchars(url_for('img/' . $heroImage)) ?>" alt="PANAG logo" class="login-hero-img">
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
                          <label class="form-label" for="login-user-ip">User IP</label>
                          <input id="login-user-ip" type="text" class="form-control" value="<?= htmlspecialchars($remoteIp) ?>" readonly>
                      </div>
                      <div class="mb-3">
                          <label class="form-label" for="login-one-time-password">One-Time Password</label>
                          <input id="login-one-time-password" type="text" name="otp" class="form-control" maxlength="6" pattern="\d{6}" autocomplete="one-time-code" inputmode="numeric" required>
                      </div>
                      <button type="submit" class="btn btn-primary w-100">Login</button>
                  </form>
              </div>
          </div>
          <div class="text-center text-muted small mt-2">Server time: <?= htmlspecialchars(date('Y-m-d H:i:s')) ?></div>
        </div>
    <?php else: ?>
        <div class="text-center text-muted nothing-here">
            <div class="nothing-here-icon">🤏</div>
            <div>There is nothing here.</div>
        </div>
    <?php endif; ?>
</div>
<script src="<?= htmlspecialchars(url_for('js/bootstrap.bundle.min.js')) ?>"></script>
</body>
</html>
