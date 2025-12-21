<?php
require_once __DIR__ . '/lib/functions.php';
ensure_session();

$flagFile = __DIR__ . '/setup-completed.txt';
if (file_exists($flagFile)) {
    header('Location: ' . url_for('index.php'));
    exit;
}

$remoteIp = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
$message = '';
$messageClass = 'info';
$flagCreated = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  require_csrf_token($_POST['csrf_token'] ?? null);
    $username = trim($_POST['username'] ?? '');
    $otp = trim($_POST['otp_secret'] ?? '');
    $access = (int)($_POST['accesslevel'] ?? 10);

    if ($username === '' || $otp === '') {
      $message = 'Username and OTP secret are required.';
        $messageClass = 'danger';
    } else {
      $existing = fetch_user_by_user_ip($remoteIp);
        if ($existing) {
        $updatedName = $username ?: $existing['username'];
            $updatedOtp = $otp ?: $existing['otp_secret'];
            $updatedAccess = max($existing['accesslevel'], $access);
        save_user((int)$existing['id'], $updatedName, $remoteIp, $updatedOtp, 1, $updatedAccess);
            $message = 'Existing user promoted to admin.';
        } else {
        save_user(null, $username, $remoteIp, $otp, 1, $access);
            $message = 'Admin user created.';
        }
        $flagCreated = @file_put_contents($flagFile, 'Setup completed on ' . date('c')) !== false;
        if (!$flagCreated) {
          $message .= ' Warning: failed to write setup-completed.txt. Create it manually to disable setup.';
          $messageClass = 'warning';
        } else {
          $messageClass = 'success';
        }
    }
}

    // If the flag was successfully created, reload to exit setup flow immediately.
    if ($flagCreated) {
      header('Location: ' . url_for('index.php'));
      exit;
    }

include __DIR__ . '/lib/header.php';
?>
<div class="row justify-content-center">
  <div class="col-lg-6">
    <div class="card shadow-sm">
      <div class="card-header">Initial setup</div>
      <div class="card-body">
        <p class="text-muted">Run this once to create or promote an admin for <?= htmlspecialchars($remoteIp) ?>.</p>
        <?php if ($message): ?>
          <div class="alert alert-<?= htmlspecialchars($messageClass) ?>" role="alert"><?= htmlspecialchars($message) ?></div>
        <?php endif; ?>
        <form method="post" novalidate>
          <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
          <div class="mb-3">
            <label class="form-label">Detected user IP</label>
            <input type="text" class="form-control" value="<?= htmlspecialchars($remoteIp) ?>" readonly>
          </div>
          <div class="mb-3">
            <label class="form-label">Username (display)</label>
            <input type="text" name="username" class="form-control" required>
          </div>
          <div class="mb-3">
            <label class="form-label">OTP secret (Base32)</label>
            <input type="text" name="otp_secret" class="form-control" required>
          </div>
          <div class="mb-3">
            <label class="form-label">Access level</label>
            <input type="number" name="accesslevel" class="form-control" value="10" min="0" max="<?= (int)MAX_ACCESS_LEVEL ?>">
          </div>
          <button type="submit" class="btn btn-primary">Save admin</button>
        </form>
        <hr>
        <p class="small text-muted mb-0">After successful setup, a flag file is written to disable this page. Remove setup-completed.txt if you need to rerun.</p>
      </div>
    </div>
  </div>
</div>
<?php include __DIR__ . '/lib/footer.php'; ?>
