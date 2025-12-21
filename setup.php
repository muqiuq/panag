<?php
require_once __DIR__ . '/lib/functions.php';
ensure_session();

$flagFile = SETUP_FLAG_PATH;
if (file_exists($flagFile)) {
  header('Location: ' . url_for('index.php'));
  exit;
}

$remoteIp = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
$message = '';
$messageClass = 'info';
$flagCreated = false;
$dbInitDone = false;
$generatedSecret = generate_otp_secret();
$prefillSecret = $generatedSecret;

// Ensure DB directories and schema exist if requested explicitly later.
// Do not auto-init here to allow manual control via the form.

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  require_csrf_token($_POST['csrf_token'] ?? null);
  $action = $_POST['action'] ?? 'create_admin';

  if ($action === 'initdb') {
    $pdo = db();
    init_db($pdo);
    $dbInitDone = true;
    $message = 'Database initialized.';
    $messageClass = 'success';
  } elseif ($action === 'create_admin') {
    $username = trim($_POST['username'] ?? '');
    $otp = trim($_POST['otp_secret'] ?? '');
    $access = (int)($_POST['accesslevel'] ?? MAX_ACCESS_LEVEL);
    $prefillSecret = $otp !== '' ? $otp : $generatedSecret;

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
        $flagName = basename($flagFile);
        $message .= ' Warning: failed to write ' . $flagName . '. Create it manually to disable setup.';
        $messageClass = 'warning';
      } else {
        $messageClass = 'success';
      }
    }
  }
}

  // If the flag was successfully created, reload to exit setup flow immediately.
  if ($flagCreated) {
    header('Location: ' . url_for('index.php'));
    exit;
  }

  // Best-effort DB health indicators
  $dbWritable = is_writable(dirname(DB_PATH));
  $dbExists = file_exists(DB_PATH);
  $dbReady = false;
  try {
    $dbReady = !is_db_empty(db());
  } catch (Throwable $e) {
    $dbReady = false;
  }

include __DIR__ . '/lib/header.php';
?>
<div class="row justify-content-center">
  <div class="col-lg-6">
    <div class="card shadow-sm">
      <div class="card-header">Initial setup</div>
      <div class="card-body">
        <p class="text-muted">Run this once to initialize the database and create or promote an admin for <?= htmlspecialchars($remoteIp) ?>.</p>
        <div class="mb-3">
          <span class="badge <?= $dbReady ? 'bg-success' : 'bg-secondary' ?>">DB ready</span>
          <span class="badge <?= $dbExists ? 'bg-success' : 'bg-secondary' ?>">File <?= htmlspecialchars(basename(DB_PATH)) ?></span>
          <span class="badge <?= $dbWritable ? 'bg-success' : 'bg-danger' ?>">Dir writable</span>
        </div>
        <form method="post" class="mb-4">
          <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
          <input type="hidden" name="action" value="initdb">
          <button type="submit" class="btn btn-outline-secondary">Initialize database</button>
          <?php if ($dbInitDone): ?><span class="text-success small ms-2">Done.</span><?php endif; ?>
        </form>
        <?php if ($message): ?>
          <div class="alert alert-<?= htmlspecialchars($messageClass) ?>" role="alert"><?= htmlspecialchars($message) ?></div>
        <?php endif; ?>
        <form method="post" novalidate>
          <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
          <input type="hidden" name="action" value="create_admin">
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
            <div class="input-group">
              <input type="text" name="otp_secret" id="otpSecretSetup" class="form-control" value="<?= htmlspecialchars($prefillSecret) ?>" required>
              <button class="btn btn-outline-secondary" type="button" id="showQrBtn">Show OTP QR</button>
            </div>
          </div>
          <div class="mb-3">
            <label class="form-label">Access level</label>
            <input type="number" name="accesslevel" class="form-control" value="<?= (int)MAX_ACCESS_LEVEL ?>" min="0" max="<?= (int)MAX_ACCESS_LEVEL ?>">
          </div>
          <button type="submit" class="btn btn-primary">Save admin</button>
        </form>
        <hr>
        <p class="small text-muted mb-0">After successful setup, a flag file is written to disable this page. Remove setup-completed.txt if you need to rerun.</p>
      </div>
    </div>
  </div>
</div>

<div class="modal fade" id="qrModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-dialog-centered">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title" id="qrTitle">OTP QR</h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <div class="modal-body d-flex justify-content-center" id="qrBody"></div>
      <div class="modal-footer">
        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
      </div>
    </div>
  </div>
</div>

<script src="<?= htmlspecialchars(url_for('js/bootstrap.bundle.min.js')) ?>"></script>
<script src="<?= htmlspecialchars(url_for('js/kjua.min.js')) ?>"></script>
<script>
document.addEventListener('DOMContentLoaded', () => {
  const btn = document.getElementById('showQrBtn');
  const secretInput = document.getElementById('otpSecretSetup');
  const usernameInput = document.querySelector('input[name="username"]');
  const modalEl = document.getElementById('qrModal');
  const modalTitle = document.getElementById('qrTitle');
  const modalBody = document.getElementById('qrBody');
  if (!btn || !secretInput || !modalEl || !window.bootstrap) return;
  const bsModal = new bootstrap.Modal(modalEl);

  const ISSUER = <?= json_encode(OTP_ISSUER) ?>;
  const DIGITS = <?= (int)OTP_DIGITS ?>;
  const PERIOD = <?= (int)OTP_STEP ?>;
  const userIp = <?= json_encode($remoteIp) ?>;

  btn.addEventListener('click', () => {
    const secret = secretInput.value.trim();
    const name = usernameInput?.value?.trim() || 'Admin';
    if (!secret) return;
    const label = encodeURIComponent(`${ISSUER}:${userIp}`);
    const issuer = encodeURIComponent(ISSUER);
    const otpUrl = `otpauth://totp/${label}?secret=${encodeURIComponent(secret)}&issuer=${issuer}&digits=${DIGITS}&period=${PERIOD}`;
    modalTitle.textContent = `OTP for ${name} (${userIp})`;
    modalBody.innerHTML = '';
    const qr = kjua({
      text: otpUrl,
      size: 240,
      quiet: 2,
      ecLevel: 'M',
      render: 'svg',
    });
    modalBody.appendChild(qr);
    bsModal.show();
  });
});
</script>
<?php include __DIR__ . '/lib/footer.php';
