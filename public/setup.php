<?php
require_once __DIR__ . '/../src/bootstrap.php';
ensure_session();

// Setup is only available while no admin exists. This replaces the old setup-completed.txt flag file,
// which re-opened setup whenever a container was recreated without it.
if (admin_exists()) {
  header('Location: ' . url_for('index.php'));
  exit;
}

$remoteIp = client_ip();
if (!login_ip_allowed($remoteIp)) {
  http_response_code(403);
  echo 'Forbidden';
  exit;
}

$message = '';
$messageClass = 'info';
$tokenRequired = (string)SETUP_TOKEN !== '';
$generatedSecret = generate_otp_secret();
$prefillSecret = $generatedSecret;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  require_csrf_token($_POST['csrf_token'] ?? null);
  $username = trim($_POST['username'] ?? '');
  $otp = trim($_POST['otp_secret'] ?? '');
  $access = (int)($_POST['accesslevel'] ?? MAX_ACCESS_LEVEL);
  $prefillSecret = $otp !== '' ? $otp : $generatedSecret;
  $tokenOk = !$tokenRequired || hash_equals((string)SETUP_TOKEN, (string)($_POST['setup_token'] ?? ''));

  if (!$tokenOk) {
    $message = 'Invalid setup token.';
    $messageClass = 'danger';
    log_event('setup_token_invalid', 'Invalid setup token', null, null, $remoteIp);
  } elseif ($username === '' || $otp === '') {
    $message = 'Username and OTP secret are required.';
    $messageClass = 'danger';
  } else {
    $existing = fetch_user_by_user_ip($remoteIp);
    if ($existing) {
      save_user((int)$existing['id'], $username, $remoteIp, $otp, 'admin', max((int)$existing['accesslevel'], $access));
    } else {
      save_user(null, $username, $remoteIp, $otp, 'admin', $access);
    }
    log_event('setup_admin_created', 'Initial admin created via setup', null, $username, $remoteIp);
    header('Location: ' . url_for('login.php'));
    exit;
  }
}

$dbWritable = is_writable(dirname(DB_PATH));
$dbExists = file_exists(DB_PATH);

include view_path('header');
?>
<div class="row justify-content-center">
  <div class="col-lg-6">
    <div class="card shadow-sm">
      <div class="card-header">Initial setup</div>
      <div class="card-body">
        <p class="text-muted">Create the first admin for <?= htmlspecialchars($remoteIp) ?>. This page is disabled as soon as an admin exists.</p>
        <div class="mb-3">
          <span class="badge <?= $dbExists ? 'bg-success' : 'bg-secondary' ?>">File <?= htmlspecialchars(basename(DB_PATH)) ?></span>
          <span class="badge <?= $dbWritable ? 'bg-success' : 'bg-danger' ?>">Data dir writable</span>
        </div>
        <?php if ($message): ?>
          <div class="alert alert-<?= htmlspecialchars($messageClass) ?>" role="alert"><?= htmlspecialchars($message) ?></div>
        <?php endif; ?>
        <form method="post" novalidate>
          <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
          <?php if ($tokenRequired): ?>
            <div class="mb-3">
              <label class="form-label" for="setupToken">Setup token</label>
              <input type="password" name="setup_token" id="setupToken" class="form-control" required autocomplete="off">
            </div>
          <?php endif; ?>
          <div class="mb-3">
            <label class="form-label" for="setup-detected-user-ip">Detected user IP</label>
            <input id="setup-detected-user-ip" type="text" class="form-control" value="<?= htmlspecialchars($remoteIp) ?>" readonly>
          </div>
          <div class="mb-3">
            <label class="form-label" for="setup-username-display">Username (display)</label>
            <input id="setup-username-display" type="text" name="username" class="form-control" required>
          </div>
          <div class="mb-3">
            <label class="form-label" for="otpSecretSetup">OTP secret (Base32)</label>
            <div class="input-group">
              <input type="text" name="otp_secret" id="otpSecretSetup" class="form-control" value="<?= htmlspecialchars($prefillSecret) ?>" required>
              <button class="btn btn-outline-secondary" type="button" id="showQrBtn">Show OTP QR</button>
            </div>
          </div>
          <div class="mb-3">
            <label class="form-label" for="setup-access-level">Access level</label>
            <input id="setup-access-level" type="number" name="accesslevel" class="form-control" value="<?= (int)MAX_ACCESS_LEVEL ?>" min="0" max="<?= (int)MAX_ACCESS_LEVEL ?>">
          </div>
          <button type="submit" class="btn btn-primary">Save admin</button>
        </form>
        <hr>
        <p class="small text-muted mb-0">Alternatively create an admin on the command line: <code>php bin/create-admin.php</code>.</p>
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
<?php include view_path('footer');
