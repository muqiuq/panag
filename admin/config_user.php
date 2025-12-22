<?php
require_once __DIR__ . '/../lib/functions.php';
require_once __DIR__ . '/../lib/backup.php';
require_admin();

ensure_session();
$flash = $_SESSION['user_flash'] ?? null;
unset($_SESSION['user_flash']);

$networks = get_all_networks();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  require_csrf_token($_POST['csrf_token'] ?? null);
  $action = $_POST['action'] ?? '';
  if ($action === 'create') {
    save_user(null, trim($_POST['username'] ?? ''), trim($_POST['user_ip'] ?? ''), trim($_POST['otp_secret'] ?? ''), isset($_POST['isadmin']) ? 1 : 0, (int)($_POST['accesslevel'] ?? 0));
  } elseif ($action === 'update') {
    $userId = (int)($_POST['id'] ?? 0);
    save_user($userId, trim($_POST['username'] ?? ''), trim($_POST['user_ip'] ?? ''), trim($_POST['otp_secret'] ?? ''), isset($_POST['isadmin']) ? 1 : 0, (int)($_POST['accesslevel'] ?? 0));
    $networkIds = $_POST['network_ids'][$userId] ?? [];
    set_user_default_networks($userId, array_map('intval', $networkIds));
  } elseif ($action === 'delete') {
    delete_user((int)($_POST['id'] ?? 0));
  } elseif ($action === 'impersonate') {
    $targetId = (int)($_POST['id'] ?? 0);
    $target = fetch_user_by_id($targetId);
    $admin = current_user();
    if ($target && $admin) {
      ensure_session();
      $_SESSION['impersonator_id'] = (int)$admin['id'];
      $_SESSION['user_id'] = (int)$target['id'];
      log_event('impersonate_start', 'Impersonate as ' . ($target['username'] ?? 'unknown') . ' (' . ($target['user_ip'] ?? '') . ')', (int)$admin['id'], $admin['username'] ?? null, $admin['user_ip'] ?? null);
    }
    header('Location: ' . url_for('index.php'));
    exit;
  } elseif ($action === 'export_users') {
    $json = export_users_json();
    header('Content-Type: application/json');
    header('Content-Disposition: attachment; filename="users.json"');
    echo $json;
    exit;
  } elseif ($action === 'import_users') {
    $json = '';
    if (isset($_FILES['users_file']) && is_uploaded_file($_FILES['users_file']['tmp_name'])) {
      $json = file_get_contents($_FILES['users_file']['tmp_name']);
    }
    if ($json === '') {
      $_SESSION['user_flash'] = ['type' => 'danger', 'message' => 'No file uploaded.'];
    } else {
      try {
        $result = import_users_json($json);
        $imported = (int)($result['imported'] ?? 0);
        $skippedExisting = (int)($result['skipped_existing'] ?? 0);
        $skippedDuplicate = (int)($result['skipped_duplicate'] ?? 0);
        $message = 'Imported ' . $imported . ' new user(s).';
        if ($skippedExisting > 0) {
          $message .= ' Skipped ' . $skippedExisting . ' existing user_ip(s).';
        }
        if ($skippedDuplicate > 0) {
          $message .= ' Skipped ' . $skippedDuplicate . ' duplicate user_ip(s) in file.';
        }
        $_SESSION['user_flash'] = ['type' => 'success', 'message' => $message];
      } catch (Throwable $e) {
        $_SESSION['user_flash'] = ['type' => 'danger', 'message' => 'Import failed: ' . $e->getMessage()];
      }
    }
  }
  header('Location: ' . url_for('admin/config_user.php'));
  exit;
}

$users = db()->query('SELECT * FROM users ORDER BY user_ip')->fetchAll(PDO::FETCH_ASSOC);
$newUserSecret = generate_otp_secret();
include __DIR__ . '/../lib/header.php';
?>
<div class="card shadow-sm mb-4">
  <div class="card-header">Add user</div>
  <div class="card-body">
    <?php if ($flash): ?>
      <div class="alert alert-<?= htmlspecialchars($flash['type']) ?>" role="alert"><?= htmlspecialchars($flash['message']) ?></div>
    <?php endif; ?>
    <form method="post" class="row g-3" autocomplete="off">
      <input type="hidden" name="action" value="create">
      <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
      <div class="col-md-3">
        <label class="form-label">Username (display)</label>
        <input type="text" name="username" class="form-control" required autocomplete="off">
      </div>
      <div class="col-md-3">
        <label class="form-label">User IP (login)</label>
        <input type="text" name="user_ip" class="form-control" placeholder="10.0.0.1" required autocomplete="off">
      </div>
      <div class="col-md-3">
        <label class="form-label">OTP secret (Base32)</label>
        <div class="input-group">
          <input type="password" name="otp_secret" id="otpSecretNew" class="form-control otp-secret" value="<?= htmlspecialchars($newUserSecret) ?>" required autocomplete="new-password">
          <button class="btn btn-outline-secondary otp-toggle" type="button" data-target="otpSecretNew">Show</button>
        </div>
      </div>
      <div class="col-md-2">
        <label class="form-label">Access level</label>
        <input type="number" name="accesslevel" class="form-control" min="0" max="<?= (int)MAX_ACCESS_LEVEL ?>" value="10" required>
      </div>
      <div class="col-md-1 d-flex align-items-end">
        <div class="form-check">
          <input class="form-check-input" type="checkbox" name="isadmin" id="adminNew">
          <label class="form-check-label" for="adminNew">Admin</label>
        </div>
      </div>
      <div class="col-12">
        <button class="btn btn-primary" type="submit">Add user</button>
      </div>
    </form>
  </div>
</div>

<?php foreach ($users as $u): $defaults = get_user_default_network_ids($u['id']); ?>
  <div class="card shadow-sm mb-3">
    <div class="card-header d-flex justify-content-between align-items-center">
      <span>User: <?= htmlspecialchars($u['username']) ?> (<?= htmlspecialchars($u['user_ip']) ?>)</span>
      <div class="d-flex gap-2">
        <form method="post" onsubmit="return confirm('Impersonate this user?');">
          <input type="hidden" name="action" value="impersonate">
          <input type="hidden" name="id" value="<?= (int)$u['id'] ?>">
          <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
          <button class="btn btn-sm btn-outline-primary">Impersonate</button>
        </form>
        <form method="post" onsubmit="return confirm('Delete user?');">
          <input type="hidden" name="action" value="delete">
          <input type="hidden" name="id" value="<?= (int)$u['id'] ?>">
          <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
          <button class="btn btn-sm btn-outline-danger">Delete</button>
        </form>
      </div>
    </div>
    <div class="card-body">
      <form method="post" class="row g-3" autocomplete="off">
        <input type="hidden" name="action" value="update">
        <input type="hidden" name="id" value="<?= (int)$u['id'] ?>">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
        <div class="col-md-3">
          <label class="form-label">Username (display)</label>
          <input type="text" name="username" class="form-control" value="<?= htmlspecialchars($u['username']) ?>" required autocomplete="off">
        </div>
        <div class="col-md-3">
          <label class="form-label">User IP (login)</label>
          <input type="text" name="user_ip" class="form-control" value="<?= htmlspecialchars($u['user_ip']) ?>" required autocomplete="off">
        </div>
        <div class="col-md-3">
          <label class="form-label">OTP secret (Base32)</label>
          <?php $otpId = 'otpSecret' . (int)$u['id']; ?>
          <div class="input-group">
            <input type="password" name="otp_secret" id="<?= $otpId ?>" class="form-control otp-secret" value="<?= htmlspecialchars($u['otp_secret']) ?>" required autocomplete="new-password">
            <button class="btn btn-outline-secondary otp-toggle" type="button" data-target="<?= $otpId ?>">Show</button>
          </div>
        </div>
        <div class="col-md-2">
          <label class="form-label">Access level</label>
          <input type="number" name="accesslevel" class="form-control" min="0" max="<?= (int)MAX_ACCESS_LEVEL ?>" value="<?= (int)$u['accesslevel'] ?>" required>
        </div>
        <div class="col-md-1 d-flex align-items-end">
          <div class="form-check">
            <input class="form-check-input" type="checkbox" name="isadmin" id="admin<?= (int)$u['id'] ?>" <?= (int)$u['isadmin'] === 1 ? 'checked' : '' ?>>
            <label class="form-check-label" for="admin<?= (int)$u['id'] ?>">Admin</label>
          </div>
        </div>
        <div class="col-12">
          <label class="form-label">Default networks</label>
          <div class="row g-2">
            <?php foreach ($networks as $n): ?>
              <div class="col-md-4">
                <div class="form-check">
                  <input class="form-check-input" type="checkbox" name="network_ids[<?= (int)$u['id'] ?>][]" value="<?= (int)$n['id'] ?>" id="net<?= (int)$u['id'] ?>-<?= (int)$n['id'] ?>" <?= in_array((int)$n['id'], $defaults, true) ? 'checked' : '' ?>>
                  <label class="form-check-label" for="net<?= (int)$u['id'] ?>-<?= (int)$n['id'] ?>">
                    <?= htmlspecialchars($n['name']) ?> (<?= htmlspecialchars($n['address']) ?>)
                  </label>
                </div>
              </div>
            <?php endforeach; ?>
          </div>
        </div>
        <div class="col-12">
          <div class="d-flex gap-2">
            <button class="btn btn-success" type="submit">Save</button>
            <button class="btn btn-outline-secondary qr-btn" type="button"
              data-secret="<?= htmlspecialchars($u['otp_secret']) ?>"
              data-username="<?= htmlspecialchars($u['user_ip']) ?>"
              data-name="<?= htmlspecialchars($u['username']) ?>">Show OTP QR</button>
          </div>
        </div>
      </form>
    </div>
  </div>
<?php endforeach; ?>

<div class="card shadow-sm mb-4">
  <div class="card-header">Backup users</div>
  <div class="card-body">
    <div class="mb-3">
      <h6 class="mb-2">Export</h6>
      <form method="post" class="d-inline">
        <input type="hidden" name="action" value="export_users">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
        <button class="btn btn-outline-primary">Export users (JSON)</button>
      </form>
    </div>
    <hr class="my-3">
    <div>
      <h6 class="mb-2">Import</h6>
      <form method="post" enctype="multipart/form-data" class="row g-2 align-items-center">
        <input type="hidden" name="action" value="import_users">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
        <div class="col-sm-7 col-md-6">
          <input type="file" name="users_file" accept="application/json" class="form-control" required>
        </div>
        <div class="col-sm-3 col-md-3">
          <button class="btn btn-outline-success w-100" type="submit">Import</button>
        </div>
      </form>
      <p class="text-muted small mt-2 mb-0">Import adds users whose user_ip is not already present; existing user_ips are skipped. New users have no default networks.</p>
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
  const buttons = document.querySelectorAll('.qr-btn');
  const toggleButtons = document.querySelectorAll('.otp-toggle');
  const modalEl = document.getElementById('qrModal');
  const modalTitle = document.getElementById('qrTitle');
  const modalBody = document.getElementById('qrBody');
  if (!modalEl || !window.bootstrap) return;
  const bsModal = new bootstrap.Modal(modalEl);

  const ISSUER = <?= json_encode(OTP_ISSUER) ?>;
  const DIGITS = <?= (int)OTP_DIGITS ?>;
  const PERIOD = <?= (int)OTP_STEP ?>;

  toggleButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.dataset.target;
      if (!targetId) return;
      const input = document.getElementById(targetId);
      if (!input) return;
      const isHidden = input.type === 'password';
      input.type = isHidden ? 'text' : 'password';
      btn.textContent = isHidden ? 'Hide' : 'Show';
    });
  });

  buttons.forEach(btn => {
    btn.addEventListener('click', () => {
      const secret = btn.dataset.secret;
      const username = btn.dataset.username;
      const name = btn.dataset.name;
      if (!secret || !username) return;
      const label = encodeURIComponent(`${ISSUER}:${username}`);
      const issuer = encodeURIComponent(ISSUER);
      const otpUrl = `otpauth://totp/${label}?secret=${encodeURIComponent(secret)}&issuer=${issuer}&digits=${DIGITS}&period=${PERIOD}`;

      modalTitle.textContent = `OTP for ${name} (${username})`;
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
});
</script>

<?php include __DIR__ . '/../lib/footer.php'; ?>
