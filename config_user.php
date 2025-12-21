<?php
require_once __DIR__ . '/functions.php';
require_admin();

$networks = get_all_networks();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    if ($action === 'create') {
        save_user(null, trim($_POST['name'] ?? ''), trim($_POST['username'] ?? ''), trim($_POST['otp_secret'] ?? ''), isset($_POST['isadmin']) ? 1 : 0, (int)($_POST['accesslevel'] ?? 0));
    } elseif ($action === 'update') {
        $userId = (int)($_POST['id'] ?? 0);
        save_user($userId, trim($_POST['name'] ?? ''), trim($_POST['username'] ?? ''), trim($_POST['otp_secret'] ?? ''), isset($_POST['isadmin']) ? 1 : 0, (int)($_POST['accesslevel'] ?? 0));
        $networkIds = $_POST['network_ids'][$userId] ?? [];
        set_user_default_networks($userId, array_map('intval', $networkIds));
    } elseif ($action === 'delete') {
        delete_user((int)($_POST['id'] ?? 0));
    }
    header('Location: ' . url_for('config_user.php'));
    exit;
}

$users = db()->query('SELECT * FROM users ORDER BY username')->fetchAll(PDO::FETCH_ASSOC);
$newUserSecret = generate_otp_secret();
include __DIR__ . '/header.php';
?>
<div class="card shadow-sm mb-4">
  <div class="card-header">Add user</div>
  <div class="card-body">
    <form method="post" class="row g-3">
      <input type="hidden" name="action" value="create">
      <div class="col-md-3">
        <label class="form-label">Name</label>
        <input type="text" name="name" class="form-control" required>
      </div>
      <div class="col-md-3">
        <label class="form-label">Username (IP)</label>
        <input type="text" name="username" class="form-control" placeholder="10.0.0.1" required>
      </div>
      <div class="col-md-3">
        <label class="form-label">OTP secret (Base32)</label>
        <input type="text" name="otp_secret" class="form-control" value="<?= htmlspecialchars($newUserSecret) ?>" required>
      </div>
      <div class="col-md-2">
        <label class="form-label">Access level</label>
        <input type="number" name="accesslevel" class="form-control" min="0" value="0" required>
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
      <span>User: <?= htmlspecialchars($u['username']) ?></span>
      <form method="post" onsubmit="return confirm('Delete user?');">
        <input type="hidden" name="action" value="delete">
        <input type="hidden" name="id" value="<?= (int)$u['id'] ?>">
        <button class="btn btn-sm btn-outline-danger">Delete</button>
      </form>
    </div>
    <div class="card-body">
      <form method="post" class="row g-3">
        <input type="hidden" name="action" value="update">
        <input type="hidden" name="id" value="<?= (int)$u['id'] ?>">
        <div class="col-md-3">
          <label class="form-label">Name</label>
          <input type="text" name="name" class="form-control" value="<?= htmlspecialchars($u['name']) ?>" required>
        </div>
        <div class="col-md-3">
          <label class="form-label">Username (IP)</label>
          <input type="text" name="username" class="form-control" value="<?= htmlspecialchars($u['username']) ?>" required>
        </div>
        <div class="col-md-3">
          <label class="form-label">OTP secret (Base32)</label>
          <input type="text" name="otp_secret" class="form-control" value="<?= htmlspecialchars($u['otp_secret']) ?>" required>
        </div>
        <div class="col-md-2">
          <label class="form-label">Access level</label>
          <input type="number" name="accesslevel" class="form-control" min="0" value="<?= (int)$u['accesslevel'] ?>" required>
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
              data-username="<?= htmlspecialchars($u['username']) ?>"
              data-name="<?= htmlspecialchars($u['name']) ?>">Show OTP QR</button>
          </div>
        </div>
      </form>
    </div>
  </div>
<?php endforeach; ?>

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
  const modalEl = document.getElementById('qrModal');
  const modalTitle = document.getElementById('qrTitle');
  const modalBody = document.getElementById('qrBody');
  if (!modalEl || !window.bootstrap) return;
  const bsModal = new bootstrap.Modal(modalEl);

  const ISSUER = <?= json_encode(OTP_ISSUER) ?>;
  const DIGITS = <?= (int)OTP_DIGITS ?>;
  const PERIOD = <?= (int)OTP_STEP ?>;

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

<?php include __DIR__ . '/footer.php'; ?>
