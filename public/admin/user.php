<?php
// Admin: one user with the tabs Account · Default networks · Durations · OTP. Each tab saves on its own.
// The OTP secret is only sent to the browser after "Reveal" (api.php?f=revealOtp, logged).
require_once __DIR__ . '/../../src/bootstrap.php';
require_permission('manage_users');

ensure_session();
$admin = current_user();
$target = fetch_user_by_id((int)($_GET['id'] ?? 0));
if (!$target) {
    http_response_code(404);
    include view_path('header');
    echo '<div class="alert alert-warning" role="alert">User not found. <a href="' . e(url_for('admin/users.php')) . '" class="alert-link">Back to users</a></div>';
    include view_path('footer');
    exit;
}
$uid = (int)$target['id'];
$self = url_for('admin/user.php') . '?id=' . $uid;
$isSelf = $uid === (int)$admin['id'];
$flash = $_SESSION['user_flash'] ?? null;
unset($_SESSION['user_flash']);

$tab = 'account';
$account = ['username' => $target['username'], 'user_ip' => $target['user_ip'], 'role' => $target['role'], 'accesslevel' => (string)(int)$target['accesslevel'],
    'email' => (string)($target['email'] ?? ''), 'notify_alerts' => (int)($target['notify_alerts'] ?? 1) === 1];
$accountErrors = [];
$durationErrors = [];
$durationInput = [
    'default' => format_duration_input(user_grant_duration($target, 'default')),
    'extended' => format_duration_input(user_grant_duration($target, 'extended')),
];
$otpErrors = [];

/** PRG: flash message and back to a tab of this page. */
$done = static function (string $type, string $message, string $anchor) use ($self): void {
    $_SESSION['user_flash'] = ['type' => $type, 'message' => $message];
    header('Location: ' . $self . '#' . $anchor);
    exit;
};

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_csrf_token($_POST['csrf_token'] ?? null);
    switch ($_POST['action'] ?? '') {
        case 'save_account':
            $tab = 'account';
            $account = [
                'username' => trim((string)($_POST['username'] ?? '')),
                'user_ip' => trim((string)($_POST['user_ip'] ?? '')),
                'role' => (string)($_POST['role'] ?? ''),
                'accesslevel' => (string)(int)($_POST['accesslevel'] ?? 0),
                'email' => trim((string)($_POST['email'] ?? '')),
                'notify_alerts' => !empty($_POST['notify_alerts']),
            ];
            $accountErrors = validate_user_account($uid, $account['username'], $account['user_ip']);
            if ($account['email'] !== '' && !filter_var($account['email'], FILTER_VALIDATE_EMAIL)) {
                $accountErrors[] = 'Not a valid e-mail address.';
            }
            if (!is_valid_role($account['role'])) {
                $accountErrors[] = 'Invalid role.';
            } elseif (would_remove_last_admin($target, $account['role'])) {
                $accountErrors[] = 'The last admin cannot be demoted – otherwise the setup page would re-open.';
            }
            if ($accountErrors) {
                break;
            }
            update_user_account($uid, $account['username'], $account['user_ip'], $account['role'], (int)$account['accesslevel']);
            update_user_contact($uid, $account['email'], $account['notify_alerts']);
            $updated = fetch_user_by_id($uid);
            $changes = [];
            foreach (['username' => 'name', 'user_ip' => 'IP', 'role' => 'role', 'accesslevel' => 'level', 'email' => 'e-mail'] as $field => $label) {
                if ((string)$target[$field] !== (string)$updated[$field]) {
                    $changes[] = $label . ' ' . $target[$field] . ' -> ' . $updated[$field];
                }
            }
            if ($changes) {
                log_event('user_updated', implode(', ', $changes) . ' by ' . $admin['username'], $uid, $updated['username'], $updated['user_ip']);
            }
            if ($target['role'] !== $updated['role']) {
                log_event('user_role_changed', $target['role'] . ' -> ' . $updated['role'], $uid, $updated['username'], $updated['user_ip'], ['from' => $target['role'], 'to' => $updated['role']]);
            }
            $invalid = ineligible_default_networks($updated);
            if ($invalid) {
                $done('warning', 'Account saved. ' . count($invalid) . ' default network(s) are above level L' . (int)$updated['accesslevel'] . ' and will not be granted: ' . implode(', ', array_column($invalid, 'name')) . '.', 'account');
            }
            $done('success', 'Account saved.', 'account');
            // no break
        case 'save_durations':
            $tab = 'durations';
            $durationInput = ['default' => trim((string)($_POST['default_duration'] ?? '')), 'extended' => trim((string)($_POST['extended_duration'] ?? ''))];
            $durationErrors = update_user_durations($target, parse_duration_input($durationInput['default']), parse_duration_input($durationInput['extended']));
            if (!$durationErrors) {
                $done('success', 'Durations saved.', 'durations');
            }
            break;
        case 'set_otp':
            $tab = 'otp';
            $secret = strtoupper(str_replace(' ', '', trim((string)($_POST['otp_secret'] ?? ''))));
            $generated = $secret === '';
            if ($generated) {
                $secret = generate_otp_secret();
            } elseif (!is_valid_otp_secret($secret)) {
                $otpErrors[] = 'OTP secret must be Base32 (A–Z, 2–7), at least 16 characters – or empty to generate one.';
                break;
            }
            set_user_otp_secret($uid, $secret);
            log_event('otp_secret_changed', 'New OTP secret (' . ($generated ? 'generated' : 'entered') . ') by ' . $admin['username'], $uid, $target['username'], $target['user_ip']);
            $done('success', 'New OTP secret saved. Reveal it to set up the authenticator app – codes of the old secret no longer work.', 'otp');
            // no break
        case 'delete':
            if (would_remove_last_admin($target, null)) {
                $done('danger', 'The last admin cannot be deleted – otherwise the setup page would re-open.', 'account');
            }
            delete_user($uid);
            log_event('user_deleted', 'Deleted ' . $target['username'] . ' (' . $target['user_ip'] . ') by ' . $admin['username'], null, $target['username'], $target['user_ip']);
            $_SESSION['user_flash'] = ['type' => 'success', 'message' => 'User ' . $target['username'] . ' deleted.'];
            header('Location: ' . url_for($isSelf ? 'logout.php' : 'admin/users.php'));
            exit;
        case 'impersonate':
            if (!$isSelf) {
                start_impersonation($admin, $target);
                header('Location: ' . url_for('index.php'));
                exit;
            }
            break;
        default:
            http_response_code(400);
            echo 'Unknown action';
            exit;
    }
    http_response_code(422); // re-render the tab with its errors
}

$invalidDefaults = ineligible_default_networks($target);
$tabs = ['account' => 'Account', 'networks' => 'Default networks', 'durations' => 'Durations', 'otp' => 'OTP'];
$pageScripts = ['js/kjua.min.js', 'js/otp-qr.js', 'js/durations.js', 'js/default-networks.js', 'js/user-admin.js'];
include view_path('header');
?>
<div class="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-3">
  <div>
    <a href="<?= e(url_for('admin/users.php')) ?>" class="small">&larr; Users</a>
    <h1 class="h4 mb-0"><?= e($target['username']) ?> <code class="fs-6"><?= e($target['user_ip']) ?></code>
      <span class="badge <?= role_badge_class($target['role']) ?> fs-6 align-middle"><?= e(role_label($target['role'])) ?></span>
      <span class="badge text-bg-light border fs-6 align-middle">L<?= (int)$target['accesslevel'] ?></span>
    </h1>
  </div>
  <?php if (!$isSelf): ?>
    <form method="post" data-confirm="Act as <?= e($target['username']) ?>? You can return to your admin account at any time.">
      <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
      <input type="hidden" name="action" value="impersonate">
      <button class="btn btn-outline-primary">Impersonate</button>
    </form>
  <?php endif; ?>
</div>

<?php if ($flash): ?>
  <div class="alert alert-<?= e($flash['type']) ?>" role="alert"><?= e($flash['message']) ?></div>
<?php endif; ?>

<ul class="nav nav-tabs" role="tablist" data-user-tabs>
  <?php foreach ($tabs as $key => $label): ?>
    <li class="nav-item" role="presentation">
      <button class="nav-link <?= $tab === $key ? 'active' : '' ?>" id="tab-<?= $key ?>" data-bs-toggle="tab" data-bs-target="#pane-<?= $key ?>" data-hash="<?= $key ?>"
              type="button" role="tab" aria-controls="pane-<?= $key ?>" aria-selected="<?= $tab === $key ? 'true' : 'false' ?>">
        <?= e($label) ?><?php if ($key === 'networks' && $invalidDefaults): ?> <span class="badge text-bg-warning"><?= count($invalidDefaults) ?></span><?php endif; ?>
      </button>
    </li>
  <?php endforeach; ?>
</ul>
<div class="tab-content card card-body border-top-0 rounded-top-0 shadow-sm mb-4">
  <div class="tab-pane fade <?= $tab === 'account' ? 'show active' : '' ?>" id="pane-account" role="tabpanel" aria-labelledby="tab-account" tabindex="0">
    <?php if ($accountErrors): ?>
      <div class="alert alert-danger" role="alert"><?= e(implode(' ', $accountErrors)) ?></div>
    <?php endif; ?>
    <?php if ($invalidDefaults): ?>
      <div class="alert alert-warning small" role="status">
        Default networks above level L<?= (int)$target['accesslevel'] ?> (not granted): <?= e(implode(', ', array_column($invalidDefaults, 'name'))) ?>.
      </div>
    <?php endif; ?>
    <form method="post" class="row g-3" autocomplete="off">
      <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
      <input type="hidden" name="action" value="save_account">
      <div class="col-md-4">
        <label class="form-label" for="acc-username">Name</label>
        <input id="acc-username" type="text" name="username" class="form-control" value="<?= e($account['username']) ?>" required>
      </div>
      <div class="col-md-3">
        <label class="form-label" for="acc-user-ip">User IP (login)</label>
        <input id="acc-user-ip" type="text" name="user_ip" class="form-control" value="<?= e($account['user_ip']) ?>" required>
      </div>
      <div class="col-md-3">
        <label class="form-label" for="acc-role">Role</label>
        <select id="acc-role" name="role" class="form-select">
          <?php foreach (ROLES as $r): ?>
            <option value="<?= e($r) ?>" <?= $account['role'] === $r ? 'selected' : '' ?>><?= e(role_label($r)) ?></option>
          <?php endforeach; ?>
        </select>
      </div>
      <div class="col-md-2">
        <label class="form-label" for="acc-level">Access level</label>
        <input id="acc-level" type="number" name="accesslevel" class="form-control" min="0" max="<?= (int)MAX_ACCESS_LEVEL ?>" value="<?= e($account['accesslevel']) ?>" required>
      </div>
      <div class="col-md-6">
        <label class="form-label" for="acc-email">E-mail (security notifications)</label>
        <input id="acc-email" type="email" name="email" class="form-control" value="<?= e($account['email']) ?>">
      </div>
      <div class="col-md-6 d-flex align-items-end">
        <div class="form-check mb-2">
          <input class="form-check-input" type="checkbox" name="notify_alerts" value="1" id="acc-notify" <?= $account['notify_alerts'] ? 'checked' : '' ?>>
          <label class="form-check-label" for="acc-notify">Send alert mails<?= $target['role'] === 'admin' ? ' (admins get all alerts)' : ' (“Was this you?”)' ?></label>
        </div>
      </div>
      <div class="col-12">
        <button class="btn btn-primary" type="submit">Save account</button>
      </div>
    </form>
    <hr>
    <form method="post" data-confirm="Delete <?= e($target['username']) ?>? This cannot be undone.">
      <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
      <input type="hidden" name="action" value="delete">
      <button class="btn btn-outline-danger btn-sm">Delete user</button>
    </form>
  </div>

  <div class="tab-pane fade" id="pane-networks" role="tabpanel" aria-labelledby="tab-networks" tabindex="0">
    <p class="text-muted small">Granted together by “Grant default access”. Changes are saved immediately. Only networks up to level L<?= (int)$target['accesslevel'] ?> can be added.</p>
    <?php $dnUser = $target; include view_path('partials/default_networks_editor'); ?>
  </div>

  <div class="tab-pane fade <?= $tab === 'durations' ? 'show active' : '' ?>" id="pane-durations" role="tabpanel" aria-labelledby="tab-durations" tabindex="0">
    <div class="col-lg-6" id="durations">
      <?php
        $dfAction = $self;
        $dfInput = $durationInput;
        $dfErrors = $durationErrors;
        include view_path('partials/duration_form');
      ?>
    </div>
  </div>

  <div class="tab-pane fade <?= $tab === 'otp' ? 'show active' : '' ?>" id="pane-otp" role="tabpanel" aria-labelledby="tab-otp" tabindex="0">
    <?php if ($otpErrors): ?>
      <div class="alert alert-danger" role="alert"><?= e(implode(' ', $otpErrors)) ?></div>
    <?php endif; ?>
    <p class="text-muted">The secret is hidden. Revealing it is recorded in the audit log.</p>
    <button type="button" class="btn btn-outline-primary" data-otp-reveal="<?= $uid ?>">Reveal secret and QR code</button>
    <div class="mt-3" data-otp-output hidden>
      <p class="mb-2">Secret: <code data-otp-secret class="user-select-all"></code></p>
      <div class="otp-qr mb-2" data-otp-qr></div>
      <button type="button" class="btn btn-sm btn-outline-secondary" data-otp-hide>Hide</button>
    </div>
    <hr>
    <form method="post" class="row g-2 align-items-end" autocomplete="off"
          data-confirm="Replace the OTP secret of <?= e($target['username']) ?>? The authenticator app must be set up again.">
      <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
      <input type="hidden" name="action" value="set_otp">
      <div class="col-md-6">
        <label class="form-label" for="otp-new">New secret (Base32, empty = generate)</label>
        <input id="otp-new" type="text" name="otp_secret" class="form-control" autocomplete="off" spellcheck="false">
      </div>
      <div class="col-md-3">
        <button class="btn btn-outline-danger" type="submit">Replace secret</button>
      </div>
    </form>
  </div>
</div>
<?php include view_path('footer'); ?>
