<?php
// Admin: user list (sortable, filterable), add user, backup. Editing happens on admin/user.php.
// OTP secrets are never part of this page – they are shown on the user page after "Reveal" only.
require_once __DIR__ . '/../../src/bootstrap.php';
require_once __DIR__ . '/../../src/backup.php';
require_permission('manage_users');

ensure_session();
$admin = current_user();
$flash = $_SESSION['user_flash'] ?? null;
unset($_SESSION['user_flash']);
$form = ['username' => '', 'user_ip' => '', 'role' => 'user', 'accesslevel' => '5', 'otp_secret' => ''];
$formErrors = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_csrf_token($_POST['csrf_token'] ?? null);
    $action = $_POST['action'] ?? '';
    if ($action === 'create') {
        $form = [
            'username' => trim((string)($_POST['username'] ?? '')),
            'user_ip' => trim((string)($_POST['user_ip'] ?? '')),
            'role' => (string)($_POST['role'] ?? 'user'),
            'accesslevel' => (string)(int)($_POST['accesslevel'] ?? 0),
            'otp_secret' => strtoupper(str_replace(' ', '', trim((string)($_POST['otp_secret'] ?? '')))),
        ];
        $formErrors = validate_user_account(null, $form['username'], $form['user_ip']);
        if (!is_valid_role($form['role'])) {
            $formErrors[] = 'Invalid role.';
        }
        if ($form['otp_secret'] !== '' && !is_valid_otp_secret($form['otp_secret'])) {
            $formErrors[] = 'OTP secret must be Base32 (A–Z, 2–7), at least 16 characters – or empty to generate one.';
        }
        if (!$formErrors) {
            save_user(null, $form['username'], $form['user_ip'], $form['otp_secret'] !== '' ? $form['otp_secret'] : generate_otp_secret(), $form['role'], (int)$form['accesslevel']);
            $created = fetch_user_by_user_ip($form['user_ip']);
            log_event('user_created', 'Created ' . $created['username'] . ' (' . $created['user_ip'] . ') as ' . $created['role'] . ', L' . (int)$created['accesslevel'] . ' by ' . $admin['username'], (int)$created['id'], $created['username'], $created['user_ip']);
            $_SESSION['user_flash'] = ['type' => 'success', 'message' => 'User created. Reveal the OTP secret to set up the authenticator app, then choose the default networks.'];
            header('Location: ' . url_for('admin/user.php') . '?id=' . (int)$created['id'] . '#otp');
            exit;
        }
        http_response_code(422); // re-render with errors and input
    } elseif ($action === 'impersonate') {
        $target = fetch_user_by_id((int)($_POST['id'] ?? 0));
        if ($target && (int)$target['id'] !== (int)$admin['id']) {
            start_impersonation($admin, $target);
            header('Location: ' . url_for('index.php'));
            exit;
        }
    } elseif ($action === 'export_users') {
        header('Content-Type: application/json');
        header('Content-Disposition: attachment; filename="users.json"');
        echo export_users_json();
        exit;
    } elseif ($action === 'import_users') {
        $json = '';
        if (isset($_FILES['users_file']) && is_uploaded_file($_FILES['users_file']['tmp_name'])) {
            $json = (string)file_get_contents($_FILES['users_file']['tmp_name']);
        }
        if ($json === '') {
            $_SESSION['user_flash'] = ['type' => 'danger', 'message' => 'No file uploaded.'];
        } else {
            try {
                $result = import_users_json($json);
                $message = 'Imported ' . (int)$result['imported'] . ' new user(s).';
                if ($result['skipped_existing'] > 0) {
                    $message .= ' Skipped ' . (int)$result['skipped_existing'] . ' existing user_ip(s).';
                }
                if ($result['skipped_duplicate'] > 0) {
                    $message .= ' Skipped ' . (int)$result['skipped_duplicate'] . ' duplicate user_ip(s) in file.';
                }
                $_SESSION['user_flash'] = ['type' => 'success', 'message' => $message];
            } catch (Throwable $e) {
                $_SESSION['user_flash'] = ['type' => 'danger', 'message' => 'Import failed: ' . $e->getMessage()];
            }
        }
    }
    if (!$formErrors) {
        header('Location: ' . url_for('admin/users.php'));
        exit;
    }
}

$users = users_with_default_counts();
$access = current_accesses_by_users($users);
$lastLogins = last_logins_by_user_ip();
$pageScripts = [];
include view_path('header');
?>
<?php if ($flash): ?>
  <div class="alert alert-<?= e($flash['type']) ?>" role="alert"><?= e($flash['message']) ?></div>
<?php endif; ?>

<div class="card shadow-sm mb-4">
  <div class="card-header d-flex flex-wrap justify-content-between align-items-center gap-2">
    <span>Users <span class="badge text-bg-secondary"><?= count($users) ?></span></span>
    <div class="d-flex gap-2">
      <input type="search" class="form-control form-control-sm w-auto" placeholder="Filter users" aria-label="Filter users" data-table-filter="usersTable">
      <a class="btn btn-sm btn-outline-secondary" href="<?= e(url_for('admin/matrix.php')) ?>">Matrix</a>
    </div>
  </div>
  <div class="card-body">
    <?php if (!$access['success']): ?>
      <div class="alert alert-warning small" role="alert">Active grants unknown – router API error<?= !empty($access['error']) ? ': ' . e($access['error']) : '' ?>.</div>
    <?php endif; ?>
    <div class="table-responsive">
      <table class="table table-sm align-middle mb-0" id="usersTable" data-sortable>
        <thead>
          <tr>
            <th>Name</th>
            <th data-sort="ip">User IP</th>
            <th>Role</th>
            <th data-sort="number">Level</th>
            <th data-sort="number">Default networks</th>
            <th data-sort="number">Last login</th>
            <th data-sort="number">Active grants</th>
            <th data-sort="none" class="text-end"><span class="visually-hidden">Actions</span></th>
          </tr>
        </thead>
        <tbody>
          <?php foreach ($users as $u):
            $uid = (int)$u['id'];
            $entries = $access['success'] ? ($access['data'][$u['user_ip']] ?? []) : null;
            $last = $lastLogins[$u['user_ip']] ?? null;
            $invalid = (int)$u['invalid_default_count'];
          ?>
            <tr data-user-id="<?= $uid ?>">
              <td><a href="<?= e(url_for('admin/user.php')) ?>?id=<?= $uid ?>" class="fw-semibold"><?= e($u['username']) ?></a></td>
              <td><code><?= e($u['user_ip']) ?></code></td>
              <td><span class="badge <?= role_badge_class($u['role']) ?>"><?= e(role_label($u['role'])) ?></span></td>
              <td data-sort-value="<?= (int)$u['accesslevel'] ?>">L<?= (int)$u['accesslevel'] ?></td>
              <td data-sort-value="<?= (int)$u['default_count'] ?>">
                <a href="<?= e(url_for('admin/user.php')) ?>?id=<?= $uid ?>#networks"><?= (int)$u['default_count'] ?></a>
                <?php if ($invalid > 0): ?>
                  <span class="badge text-bg-warning ms-1" title="Above the user's level – not granted"><?= $invalid ?> above level</span>
                <?php endif; ?>
              </td>
              <td class="small" data-sort-value="<?= $last ?? '' ?>"><?= $last ? e(date('Y-m-d H:i', $last)) : '<span class="text-muted">never</span>' ?></td>
              <td data-sort-value="<?= $entries === null ? '' : count($entries) ?>"><?= $entries === null ? '?' : count($entries) ?></td>
              <td class="text-end text-nowrap">
                <a class="btn btn-sm btn-outline-secondary" href="<?= e(url_for('admin/user.php')) ?>?id=<?= $uid ?>" aria-label="Edit <?= e($u['username']) ?>">Edit</a>
                <?php if ($uid !== (int)$admin['id']): ?>
                  <form method="post" class="d-inline" data-confirm="Act as <?= e($u['username']) ?>? You can return to your admin account at any time.">
                    <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
                    <input type="hidden" name="action" value="impersonate">
                    <input type="hidden" name="id" value="<?= $uid ?>">
                    <button class="btn btn-sm btn-outline-primary" aria-label="Impersonate <?= e($u['username']) ?>">Impersonate</button>
                  </form>
                <?php endif; ?>
              </td>
            </tr>
          <?php endforeach; ?>
        </tbody>
      </table>
    </div>
  </div>
</div>

<div class="card shadow-sm mb-4" id="add-user">
  <div class="card-header">Add user</div>
  <div class="card-body">
    <?php if ($formErrors): ?>
      <div class="alert alert-danger" role="alert"><?= e(implode(' ', $formErrors)) ?></div>
    <?php endif; ?>
    <form method="post" class="row g-3" autocomplete="off">
      <input type="hidden" name="action" value="create">
      <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
      <div class="col-md-3">
        <label class="form-label" for="new-username">Name</label>
        <input id="new-username" type="text" name="username" class="form-control" value="<?= e($form['username']) ?>" required>
      </div>
      <div class="col-md-2">
        <label class="form-label" for="new-user-ip">User IP (login)</label>
        <input id="new-user-ip" type="text" name="user_ip" class="form-control" placeholder="10.0.0.1" value="<?= e($form['user_ip']) ?>" required>
      </div>
      <div class="col-md-2">
        <label class="form-label" for="new-role">Role</label>
        <select name="role" id="new-role" class="form-select">
          <?php foreach (ROLES as $r): ?>
            <option value="<?= e($r) ?>" <?= $form['role'] === $r ? 'selected' : '' ?>><?= e(role_label($r)) ?></option>
          <?php endforeach; ?>
        </select>
      </div>
      <div class="col-md-2">
        <label class="form-label" for="new-access-level">Access level</label>
        <input id="new-access-level" type="number" name="accesslevel" class="form-control" min="0" max="<?= (int)MAX_ACCESS_LEVEL ?>" value="<?= e($form['accesslevel']) ?>" required>
      </div>
      <div class="col-md-3">
        <label class="form-label" for="new-otp-secret">OTP secret (optional)</label>
        <input id="new-otp-secret" type="text" name="otp_secret" class="form-control" placeholder="empty = generate" value="<?= e($form['otp_secret']) ?>" autocomplete="off" spellcheck="false">
      </div>
      <div class="col-12">
        <button class="btn btn-primary" type="submit">Add user</button>
      </div>
    </form>
  </div>
</div>

<div class="card shadow-sm mb-4">
  <div class="card-header">Backup users</div>
  <div class="card-body">
    <div class="mb-3">
      <h2 class="h6 mb-2">Export</h2>
      <form method="post" class="d-inline">
        <input type="hidden" name="action" value="export_users">
        <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
        <button class="btn btn-outline-primary">Export users (JSON)</button>
      </form>
      <p class="text-muted small mt-2 mb-0">The export contains the OTP secrets – store it safely.</p>
    </div>
    <hr class="my-3">
    <div>
      <h2 class="h6 mb-2">Import</h2>
      <form method="post" enctype="multipart/form-data" class="row g-2 align-items-center">
        <input type="hidden" name="action" value="import_users">
        <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
        <div class="col-sm-7 col-md-6">
          <input type="file" name="users_file" accept="application/json" class="form-control" required aria-label="Users file (JSON)">
        </div>
        <div class="col-sm-3 col-md-3">
          <button class="btn btn-outline-success w-100" type="submit">Import</button>
        </div>
      </form>
      <p class="text-muted small mt-2 mb-0">Import adds users whose user_ip is not already present; existing user_ips are skipped. New users have no default networks.</p>
    </div>
  </div>
</div>
<?php include view_path('footer'); ?>
