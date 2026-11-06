<?php
// Own profile. Superusers and admins choose their own default networks here (only networks within their
// access level); users see theirs read-only. Durations and theme settings follow in the next phases.
require_once __DIR__ . '/../src/bootstrap.php';
require_login();
$user = current_user();

ensure_session();
$flash = $_SESSION['profile_flash'] ?? null;
unset($_SESSION['profile_flash']);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_csrf_token($_POST['csrf_token'] ?? null);
    $action = $_POST['action'] ?? '';
    if ($action === 'save_default_networks') {
        if (!can($user, 'edit_own_default_networks')) {
            http_response_code(403);
            echo 'Forbidden';
            exit;
        }
        $ids = is_array($_POST['network_ids'] ?? null) ? $_POST['network_ids'] : [];
        $result = set_own_default_networks($user, $ids);
        $byId = array_column(get_all_networks(), 'name', 'id');
        $names = array_map(fn($id) => $byId[$id] ?? ('#' . $id), $result['saved']);
        log_event('own_default_networks_updated', 'Default networks: ' . ($names ? implode(', ', $names) : '(none)'), (int)$user['id'], $user['username'], $user['user_ip']);
        $_SESSION['profile_flash'] = $result['rejected']
            ? ['type' => 'warning', 'message' => 'Saved. Networks above your access level were ignored.']
            : ['type' => 'success', 'message' => 'Default networks saved.'];
    }
    header('Location: ' . url_for('profile.php'));
    exit;
}

$canEditDefaults = can($user, 'edit_own_default_networks');
$defaultIds = get_user_default_network_ids((int)$user['id']);
$defaultNetworks = get_default_networks_for_user((int)$user['id']);
$eligible = eligible_networks_for_user($user);
$ineligibleDefaults = array_values(array_filter($defaultNetworks, fn($n) => !user_can_access_network($user, $n)));

function format_duration_human(int $seconds): string
{
    $h = intdiv($seconds, 3600);
    $m = intdiv($seconds % 3600, 60);
    return trim(($h ? $h . ' h ' : '') . ($m ? $m . ' min' : '')) ?: '0 min';
}

include view_path('header');
?>
<div class="row g-4">
  <div class="col-lg-4">
    <div class="card shadow-sm">
      <div class="card-header">Account</div>
      <div class="card-body">
        <dl class="row mb-0">
          <dt class="col-5">Name</dt><dd class="col-7"><?= htmlspecialchars($user['username']) ?></dd>
          <dt class="col-5">IP</dt><dd class="col-7"><code><?= htmlspecialchars($user['user_ip']) ?></code></dd>
          <dt class="col-5">Role</dt><dd class="col-7" data-testid="profile-role"><?= htmlspecialchars(role_label((string)user_role($user))) ?></dd>
          <dt class="col-5">Access level</dt><dd class="col-7">L<?= (int)$user['accesslevel'] ?></dd>
          <dt class="col-5">Default access</dt><dd class="col-7"><?= htmlspecialchars(format_duration_human((int)$user['default_duration_sec'])) ?></dd>
          <dt class="col-5">Extended access</dt><dd class="col-7 mb-0"><?= htmlspecialchars(format_duration_human((int)$user['extended_duration_sec'])) ?></dd>
        </dl>
      </div>
    </div>
  </div>

  <div class="col-lg-8">
    <div class="card shadow-sm">
      <div class="card-header d-flex justify-content-between align-items-center">
        <span>Default networks</span>
        <span class="text-muted small">granted together by “Grant default access”</span>
      </div>
      <div class="card-body">
        <?php if ($flash): ?>
          <div class="alert alert-<?= htmlspecialchars($flash['type']) ?>" role="alert"><?= htmlspecialchars($flash['message']) ?></div>
        <?php endif; ?>

        <?php if ($canEditDefaults): ?>
          <?php if (empty($eligible)): ?>
            <p class="text-muted mb-0">No networks within your access level.</p>
          <?php else: ?>
            <form method="post">
              <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
              <input type="hidden" name="action" value="save_default_networks">
              <div class="table-responsive">
                <table class="table table-sm align-middle">
                  <thead>
                    <tr><th style="width: 3rem;">Default</th><th>Name</th><th>Address</th><th>Level</th></tr>
                  </thead>
                  <tbody>
                    <?php foreach ($eligible as $n): $nid = (int)$n['id']; ?>
                      <tr>
                        <td><input class="form-check-input" type="checkbox" name="network_ids[]" value="<?= $nid ?>" id="own-net-<?= $nid ?>" <?= in_array($nid, $defaultIds, true) ? 'checked' : '' ?> aria-label="Default: <?= htmlspecialchars($n['name']) ?>"></td>
                        <td><label for="own-net-<?= $nid ?>"><?= htmlspecialchars($n['name']) ?></label></td>
                        <td><code><?= htmlspecialchars($n['address']) ?></code></td>
                        <td>L<?= (int)$n['accesslevel'] ?></td>
                      </tr>
                    <?php endforeach; ?>
                  </tbody>
                </table>
              </div>
              <?php if ($ineligibleDefaults): ?>
                <div class="alert alert-warning small">
                  Assigned by an admin but above your access level (not granted, removed when you save):
                  <?= htmlspecialchars(implode(', ', array_column($ineligibleDefaults, 'name'))) ?>
                </div>
              <?php endif; ?>
              <button class="btn btn-primary" type="submit">Save default networks</button>
            </form>
          <?php endif; ?>
        <?php else: ?>
          <?php if (empty($defaultNetworks)): ?>
            <p class="text-muted">No default networks configured for you.</p>
          <?php else: ?>
            <ul class="list-group mb-3">
              <?php foreach ($defaultNetworks as $n): ?>
                <li class="list-group-item d-flex justify-content-between">
                  <span><?= htmlspecialchars($n['name']) ?> <code class="ms-2"><?= htmlspecialchars($n['address']) ?></code></span>
                  <span class="badge bg-secondary">L<?= (int)$n['accesslevel'] ?></span>
                </li>
              <?php endforeach; ?>
            </ul>
          <?php endif; ?>
          <p class="text-muted small mb-0">Your default networks are managed by your admin.</p>
        <?php endif; ?>
      </div>
    </div>
  </div>
</div>
<?php include view_path('footer'); ?>
