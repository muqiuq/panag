<?php
// Own profile: access durations (all roles), default networks (superusers/admins choose their own, only
// networks within their access level; users see theirs read-only). Theme settings follow in phase 4.
require_once __DIR__ . '/../src/bootstrap.php';
require_login();
$user = current_user();

ensure_session();
$flash = $_SESSION['profile_flash'] ?? null;
unset($_SESSION['profile_flash']);
$durationErrors = [];
$durationInput = [
    'default' => format_duration_input(user_grant_duration($user, 'default')),
    'extended' => format_duration_input(user_grant_duration($user, 'extended')),
];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_csrf_token($_POST['csrf_token'] ?? null);
    $action = $_POST['action'] ?? '';
    if ($action === 'save_durations') {
        $durationInput = ['default' => trim((string)($_POST['default_duration'] ?? '')), 'extended' => trim((string)($_POST['extended_duration'] ?? ''))];
        $durationErrors = update_user_durations($user, parse_duration_input($durationInput['default']), parse_duration_input($durationInput['extended']));
        if ($durationErrors) {
            http_response_code(422); // re-render the form with the errors below
        } else {
            $_SESSION['profile_flash'] = ['type' => 'success', 'message' => 'Durations saved.', 'section' => 'durations'];
            header('Location: ' . url_for('profile.php') . '#durations');
            exit;
        }
    } elseif ($action === 'save_default_networks') {
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
            ? ['type' => 'warning', 'message' => 'Saved. Networks above your access level were ignored.', 'section' => 'networks']
            : ['type' => 'success', 'message' => 'Default networks saved.', 'section' => 'networks'];
    }
    if (!$durationErrors) {
        header('Location: ' . url_for('profile.php'));
        exit;
    }
}

$canEditDefaults = can($user, 'edit_own_default_networks');
$defaultIds = get_user_default_network_ids((int)$user['id']);
$defaultNetworks = get_default_networks_for_user((int)$user['id']);
$eligible = eligible_networks_for_user($user);
$ineligibleDefaults = array_values(array_filter($defaultNetworks, fn($n) => !user_can_access_network($user, $n)));

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
        </dl>
      </div>
    </div>

    <div class="card shadow-sm mt-4" id="durations">
      <div class="card-header">Access durations</div>
      <div class="card-body">
        <?php if ($flash && ($flash['section'] ?? '') === 'durations'): ?>
          <div class="alert alert-<?= htmlspecialchars($flash['type']) ?>" role="alert"><?= htmlspecialchars($flash['message']) ?></div>
        <?php endif; ?>
        <?php if ($durationErrors): ?>
          <div class="alert alert-danger" role="alert"><?= htmlspecialchars(implode(' ', $durationErrors)) ?></div>
        <?php endif; ?>
        <form method="post" novalidate>
          <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
          <input type="hidden" name="action" value="save_durations">
          <?php foreach (['default' => 'Default access', 'extended' => 'Extended access'] as $kind => $label): ?>
            <div class="mb-3" data-duration-field>
              <label class="form-label" for="duration-<?= $kind ?>"><?= $label ?></label>
              <div class="d-flex flex-wrap gap-1 mb-2">
                <?php foreach (grant_duration_presets($kind) as $preset): ?>
                  <button type="button" class="btn btn-sm btn-outline-secondary" data-preset="<?= htmlspecialchars(format_duration_input($preset)) ?>"><?= htmlspecialchars(format_duration_human($preset)) ?></button>
                <?php endforeach; ?>
              </div>
              <div class="input-group">
                <input type="text" class="form-control" id="duration-<?= $kind ?>" name="<?= $kind ?>_duration" value="<?= htmlspecialchars($durationInput[$kind]) ?>"
                       inputmode="numeric" autocomplete="off" aria-describedby="duration-<?= $kind ?>-help" <?= $durationErrors ? 'aria-invalid="true"' : '' ?>>
                <span class="input-group-text">h:mm</span>
              </div>
              <div class="form-text" id="duration-<?= $kind ?>-help">
                <?= htmlspecialchars(format_duration_human(MIN_GRANT_DURATION)) ?> – <?= htmlspecialchars(format_duration_human(max_grant_duration($kind))) ?><span data-until></span>
              </div>
            </div>
          <?php endforeach; ?>
          <button class="btn btn-primary" type="submit">Save durations</button>
        </form>
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
        <?php if ($flash && ($flash['section'] ?? '') === 'networks'): ?>
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
<script src="<?= htmlspecialchars(url_for('js/profile.js')) ?>"></script>
<?php include view_path('footer'); ?>
