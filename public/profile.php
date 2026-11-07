<?php
// Own profile: access durations (all roles) and default networks – superusers and admins choose their own
// (only networks within their access level, saved immediately via the API); users see theirs read-only.
// Theme settings follow in phase 4.
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
    if (($_POST['action'] ?? '') === 'save_durations') {
        $durationInput = ['default' => trim((string)($_POST['default_duration'] ?? '')), 'extended' => trim((string)($_POST['extended_duration'] ?? ''))];
        $durationErrors = update_user_durations($user, parse_duration_input($durationInput['default']), parse_duration_input($durationInput['extended']));
        if (!$durationErrors) {
            $_SESSION['profile_flash'] = ['type' => 'success', 'message' => 'Durations saved.'];
            header('Location: ' . url_for('profile.php') . '#durations');
            exit;
        }
        http_response_code(422); // re-render the form with the errors
    } else {
        http_response_code(400);
        echo 'Unknown action';
        exit;
    }
}

$canEditDefaults = can($user, 'edit_own_default_networks');
$defaultNetworks = get_default_networks_for_user((int)$user['id']);
$pageScripts = ['js/durations.js', 'js/default-networks.js'];

include view_path('header');
?>
<div class="row g-4">
  <div class="col-lg-4">
    <div class="card shadow-sm">
      <div class="card-header">Account</div>
      <div class="card-body">
        <dl class="row mb-0">
          <dt class="col-5">Name</dt><dd class="col-7"><?= e($user['username']) ?></dd>
          <dt class="col-5">IP</dt><dd class="col-7"><code><?= e($user['user_ip']) ?></code></dd>
          <dt class="col-5">Role</dt><dd class="col-7" data-testid="profile-role"><?= e(role_label((string)user_role($user))) ?></dd>
          <dt class="col-5">Access level</dt><dd class="col-7">L<?= (int)$user['accesslevel'] ?></dd>
        </dl>
      </div>
    </div>

    <div class="card shadow-sm mt-4" id="durations">
      <div class="card-header">Access durations</div>
      <div class="card-body">
        <?php if ($flash): ?>
          <div class="alert alert-<?= e($flash['type']) ?>" role="alert"><?= e($flash['message']) ?></div>
        <?php endif; ?>
        <?php
          $dfAction = url_for('profile.php');
          $dfInput = $durationInput;
          $dfErrors = $durationErrors;
          include view_path('partials/duration_form');
        ?>
      </div>
    </div>
  </div>

  <div class="col-lg-8">
    <div class="card shadow-sm" id="networks">
      <div class="card-header d-flex justify-content-between align-items-center">
        <span>Default networks</span>
        <span class="text-muted small">granted together by “Grant default access”</span>
      </div>
      <div class="card-body">
        <?php if ($canEditDefaults): ?>
          <p class="text-muted small">Changes are saved immediately. You can choose networks up to your level (L<?= (int)$user['accesslevel'] ?>).</p>
          <?php $dnUser = $user; include view_path('partials/default_networks_editor'); ?>
        <?php else: ?>
          <?php if (empty($defaultNetworks)): ?>
            <p class="text-muted">No default networks configured for you.</p>
          <?php else: ?>
            <ul class="list-group mb-3">
              <?php foreach ($defaultNetworks as $n): $eligible = user_can_access_network($user, $n); ?>
                <li class="list-group-item d-flex justify-content-between">
                  <span><?= e($n['name']) ?> <code class="ms-2"><?= e($n['address']) ?></code>
                    <?php if (!$eligible): ?><span class="badge text-bg-warning ms-1">Above your level – not granted</span><?php endif; ?>
                  </span>
                  <span class="badge text-bg-secondary">L<?= (int)$n['accesslevel'] ?></span>
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
