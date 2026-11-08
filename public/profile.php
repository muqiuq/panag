<?php
// Own profile: access durations (all roles) and default networks – superusers and admins choose their own
// (only networks within their access level, saved immediately via the API); users see theirs read-only.
// Theme: tiles with a preview of each theme, live preview on selection (js/theme-picker.js), saved with the form.
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
    if ($action === 'save_contact') {
        $error = update_user_contact((int)$user['id'], (string)($_POST['email'] ?? ''), !empty($_POST['notify_alerts']));
        $_SESSION['profile_flash'] = $error === null ? ['type' => 'success', 'message' => 'Notification settings saved.', 'section' => 'contact'] : ['type' => 'danger', 'message' => $error, 'section' => 'contact'];
        if ($error === null) {
            log_event('contact_updated', 'E-mail for alerts ' . (trim((string)($_POST['email'] ?? '')) !== '' ? 'set' : 'removed'), (int)$user['id'], $user['username'], $user['user_ip']);
        }
        header('Location: ' . url_for('profile.php') . '#contact');
        exit;
    } elseif ($action === 'forget_place') {
        $kind = ($_POST['kind'] ?? '') === 'asn' ? 'asn' : 'country';
        place_forget((int)$user['id'], $kind, (string)($_POST['value'] ?? ''));
        log_event('known_place_removed', place_label($kind, (string)($_POST['value'] ?? '')), (int)$user['id'], $user['username'], $user['user_ip']);
        $_SESSION['profile_flash'] = ['type' => 'success', 'message' => 'Removed from your known places.', 'section' => 'places'];
        header('Location: ' . url_for('profile.php') . '#places');
        exit;
    } elseif ($action === 'save_theme') {
        $theme = (string)($_POST['theme'] ?? '');
        $_SESSION['profile_flash'] = set_user_theme($user, $theme)
            ? ['type' => 'success', 'message' => 'Theme set to ' . THEMES[$theme]['label'] . '.', 'section' => 'theme']
            : ['type' => 'danger', 'message' => 'Unknown theme.', 'section' => 'theme'];
        header('Location: ' . url_for('profile.php') . '#theme');
        exit;
    } elseif ($action === 'save_durations') {
        $durationInput = ['default' => trim((string)($_POST['default_duration'] ?? '')), 'extended' => trim((string)($_POST['extended_duration'] ?? ''))];
        $durationErrors = update_user_durations($user, parse_duration_input($durationInput['default']), parse_duration_input($durationInput['extended']));
        if (!$durationErrors) {
            $_SESSION['profile_flash'] = ['type' => 'success', 'message' => 'Durations saved.', 'section' => 'durations'];
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
$places = user_places((int)$user['id']);
$defaultNetworks = get_default_networks_for_user((int)$user['id']);
$pageScripts = ['js/durations.js', 'js/default-networks.js', 'js/theme-picker.js'];
$userTheme = current_theme($user);

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
        <?php if ($flash && ($flash['section'] ?? 'durations') === 'durations'): ?>
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

    <div class="row g-4 mt-0">
      <div class="col-md-6">
        <div class="card shadow-sm h-100" id="contact">
          <div class="card-header">Security notifications</div>
          <div class="card-body">
            <?php if ($flash && ($flash['section'] ?? '') === 'contact'): ?>
              <div class="alert alert-<?= e($flash['type']) ?>" role="alert"><?= e($flash['message']) ?></div>
            <?php endif; ?>
            <form method="post">
              <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
              <input type="hidden" name="action" value="save_contact">
              <div class="mb-2">
                <label class="form-label" for="contact-email">E-mail address</label>
                <input id="contact-email" type="email" name="email" class="form-control" value="<?= e((string)($user['email'] ?? '')) ?>" autocomplete="email">
              </div>
              <div class="form-check mb-3">
                <input class="form-check-input" type="checkbox" name="notify_alerts" value="1" id="contact-notify" <?= (int)($user['notify_alerts'] ?? 1) === 1 ? 'checked' : '' ?>>
                <label class="form-check-label" for="contact-notify">Mail me when PANAG notices unusual activity on my account</label>
              </div>
              <button class="btn btn-primary btn-sm" type="submit">Save</button>
            </form>
          </div>
        </div>
      </div>
      <div class="col-md-6">
        <div class="card shadow-sm h-100" id="places">
          <div class="card-header">Known places</div>
          <div class="card-body">
            <?php if ($flash && ($flash['section'] ?? '') === 'places'): ?>
              <div class="alert alert-<?= e($flash['type']) ?>" role="alert"><?= e($flash['message']) ?></div>
            <?php endif; ?>
            <?php if (!$places): ?>
              <p class="text-muted small">None yet. Countries you connect from are learned automatically within the allowed countries; others are added when you answer “That was me”.</p>
            <?php else: ?>
              <ul class="list-group mb-2">
                <?php foreach ($places as $place): ?>
                  <li class="list-group-item d-flex justify-content-between align-items-center gap-2">
                    <span><strong><?= e(place_label($place['kind'], $place['value'])) ?></strong> <span class="text-muted small"><?= e($place['source']) ?>, last <?= e(date('Y-m-d', (int)$place['last_seen'])) ?></span></span>
                    <form method="post" data-confirm="Remove <?= e(place_label($place['kind'], $place['value'])) ?> from your known places?">
                      <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
                      <input type="hidden" name="action" value="forget_place">
                      <input type="hidden" name="kind" value="<?= e($place['kind']) ?>">
                      <input type="hidden" name="value" value="<?= e($place['value']) ?>">
                      <button class="btn btn-sm btn-outline-secondary" aria-label="Remove <?= e(place_label($place['kind'], $place['value'])) ?>">Remove</button>
                    </form>
                  </li>
                <?php endforeach; ?>
              </ul>
            <?php endif; ?>
          </div>
        </div>
      </div>
    </div>
    <?php if (MONITOR_ENABLED): ?>
      <p class="small text-muted mt-3 mb-0" data-testid="monitoring-notice">
        <strong>Security monitoring:</strong> to detect misuse, PANAG checks your logins and grants and the location (country and network operator)
        of your WireGuard connections. Public IP addresses are kept for <?= (int)MONITOR_IP_RETENTION_DAYS ?> days, alerts for <?= (int)MONITOR_ALERT_RETENTION_DAYS ?> days.
        Only admins see alerts.<?= MONITOR_AI !== 'off' ? ' Unusual cases may be assessed by an AI service; it only receives pseudonymised facts (no name, no IP address).' : '' ?>
      </p>
    <?php endif; ?>
  </div>
</div>

<div class="card shadow-sm mt-4" id="theme">
  <div class="card-header">Theme</div>
  <div class="card-body">
    <?php if ($flash && ($flash['section'] ?? '') === 'theme'): ?>
      <div class="alert alert-<?= e($flash['type']) ?>" role="alert"><?= e($flash['message']) ?></div>
    <?php endif; ?>
    <form method="post" data-theme-picker data-saved-theme="<?= e($userTheme) ?>">
      <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
      <input type="hidden" name="action" value="save_theme">
      <fieldset>
        <legend class="visually-hidden">Theme</legend>
        <div class="row g-3">
          <?php foreach (THEMES as $key => $t): ?>
            <div class="col-6 col-md-4 col-xl">
              <input type="radio" class="btn-check" name="theme" id="theme-<?= e($key) ?>" value="<?= e($key) ?>"
                data-dark="<?= $t['dark'] ? '1' : '0' ?>" aria-describedby="theme-desc-<?= e($key) ?>" <?= $key === $userTheme ? 'checked' : '' ?>>
              <label class="theme-tile" for="theme-<?= e($key) ?>">
                <span class="theme-preview" <?= theme_attributes($key) ?> aria-hidden="true">
                  <span class="theme-preview-nav"></span>
                  <span class="theme-preview-card">
                    <span class="theme-preview-line"></span>
                    <span class="theme-preview-line theme-preview-link"></span>
                    <span class="theme-preview-btn"></span>
                  </span>
                </span>
                <span class="theme-tile-name"><?= e($t['label']) ?></span>
                <span class="theme-tile-desc" id="theme-desc-<?= e($key) ?>" aria-hidden="true"><?= e($t['description']) ?></span>
              </label>
            </div>
          <?php endforeach; ?>
        </div>
      </fieldset>
      <div class="d-flex flex-wrap align-items-center gap-3 mt-3">
        <button class="btn btn-primary btn-sm" type="submit">Save theme</button>
        <span class="small text-muted" data-theme-preview-note hidden>Preview – save to keep this theme.</span>
      </div>
    </form>
  </div>
</div>
<?php include view_path('footer'); ?>
