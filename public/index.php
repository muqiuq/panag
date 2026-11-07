<?php
require_once __DIR__ . '/../src/bootstrap.php';
require_login();
$user = current_user();
$defaultNetworks = get_default_networks_for_user($user['id']);
$eligibleDefaultCount = 0;
foreach ($defaultNetworks as $dn) {
  if (user_can_access_network($user, $dn)) {
    $eligibleDefaultCount++;
  }
}
$currentAccess = current_access_view($user);
$hour = (int)date('G');
$greeting = 'Hello';
$quip = '';
foreach (GREETING_MESSAGES as $msg) {
  if ($hour >= $msg['start'] && $hour < $msg['end']) {
    $greeting = $msg['greeting'];
    $quip = $msg['quip'];
    break;
  }
}
$allUsers = [];
$accessReport = ['success' => false, 'data' => [], 'error' => '', 'fingerprint' => null];
$lastLogins = [];
if (is_admin($user)) {
  $adminOverview = admin_access_overview();
  $allUsers = $adminOverview['allUsers'];
  $accessReport = $adminOverview['accessReport'];
  $lastLogins = $adminOverview['lastLogins'];
  $loggedInToday = $adminOverview['loggedInToday'];
}
include view_path('header');
?>
<div class="spinner-overlay" id="spinnerOverlay">
  <div class="spinner-border text-light" role="status"></div>
</div>
<div class="row g-4 mb-2">
  <div class="col-12">
    <div class="card shadow-sm">
      <div class="card-body">
        <h5 class="card-title mb-1"><?= htmlspecialchars($greeting) ?>, <?= htmlspecialchars($user['username']) ?> (<?= htmlspecialchars($user['user_ip']) ?>)</h5>
        <p class="text-muted mb-0"><?= htmlspecialchars($quip) ?></p>
      </div>
    </div>
  </div>
</div>
<div class="row g-4">
  <div class="col-md-6">
    <div class="card shadow-sm">
      <div class="card-header">Default Access</div>
      <div class="card-body">
        <?php if (empty($defaultNetworks)): ?>
          <p class="text-muted mb-3">No default networks configured for you.</p>
        <?php else: ?>
          <ul class="list-group mb-3">
            <?php foreach ($defaultNetworks as $net): 
              $eligible = user_can_access_network($user, $net);
            ?>
              <li class="list-group-item d-flex justify-content-between align-items-center">
                <span>
                  <strong><?= htmlspecialchars($net['name']) ?></strong><br>
                  <small class="text-muted"><?= htmlspecialchars($net['address']) ?></small>
                  <?php if (!$eligible): ?>
                    <div class="text-danger small mt-1">Requires L<?= (int)$net['accesslevel'] ?> (you are L<?= (int)$user['accesslevel'] ?>)</div>
                  <?php endif; ?>
                </span>
                <span class="badge <?= $eligible ? 'bg-secondary' : 'bg-danger' ?>">L<?= (int)$net['accesslevel'] ?></span>
              </li>
            <?php endforeach; ?>
          </ul>
        <?php endif; ?>
        <button class="btn btn-primary" id="btnDefaultAccess" <?= $eligibleDefaultCount === 0 ? 'disabled' : '' ?>>Grant default access</button>
        <span class="text-muted small ms-2">for <?= htmlspecialchars(format_duration_human(user_grant_duration($user, 'default'))) ?> · <a href="<?= htmlspecialchars(url_for('profile.php')) ?>#durations">change</a></span>
        <div class="mt-3" id="defaultAccessResult"></div>
      </div>
    </div>
    <?php if (is_admin($user)): ?>
      <?php include view_path('partials/api_status_card'); ?>
    <?php endif; ?>
  </div>
  <div class="col-md-6">
    <div class="card shadow-sm mb-4">
      <div class="card-header">Current granted accesses</div>
      <div class="card-body">
        <div id="currentAccessResult"></div>
        <div id="currentAccessContainer" class="mb-3" data-entries="<?= htmlspecialchars(json_encode($currentAccess)) ?>">
          <p class="text-muted">Loading…</p>
        </div>
        <button class="btn btn-outline-danger" id="btnSelfRevoke" <?= empty($currentAccess) ? 'disabled' : '' ?>>Revoke my access</button>
      </div>
    </div>
    <div class="card shadow-sm card-warning">
      <div class="card-header bg-warning-subtle">Extended access</div>
      <div class="card-body">
        <p class="text-dark">Use only if required. Extended access grants additional networks for <?= htmlspecialchars(format_duration_human(user_grant_duration($user, 'extended'))) ?>.</p>
        <a href="<?= htmlspecialchars(url_for('extendedaccess.php')) ?>" class="btn btn-warning text-dark">Go to extended access</a>
      </div>
    </div>
  </div>
</div>
<script src="<?= htmlspecialchars(url_for('js/app.js')) ?>"></script>
<script src="<?= htmlspecialchars(url_for('js/dashboard.js')) ?>"></script>
<?php include view_path('footer'); ?>
