<?php
// Dashboard: search/command field, default access, active access, all networks (+ users overview for admins).
require_once __DIR__ . '/../src/bootstrap.php';
require_login();
$user = current_user();
$defaultNetworks = get_default_networks_for_user((int)$user['id']);
$defaultIds = array_flip(array_map(fn($n) => (int)$n['id'], $defaultNetworks));
$eligibleDefaultCount = count(array_filter($defaultNetworks, fn($n) => user_can_access_network($user, $n)));
$networks = get_all_networks();
$routerEntries = own_address_list_entries((string)$user['user_ip']); // null = router not reachable
$currentAccess = current_access_view($user, $routerEntries ?? []);
$extendedDuration = format_duration_human(user_grant_duration($user, 'extended'));

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
if (is_admin($user)) {
    $adminOverview = admin_access_overview();
    $allUsers = $adminOverview['allUsers'];
    $accessReport = $adminOverview['accessReport'];
    $lastLogins = $adminOverview['lastLogins'];
    $loggedInToday = $adminOverview['loggedInToday'];
}
$pageScripts = ['js/dashboard.js', 'js/users-overview.js'];
include view_path('header');
?>
<div class="card shadow-sm mb-4 palette-card">
  <div class="card-body">
    <div class="d-flex flex-wrap justify-content-between align-items-baseline gap-2 mb-2">
      <h1 class="h5 mb-0"><?= e($greeting) ?>, <?= e($user['username']) ?> <span class="text-muted fw-normal">(<?= e($user['user_ip']) ?>)</span></h1>
      <span class="text-muted small"><?= e($quip) ?></span>
    </div>
    <label class="form-label fw-semibold" for="paletteInput">Grant access to a network</label>
    <div class="palette-inline">
      <input type="text" id="paletteInput" class="form-control form-control-lg" autofocus
             placeholder="Type a network, an IP or a command – e.g. “vpn”, “10.10.0.5”, “dc 2h”" aria-describedby="paletteHelp">
      <ul id="paletteList" class="palette-list palette-popup list-unstyled mb-0" hidden></ul>
    </div>
    <div id="paletteHelp" class="form-text">
      Enter or ↓ selects, Enter again grants for <?= e($extendedDuration) ?> (or add a duration: “vpn 2h”). Press <kbd>/</kbd> or <kbd>Ctrl</kbd>+<kbd>K</kbd> on any page.
    </div>
  </div>
</div>

<div class="row g-4">
  <div class="col-lg-5">
    <div class="card shadow-sm h-100">
      <div class="card-header">Default access</div>
      <div class="card-body">
        <?php if (empty($defaultNetworks)): ?>
          <p class="text-muted mb-3">No default networks configured for you.</p>
        <?php else: ?>
          <ul class="list-group mb-3">
            <?php foreach ($defaultNetworks as $net): $eligible = user_can_access_network($user, $net); ?>
              <li class="list-group-item d-flex justify-content-between align-items-center">
                <span>
                  <strong><?= e($net['name']) ?></strong> <code class="small ms-1"><?= e($net['address']) ?></code>
                  <?php if (!$eligible): ?>
                    <span class="d-block text-danger small">Requires L<?= (int)$net['accesslevel'] ?> (you are L<?= (int)$user['accesslevel'] ?>) – not granted</span>
                  <?php endif; ?>
                </span>
                <span class="badge <?= $eligible ? 'text-bg-secondary' : 'text-bg-danger' ?>">L<?= (int)$net['accesslevel'] ?></span>
              </li>
            <?php endforeach; ?>
          </ul>
        <?php endif; ?>
        <button class="btn btn-primary" id="btnDefaultAccess" <?= $eligibleDefaultCount === 0 ? 'disabled' : '' ?>>Grant default access</button>
        <span class="text-muted small ms-2">for <?= e(format_duration_human(user_grant_duration($user, 'default'))) ?> · <a href="<?= e(url_for('profile.php')) ?>#durations">change</a></span>
      </div>
    </div>
  </div>
  <div class="col-lg-7">
    <div class="card shadow-sm h-100">
      <div class="card-header">Active access</div>
      <div class="card-body">
        <?php if ($routerEntries === null): ?>
          <div class="alert alert-warning small" role="alert">The router is not reachable – your active access is unknown right now.</div>
        <?php endif; ?>
        <div class="table-responsive" id="currentAccessContainer">
          <table class="table table-sm align-middle mb-3" id="activeAccessTable" data-sortable data-entries="<?= e(json_encode($currentAccess)) ?>">
            <thead>
              <tr><th>Network</th><th data-sort="ip">Address</th><th>Type</th><th data-sort="number">Remaining</th><th data-sort="number">Until</th><th data-sort="none" class="text-end"><span class="visually-hidden">Actions</span></th></tr>
            </thead>
            <tbody><tr><td colspan="6" class="text-muted">Loading…</td></tr></tbody>
          </table>
        </div>
        <button class="btn btn-outline-danger" id="btnSelfRevoke" <?= empty($currentAccess) ? 'disabled' : '' ?>>Revoke my access</button>
      </div>
    </div>
  </div>
</div>

<div class="card shadow-sm mt-4">
  <div class="card-header d-flex flex-wrap justify-content-between align-items-center gap-2">
    <span>All networks</span>
    <input type="search" class="form-control form-control-sm w-auto" placeholder="Filter" aria-label="Filter networks" data-table-filter="networksTable">
  </div>
  <div class="card-body">
    <p class="text-muted small">Granting a single network uses your extended duration (<?= e($extendedDuration) ?>) – also for default networks. An active network is extended, never shortened.</p>
    <div class="table-responsive">
      <table class="table table-sm align-middle mb-0" id="networksTable" data-sortable>
        <thead>
          <tr><th>Name</th><th data-sort="ip">Address</th><th data-sort="number">Level</th><th>Default</th><th data-sort="number">Status</th><th data-sort="none" class="text-end"><span class="visually-hidden">Actions</span></th></tr>
        </thead>
        <tbody>
          <?php foreach ($networks as $n): $allowed = user_can_access_network($user, $n); ?>
            <tr data-address="<?= e($n['address']) ?>" <?= $allowed ? '' : 'class="network-locked"' ?>>
              <td><?= e($n['name']) ?></td>
              <td><code><?= e($n['address']) ?></code></td>
              <td data-sort-value="<?= (int)$n['accesslevel'] ?>">L<?= (int)$n['accesslevel'] ?></td>
              <td><?= isset($defaultIds[(int)$n['id']]) ? '<span class="badge text-bg-secondary">Default</span>' : '' ?></td>
              <td data-status></td>
              <td class="text-end">
                <?php if ($allowed): ?>
                  <button type="button" class="btn btn-sm btn-outline-primary" data-grant="<?= (int)$n['id'] ?>" aria-label="Grant <?= e($n['name']) ?>">Grant</button>
                <?php else: ?>
                  <span class="d-inline-block" tabindex="0" title="Requires L<?= (int)$n['accesslevel'] ?> – you have L<?= (int)$user['accesslevel'] ?>">
                    <button type="button" class="btn btn-sm btn-outline-secondary" disabled aria-label="Grant <?= e($n['name']) ?> (requires L<?= (int)$n['accesslevel'] ?>)">Grant</button>
                  </span>
                <?php endif; ?>
              </td>
            </tr>
          <?php endforeach; ?>
        </tbody>
      </table>
    </div>
  </div>
</div>

<?php if (is_admin($user)): ?>
  <?php include view_path('partials/api_status_card'); ?>
<?php endif; ?>
<script type="application/json" id="paletteData"><?= json_encode(palette_data($user, $routerEntries ?? []), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?></script>
<?php include view_path('footer'); ?>
