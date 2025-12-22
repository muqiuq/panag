<?php
require_once __DIR__ . '/lib/functions.php';
require_login();

$identityRes = mikrotik_identity();
$apiOk = $identityRes['success'] ?? false;
$adminOverview = admin_access_overview();
$allUsers = $adminOverview['allUsers'];
$accessReport = $adminOverview['accessReport'];
$loggedInToday = $adminOverview['loggedInToday'];

$todayUsers = array_filter($allUsers, function ($u) use ($loggedInToday) {
  $ipKey = $u['user_ip'] ?? null;
  $nameKey = $u['username'] ?? null;
  $idKey = isset($u['id']) ? (string)$u['id'] : null;
  return ($ipKey && isset($loggedInToday[$ipKey]))
    || ($nameKey && isset($loggedInToday[$nameKey]))
    || ($idKey !== null && isset($loggedInToday[$idKey]));
});

include __DIR__ . '/lib/header.php';
?>
<div class="row g-4">
  <div class="col-12">
    <div class="card shadow-sm">
      <div class="card-header d-flex justify-content-between align-items-center">
        <span>Status</span>
        <?php if ($apiOk): ?>
          <span class="badge bg-success">API OK</span>
        <?php else: ?>
          <span class="badge bg-danger">API error</span>
        <?php endif; ?>
      </div>
      <div class="card-body">
        <?php if (!($identityRes['success'] ?? false)): ?>
          <div class="alert alert-danger" role="alert">Failed to reach API<?= $identityRes['error'] ? ': ' . htmlspecialchars((string)$identityRes['error']) : '' ?></div>
        <?php else: ?>
          <div class="text-muted">Router identity: <?= htmlspecialchars($identityRes['data']['name'] ?? 'n/a') ?></div>
        <?php endif; ?>
        <?php if (!($accessReport['success'] ?? true)): ?>
          <div class="alert alert-danger mt-3" role="alert">Could not load access lists<?= $accessReport['error'] ? ': ' . htmlspecialchars((string)$accessReport['error']) : '' ?></div>
        <?php endif; ?>
      </div>
    </div>
  </div>

  <div class="col-12">
    <div class="card shadow-sm">
      <div class="card-header d-flex justify-content-between align-items-center">
        <span>Users logged in today</span>
        <span class="badge bg-secondary">Visible only for today</span>
      </div>
      <div class="card-body">
        <?php if (empty($todayUsers)): ?>
          <p class="text-muted mb-0">No users have logged in today.</p>
        <?php else: ?>
          <div class="table-responsive">
            <table class="table table-sm align-middle mb-0">
              <thead>
                <tr>
                  <th class="text-center" style="width: 48px;">#</th>
                  <th>Name</th>
                  <th>User IP</th>
                  <th>Access granted</th>
                </tr>
              </thead>
              <tbody>
                <?php foreach ($todayUsers as $u):
                  $entries = $accessReport['data'][$u['user_ip']] ?? [];
                  $hasAccess = is_array($entries) && count($entries) > 0;
                  $ipKey = $u['user_ip'] ?? null;
                  $nameKey = $u['username'] ?? null;
                  $idKey = isset($u['id']) ? (string)$u['id'] : null;
                  $loggedToday = ($ipKey && isset($loggedInToday[$ipKey])) || ($nameKey && isset($loggedInToday[$nameKey])) || ($idKey !== null && isset($loggedInToday[$idKey]));
                ?>
                  <tr>
                    <td class="text-center" aria-label="Logged in today"><?php if ($loggedToday): ?>✅<?php else: ?>❌<?php endif; ?></td>
                    <td><?= htmlspecialchars($u['username']) ?></td>
                    <td><?= htmlspecialchars($u['user_ip']) ?></td>
                    <td><?= $hasAccess ? '<span class="badge bg-success">Yes</span>' : '<span class="badge bg-secondary">No</span>' ?></td>
                  </tr>
                <?php endforeach; ?>
              </tbody>
            </table>
          </div>
        <?php endif; ?>
      </div>
    </div>
  </div>
</div>
<?php include __DIR__ . '/lib/footer.php'; ?>
