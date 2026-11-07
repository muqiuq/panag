<?php
// Users overview (admin dashboard and status page). JS: public/js/users-overview.js ("Revoke all").
// Expects the variables of admin_access_overview(): $allUsers, $accessReport, $lastLogins, $loggedInToday.
$accessReport = $accessReport ?? ['success' => false, 'data' => [], 'error' => '', 'fingerprint' => null];
$allUsers = $allUsers ?? [];
$lastLogins = $lastLogins ?? [];
$loggedInToday = $loggedInToday ?? [];
?>
<div class="card shadow-sm mt-4">
  <div class="card-header d-flex justify-content-between align-items-center">
    <span>Users overview</span>
    <?php if ($accessReport['success']): ?>
      <span class="badge text-bg-success">API OK</span>
    <?php else: ?>
      <span class="badge text-bg-danger">API error</span>
    <?php endif; ?>
  </div>
  <div class="card-body">
    <?php if (!$accessReport['success']): ?>
      <div class="alert alert-danger" role="alert">
        Failed to fetch address list<?= $accessReport['error'] ? ': ' . e($accessReport['error']) : '' ?>
        <?php if (!empty($accessReport['fingerprint'])): ?>
          <div class="small mb-0">Peer fingerprint: <?= e($accessReport['fingerprint']) ?></div>
        <?php endif; ?>
      </div>
    <?php elseif (empty($allUsers)): ?>
      <p class="text-muted">No users found.</p>
    <?php else: ?>
      <div class="table-responsive">
        <table class="table table-sm align-middle mb-0" data-sortable id="usersOverviewTable">
          <thead>
            <tr>
              <th data-sort="number" class="col-icon" title="Logged in today"><span class="visually-hidden">Logged in today</span>#</th>
              <th>User</th>
              <th data-sort="ip">User IP</th>
              <th data-sort="number">Current addresses</th>
              <th data-sort="number" class="col-time">Last login</th>
              <th data-sort="none" class="text-end"><span class="visually-hidden">Actions</span></th>
            </tr>
          </thead>
          <tbody>
            <?php foreach ($allUsers as $u):
              $entries = $accessReport['data'][$u['user_ip']] ?? [];
              $lastLoginTs = $lastLogins[$u['user_ip']] ?? null;
              $today = isset($loggedInToday[(string)$u['id']]);
            ?>
              <tr>
                <td class="text-center fs-6" data-sort-value="<?= $today ? 1 : 0 ?>" title="<?= $today ? 'Logged in today' : 'Not logged in today' ?>"><?= $today ? '✅' : '⌛' ?></td>
                <td><strong><?= e($u['username']) ?></strong></td>
                <td><code><?= e($u['user_ip']) ?></code></td>
                <td data-sort-value="<?= count($entries) ?>">
                  <?php if (empty($entries)): ?>
                    <span class="text-muted">None</span>
                  <?php else: ?>
                    <ul class="list-unstyled mb-0 small">
                      <?php foreach ($entries as $entry): ?>
                        <li><?= e($entry['address'] ?? 'n/a') ?> <span class="text-muted"><?= e($entry['timeout'] ?? '') ?></span></li>
                      <?php endforeach; ?>
                    </ul>
                  <?php endif; ?>
                </td>
                <td class="small text-muted" data-sort-value="<?= $lastLoginTs ? (int)$lastLoginTs : '' ?>"><?= $lastLoginTs ? e(date('Y-m-d H:i', $lastLoginTs)) : 'n/a' ?></td>
                <td class="text-end">
                  <button type="button" class="btn btn-sm btn-outline-danger" data-revoke-all="<?= (int)$u['id'] ?>" data-username="<?= e($u['username']) ?>" <?= empty($entries) ? 'disabled' : '' ?>>Revoke all</button>
                </td>
              </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </div>
    <?php endif; ?>
  </div>
</div>
