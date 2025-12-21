<?php
if (!isset($accessReport)) {
    $accessReport = ['success' => false, 'data' => [], 'error' => '', 'fingerprint' => null];
}
if (!isset($allUsers)) {
    $allUsers = [];
}
if (!isset($lastLogins)) {
    $lastLogins = [];
}
?>
<div class="card shadow-sm mt-4">
  <div class="card-header d-flex justify-content-between align-items-center">
    <span>Mikrotik API status &amp; current accesses</span>
    <?php if ($accessReport['success']): ?>
      <span class="badge bg-success">API OK</span>
    <?php else: ?>
      <span class="badge bg-danger">API error</span>
    <?php endif; ?>
  </div>
  <div class="card-body">
    <div id="revokeResult"></div>
    <?php if (!$accessReport['success']): ?>
      <div class="alert alert-danger" role="alert">
        Failed to fetch address list<?= $accessReport['error'] ? ': ' . htmlspecialchars($accessReport['error']) : '' ?>
        <?php if (!empty($accessReport['fingerprint'])): ?>
          <div class="small mb-0">Peer fingerprint: <?= htmlspecialchars($accessReport['fingerprint']) ?></div>
        <?php endif; ?>
      </div>
    <?php else: ?>
      <?php if (empty($allUsers)): ?>
        <p class="text-muted">No users found.</p>
      <?php else: ?>
        <div class="table-responsive">
          <table class="table table-sm align-middle mb-0">
            <thead>
              <tr>
                <th>User</th>
                <th>Current addresses</th>
                <th>Last login</th>
                <th class="text-end">Actions</th>
              </tr>
            </thead>
            <tbody>
              <?php foreach ($allUsers as $u):
                $entries = $accessReport['data'][$u['user_ip']] ?? [];
                $lastLoginTs = $lastLogins[$u['user_ip']] ?? null;
              ?>
              <tr>
                <td><strong><?= htmlspecialchars($u['username']) ?></strong><br><small class="text-muted"><?= htmlspecialchars($u['user_ip']) ?></small></td>
                <td>
                  <?php if (empty($entries)): ?>
                    <span class="text-muted">None</span>
                  <?php else: ?>
                    <ul class="list-unstyled mb-0 small">
                      <?php foreach ($entries as $entry): ?>
                        <li><?= htmlspecialchars($entry['address'] ?? 'n/a') ?> <span class="text-muted"><?= htmlspecialchars($entry['timeout'] ?? '') ?></span></li>
                      <?php endforeach; ?>
                    </ul>
                  <?php endif; ?>
                </td>
                <td class="small text-muted" style="width: 140px;">
                  <?php if ($lastLoginTs): ?>
                    <?= htmlspecialchars(date('Y-m-d H:i', $lastLoginTs)) ?>
                  <?php else: ?>
                    <span class="text-muted">n/a</span>
                  <?php endif; ?>
                </td>
                <td class="text-end">
                  <button class="btn btn-sm btn-outline-danger revoke-btn" data-user-id="<?= (int)$u['id'] ?>" data-username="<?= htmlspecialchars($u['user_ip']) ?>" <?= empty($entries) ? 'disabled' : '' ?>>Revoke all</button>
                </td>
              </tr>
              <?php endforeach; ?>
            </tbody>
          </table>
        </div>
      <?php endif; ?>
    <?php endif; ?>
  </div>
</div>
