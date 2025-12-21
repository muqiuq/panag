<?php
require_once __DIR__ . '/functions.php';
require_login();
$user = current_user();
$defaultNetworks = get_default_networks_for_user($user['id']);
$currentEntries = get_current_address_list_entries($user['username']);
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
$accessReport = ['success' => false, 'data' => [], 'error' => ''];
if ((int)$user['isadmin'] === 1) {
  $allUsers = db()->query('SELECT id, name, username FROM users ORDER BY username')->fetchAll(PDO::FETCH_ASSOC);
  $accessReport = current_accesses_by_users($allUsers);
}
include __DIR__ . '/header.php';
?>
<div class="spinner-overlay" id="spinnerOverlay">
  <div class="spinner-border text-light" role="status"></div>
</div>
<div class="row g-4 mb-2">
  <div class="col-12">
    <div class="card shadow-sm">
      <div class="card-body">
        <h5 class="card-title mb-1"><?= htmlspecialchars($greeting) ?>, <?= htmlspecialchars($user['name']) ?> (<?= htmlspecialchars($user['username']) ?>)</h5>
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
            <?php foreach ($defaultNetworks as $net): ?>
              <li class="list-group-item d-flex justify-content-between align-items-center">
                <span>
                  <strong><?= htmlspecialchars($net['name']) ?></strong><br>
                  <small class="text-muted"><?= htmlspecialchars($net['address']) ?></small>
                </span>
                <span class="badge bg-secondary">L<?= (int)$net['accesslevel'] ?></span>
              </li>
            <?php endforeach; ?>
          </ul>
        <?php endif; ?>
        <button class="btn btn-primary" id="btnDefaultAccess" <?= empty($defaultNetworks) ? 'disabled' : '' ?>>Grant default access</button>
        <div class="mt-3" id="defaultAccessResult"></div>
      </div>
    </div>
    <?php if ((int)$user['isadmin'] === 1): ?>
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
                    <th class="text-end">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  <?php foreach ($allUsers as $u):
                    $entries = $accessReport['data'][$u['username']] ?? [];
                  ?>
                  <tr>
                    <td><strong><?= htmlspecialchars($u['name']) ?></strong><br><small class="text-muted"><?= htmlspecialchars($u['username']) ?></small></td>
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
                    <td class="text-end">
                      <button class="btn btn-sm btn-outline-danger revoke-btn" data-user-id="<?= (int)$u['id'] ?>" data-username="<?= htmlspecialchars($u['username']) ?>" <?= empty($entries) ? 'disabled' : '' ?>>Revoke all</button>
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
    <?php endif; ?>
  </div>
  <div class="col-md-6">
    <div class="card shadow-sm mb-4">
      <div class="card-header">Current granted accesses</div>
      <div class="card-body">
        <div id="currentAccessContainer">
          <?php if (empty($currentEntries)): ?>
            <p class="text-muted">No active address list entries.</p>
          <?php else: ?>
            <ul class="list-group">
              <?php foreach ($currentEntries as $entry): ?>
                <li class="list-group-item d-flex justify-content-between">
                  <span><?= htmlspecialchars($entry['address'] ?? 'n/a') ?></span>
                  <small class="text-muted"><?= htmlspecialchars($entry['timeout'] ?? '') ?></small>
                </li>
              <?php endforeach; ?>
            </ul>
          <?php endif; ?>
        </div>
      </div>
    </div>
    <div class="card shadow-sm card-warning">
      <div class="card-header bg-warning-subtle">Extended access</div>
      <div class="card-body">
        <p class="text-dark">Use only if required. Extended access grants additional networks temporarily.</p>
        <a href="<?= htmlspecialchars(url_for('extendedaccess.php')) ?>" class="btn btn-warning text-dark">Go to extended access</a>
      </div>
    </div>
  </div>
</div>
<script>
const BASE_PATH = document.body.dataset.basePath || '';
const CSRF_TOKEN = document.querySelector('meta[name="csrf-token"]')?.content || document.body.dataset.csrfToken || '';
const overlay = document.getElementById('spinnerOverlay');
const resultBox = document.getElementById('defaultAccessResult');
const btn = document.getElementById('btnDefaultAccess');
const currentAccessContainer = document.getElementById('currentAccessContainer');
const revokeResult = document.getElementById('revokeResult');
const revokeButtons = document.querySelectorAll('.revoke-btn');

function renderCurrentAccess(entries) {
  if (!currentAccessContainer) return;
  if (!entries || entries.length === 0) {
    currentAccessContainer.innerHTML = '<p class="text-muted">No active address list entries.</p>';
    return;
  }
  const items = entries.map(e => {
    const address = e.address ?? 'n/a';
    const timeout = e.timeout ?? '';
    return `<li class="list-group-item d-flex justify-content-between"><span>${address}</span><small class="text-muted">${timeout}</small></li>`;
  }).join('');
  currentAccessContainer.innerHTML = `<ul class="list-group">${items}</ul>`;
}

function refreshCurrentAccess() {
  fetch(`${BASE_PATH}/api.php?f=currentAccess`)
    .then(resp => resp.json())
    .then(data => {
      if (data.status && data.entries) {
        renderCurrentAccess(data.entries);
      }
    })
    .catch(() => {});
}

if (btn) {
  btn.addEventListener('click', () => {
    overlay.classList.add('active');
    resultBox.innerHTML = '';
    const started = Date.now();
    fetch(`${BASE_PATH}/api.php?f=defaultaccess`, {
      method: 'POST',
      headers: {'X-CSRF-Token': CSRF_TOKEN},
    })
      .then(resp => resp.json())
      .then(data => {
        const elapsed = Date.now() - started;
        const wait = Math.max(0, 1000 - elapsed);
        setTimeout(() => {
          overlay.classList.remove('active');
          const cls = data.status ? 'alert-success' : 'alert-danger';
          resultBox.innerHTML = `<div class="alert ${cls}" role="alert">${data.message}</div>`;
          refreshCurrentAccess();
        }, wait);
      })
      .catch(() => {
        const elapsed = Date.now() - started;
        const wait = Math.max(0, 1000 - elapsed);
        setTimeout(() => {
          overlay.classList.remove('active');
          resultBox.innerHTML = '<div class="alert alert-danger" role="alert">Request failed.</div>';
        }, wait);
      });
  });
}

// Keep current list up to date on load.
refreshCurrentAccess();

revokeButtons.forEach(btn => {
  btn.addEventListener('click', () => {
    const uid = btn.dataset.userId;
    const uname = btn.dataset.username;
    if (!uid) return;
    if (!confirm(`Revoke all access for ${uname}?`)) return;
    revokeResult.innerHTML = '';
    fetch(`${BASE_PATH}/api.php?f=revokeAccess`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': CSRF_TOKEN,
      },
      body: JSON.stringify({user_id: uid})
    })
      .then(resp => resp.json())
      .then(data => {
        const cls = data.status ? 'alert-success' : 'alert-danger';
        revokeResult.innerHTML = `<div class="alert ${cls}" role="alert">${data.message || 'Done.'}</div>`;
        if (data.status) {
          setTimeout(() => window.location.reload(), 600);
        }
      })
      .catch(() => {
        revokeResult.innerHTML = '<div class="alert alert-danger" role="alert">Revoke request failed.</div>';
      });
  });
});
</script>
<?php include __DIR__ . '/footer.php'; ?>
