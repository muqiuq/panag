<?php
require_once __DIR__ . '/lib/functions.php';
require_login();
$user = current_user();
$networks = get_all_networks();
$current = get_current_address_list_entries($user['user_ip']);
$addresses = array_column($current, 'address');
include __DIR__ . '/lib/header.php';
?>
<div class="spinner-overlay" id="spinnerOverlay">
  <div class="spinner-border text-light" role="status"></div>
</div>
<div class="card shadow-sm">
  <div class="card-header d-flex justify-content-between align-items-center">
    <span>Extended access</span>
    <a href="<?= htmlspecialchars(url_for('index.php')) ?>" class="btn btn-outline-secondary btn-sm">
      &#8592; Return to Dashboard
    </a>
  </div>
  <div class="card-body">
    <p class="text-dark">Only request extended access when necessary.</p>
    <form id="extendedForm">
      <div class="table-responsive">
        <table class="table table-sm align-middle">
          <thead>
            <tr>
              <th>Select</th>
              <th>Name</th>
              <th>Address</th>
              <th>Access level</th>
              <th>Currently granted</th>
            </tr>
          </thead>
          <tbody>
            <?php foreach ($networks as $n):
              $allowed = user_can_access_network($user, $n);
              $hasAccess = in_array($n['address'], $addresses, true);
            ?>
              <tr class="<?= $allowed ? '' : 'table-light' ?>">
                <td>
                  <?php if ($allowed): ?>
                    <input type="checkbox" name="network_ids[]" value="<?= (int)$n['id'] ?>" <?= $hasAccess ? 'checked' : '' ?>>
                  <?php else: ?>
                    <input type="checkbox" disabled>
                  <?php endif; ?>
                </td>
                <td><?= htmlspecialchars($n['name']) ?></td>
                <td><code><?= htmlspecialchars($n['address']) ?></code></td>
                <td>L<?= (int)$n['accesslevel'] ?></td>
                <td><?= $hasAccess ? '<span class="badge bg-success">Yes</span>' : '<span class="badge bg-secondary">No</span>' ?></td>
              </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </div>
      <button type="submit" class="btn btn-warning text-dark">Apply selection</button>
      <div class="mt-3" id="resultBox"></div>
    </form>
  </div>
</div>
<script>
const BASE_PATH = document.body.dataset.basePath || '';
const CSRF_TOKEN = document.querySelector('meta[name="csrf-token"]')?.content || document.body.dataset.csrfToken || '';
const overlay = document.getElementById('spinnerOverlay');
const form = document.getElementById('extendedForm');
const resultBox = document.getElementById('resultBox');

function updateGrantedBadges(entries) {
  if (!Array.isArray(entries)) return;
  const granted = new Set(entries.map(e => e.address));
  document.querySelectorAll('tbody tr').forEach(row => {
    const addrEl = row.querySelector('code');
    const badgeCell = row.querySelector('td:last-child');
    if (!addrEl || !badgeCell) return;
    const addr = addrEl.textContent.trim();
    const has = granted.has(addr);
    badgeCell.innerHTML = has ? '<span class="badge bg-success">Yes</span>' : '<span class="badge bg-secondary">No</span>';
    const cb = row.querySelector('input[type="checkbox"]');
    if (cb && !cb.disabled && has) {
      cb.checked = true;
    }
  });
}

function refreshCurrentAccess() {
  fetch(`${BASE_PATH}/api.php?f=currentAccess`)
    .then(r => r.json())
    .then(json => {
      if (json.status && json.entries) {
        updateGrantedBadges(json.entries);
      }
    })
    .catch(() => {});
}

refreshCurrentAccess();

form.addEventListener('submit', (e) => {
  e.preventDefault();
  overlay.classList.add('active');
  resultBox.innerHTML = '';
  const data = new FormData(form);
  const ids = data.getAll('network_ids[]');
  fetch(`${BASE_PATH}/api.php?f=applyExtended`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': CSRF_TOKEN,
    },
    body: JSON.stringify({network_ids: ids})
  })
    .then(r => r.json())
    .then(json => {
      overlay.classList.remove('active');
      const cls = json.status ? 'alert-success' : 'alert-danger';
      resultBox.innerHTML = `<div class="alert ${cls}" role="alert">${json.message}</div>`;
      refreshCurrentAccess();
    })
    .catch(() => {
      overlay.classList.remove('active');
      resultBox.innerHTML = '<div class="alert alert-danger" role="alert">Request failed.</div>';
    });
});
</script>
<?php include __DIR__ . '/lib/footer.php'; ?>
