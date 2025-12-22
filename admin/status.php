<?php
require_once __DIR__ . '/../lib/functions.php';
require_once __DIR__ . '/../lib/statistics.php';
require_admin();

$identityRes = mikrotik_identity();
$uptimeRes = mikrotik_uptime();
$clockRes = mikrotik_clock();
$peersRes = mikrotik_wireguard_peers();
$stats = statistics_overview($peersRes);
$adminOverview = admin_access_overview();
$allUsers = $adminOverview['allUsers'];
$accessReport = $adminOverview['accessReport'];
$lastLogins = $adminOverview['lastLogins'];
$loggedInToday = $adminOverview['loggedInToday'];

$identityName = $identityRes['data']['name'] ?? null;
$uptimeValue = $uptimeRes['data']['uptime'] ?? null;
$routerDate = $clockRes['data']['date'] ?? null;
$routerTime = $clockRes['data']['time'] ?? null;
$routerTz = $clockRes['data']['time_zone'] ?? ($clockRes['data']['time-zone-name'] ?? ($clockRes['data']['gmt_offset'] ?? null));
$routerTimeDisplay = ($routerDate && $routerTime) ? ($routerDate . ' ' . $routerTime) : ($routerTime ?? $routerDate ?? null);
$serverTimeDisplay = date('Y-m-d H:i:s');
$serverTz = date_default_timezone_get();
$peers = is_array($peersRes['data'] ?? null) ? $peersRes['data'] : [];

function wg_format_bytes($bytes): string
{
    if (!is_numeric($bytes)) {
        return 'n/a';
    }
    $bytes = (float)$bytes;
    $units = ['B','KB','MB','GB','TB'];
    $i = 0;
    while ($bytes >= 1024 && $i < count($units) - 1) {
        $bytes /= 1024;
        $i++;
    }
    return sprintf('%.1f %s', $bytes, $units[$i]);
}

function wg_format_handshake($value): string
{
    if ($value === null || $value === '') {
        return 'n/a';
    }
    // RouterOS may return RFC3339 or a timestamp; handle both.
    if (is_numeric($value)) {
        return date('Y-m-d H:i:s', (int)$value);
    }
    $ts = strtotime((string)$value);
    return $ts ? date('Y-m-d H:i:s', $ts) : (string)$value;
}

include __DIR__ . '/../lib/header.php';
?>
<div class="row g-4">
  <div class="col-12">
    <div class="card shadow-sm">
      <div class="card-header d-flex justify-content-between align-items-center">
        <span>Status</span>
        <?php $apiOk = ($identityRes['success'] ?? false) && ($uptimeRes['success'] ?? false) && ($clockRes['success'] ?? false); ?>
        <?php if ($apiOk): ?>
          <span class="badge bg-success">API OK</span>
        <?php else: ?>
          <span class="badge bg-danger">API error</span>
        <?php endif; ?>
      </div>
      <div class="card-body">
        <?php if (!($identityRes['success'] ?? false)): ?>
          <div class="alert alert-danger" role="alert">Failed to fetch identity<?= $identityRes['error'] ? ': ' . htmlspecialchars((string)$identityRes['error']) : '' ?></div>
        <?php endif; ?>
        <?php if (!($uptimeRes['success'] ?? false)): ?>
          <div class="alert alert-danger" role="alert">Failed to fetch uptime<?= $uptimeRes['error'] ? ': ' . htmlspecialchars((string)$uptimeRes['error']) : '' ?></div>
        <?php endif; ?>
        <?php if (!($clockRes['success'] ?? false)): ?>
          <div class="alert alert-danger" role="alert">Failed to fetch router time<?= $clockRes['error'] ? ': ' . htmlspecialchars((string)$clockRes['error']) : '' ?></div>
        <?php endif; ?>
        <div class="row g-3">
          <div class="col-md-6">
            <div class="p-3 border rounded bg-light h-100">
              <div class="text-muted small">Identity</div>
              <div class="fs-5 fw-semibold mb-0"><?= $identityName ? htmlspecialchars($identityName) : 'n/a' ?></div>
            </div>
          </div>
          <div class="col-md-6">
            <div class="p-3 border rounded bg-light h-100">
              <div class="text-muted small">Uptime</div>
              <div class="fs-5 fw-semibold mb-0"><?= $uptimeValue ? htmlspecialchars($uptimeValue) : 'n/a' ?></div>
            </div>
          </div>
        </div>
        <div class="row g-3 mt-1">
          <div class="col-md-6">
            <div class="p-3 border rounded bg-light h-100">
              <div class="text-muted small">Router time</div>
              <div class="fs-6 fw-semibold mb-0"><?= $routerTimeDisplay ? htmlspecialchars($routerTimeDisplay) : 'n/a' ?></div>
              <div class="text-muted small">Timezone: <?= $routerTz ? htmlspecialchars($routerTz) : 'n/a' ?></div>
            </div>
          </div>
          <div class="col-md-6">
            <div class="p-3 border rounded bg-light h-100">
              <div class="text-muted small">PHP server time</div>
              <div class="fs-6 fw-semibold mb-0"><?= htmlspecialchars($serverTimeDisplay) ?></div>
              <div class="text-muted small">Timezone: <?= htmlspecialchars($serverTz) ?></div>
            </div>
          </div>
        </div>
        <div class="mt-3 d-flex justify-content-end">
          <a href="<?= htmlspecialchars(url_for('status_public.php')) ?>" class="btn btn-outline-dark btn-sm">View public status</a>
        </div>
      </div>
    </div>
  </div>

  <div class="col-12">
    <?php include __DIR__ . '/partials/api_status_card.php'; ?>
  </div>

  <div class="col-12">
    <div class="card shadow-sm">
      <div class="card-header">Statistics</div>
      <div class="card-body">
        <div class="row row-cols-1 row-cols-md-3 g-3">
          <div class="col">
            <div class="p-3 border rounded bg-light h-100">
              <div class="text-muted small">Users logged in today</div>
              <div class="fs-5 fw-semibold mb-0"><?= htmlspecialchars($stats['logins_today'] ?? 0) ?> / <?= htmlspecialchars($stats['total_users'] ?? 0) ?></div>
              <?php if (isset($stats['login_coverage_pct'])): ?>
                <div class="text-muted small">Coverage: <?= htmlspecialchars($stats['login_coverage_pct']) ?>%</div>
              <?php endif; ?>
            </div>
          </div>
          <div class="col">
            <div class="p-3 border rounded bg-light h-100">
              <div class="text-muted small">Login failures today</div>
              <div class="fs-5 fw-semibold mb-0"><?= htmlspecialchars($stats['login_fails_today'] ?? 0) ?></div>
            </div>
          </div>
          <div class="col">
            <div class="p-3 border rounded bg-light h-100">
              <div class="text-muted small">Audit events today</div>
              <div class="fs-5 fw-semibold mb-0"><?= htmlspecialchars($stats['audit_events_today'] ?? 0) ?></div>
            </div>
          </div>
          <div class="col">
            <div class="p-3 border rounded bg-light h-100">
              <div class="text-muted small">Networks configured</div>
              <div class="fs-5 fw-semibold mb-0"><?= htmlspecialchars($stats['total_networks'] ?? 0) ?></div>
            </div>
          </div>
          <div class="col">
            <div class="p-3 border rounded bg-light h-100">
              <div class="text-muted small">Access list entries</div>
              <?php if (array_key_exists('accesses_granted', $stats) && $stats['accesses_granted'] !== null): ?>
                <div class="fs-5 fw-semibold mb-0"><?= htmlspecialchars($stats['accesses_granted']) ?></div>
              <?php else: ?>
                <div class="fs-5 fw-semibold mb-0 text-danger">n/a</div>
                <?php if (!empty($stats['access_error'])): ?>
                  <div class="text-danger small"><?= htmlspecialchars($stats['access_error']) ?></div>
                <?php endif; ?>
              <?php endif; ?>
            </div>
          </div>
          <div class="col">
            <div class="p-3 border rounded bg-light h-100">
              <div class="text-muted small">WireGuard peers<?php if (defined('WIREGUARD_INTERFACE') && WIREGUARD_INTERFACE !== ''): ?> (<?= htmlspecialchars(WIREGUARD_INTERFACE) ?>)<?php endif; ?></div>
              <div class="fs-5 fw-semibold mb-0"><?= htmlspecialchars($stats['wireguard_peers'] ?? 0) ?></div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <div class="col-12">
    <div class="card shadow-sm">
      <div class="card-header d-flex justify-content-between align-items-center">
        <span>WireGuard peers<?php if (defined('WIREGUARD_INTERFACE') && WIREGUARD_INTERFACE !== ''): ?> (<?= htmlspecialchars(WIREGUARD_INTERFACE) ?>)<?php endif; ?></span>
        <?php if ($peersRes['success'] ?? false): ?>
          <span class="badge bg-success">Loaded</span>
        <?php else: ?>
          <span class="badge bg-danger">API error</span>
        <?php endif; ?>
      </div>
      <div class="card-body">
        <?php if (!($peersRes['success'] ?? false)): ?>
          <div class="alert alert-danger" role="alert">Failed to fetch peers<?= $peersRes['error'] ? ': ' . htmlspecialchars((string)$peersRes['error']) : '' ?></div>
        <?php endif; ?>
        <?php if (empty($peers)): ?>
          <p class="text-muted mb-0">No peers found.</p>
        <?php else: ?>
          <div class="table-responsive">
            <table class="table table-sm align-middle mb-0">
              <thead>
                <tr>
                  <th>Public key</th>
                  <th>Comment</th>
                  <th>Name</th>
                  <th>Last handshake</th>
                  <th class="text-end">TX</th>
                  <th class="text-end">RX</th>
                </tr>
              </thead>
              <tbody>
                <?php foreach ($peers as $peer): ?>
                  <tr>
                    <td class="small text-break" style="max-width: 220px;"><?= htmlspecialchars($peer['public-key'] ?? $peer['public_key'] ?? 'n/a') ?></td>
                    <td><?= htmlspecialchars($peer['comment'] ?? '') ?></td>
                    <td><?= htmlspecialchars($peer['name'] ?? '') ?></td>
                    <td class="small text-muted"><?= htmlspecialchars(wg_format_handshake($peer['last-handshake'] ?? $peer['last_handshake'] ?? null)) ?></td>
                    <td class="text-end small"><?= htmlspecialchars(wg_format_bytes($peer['tx'] ?? $peer['tx-byte'] ?? $peer['tx_bytes'] ?? null)) ?></td>
                    <td class="text-end small"><?= htmlspecialchars(wg_format_bytes($peer['rx'] ?? $peer['rx-byte'] ?? $peer['rx_bytes'] ?? null)) ?></td>
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
<script>
const BASE_PATH = document.body.dataset.basePath || '';
const CSRF_TOKEN = document.querySelector('meta[name="csrf-token"]')?.content || document.body.dataset.csrfToken || '';
const revokeResult = document.getElementById('revokeResult');

document.querySelectorAll('.revoke-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const uid = btn.dataset.userId;
    const uname = btn.dataset.username;
    if (!uid) return;
    if (!confirm(`Revoke all access for ${uname}?`)) return;
    if (revokeResult) {
      revokeResult.innerHTML = '';
    }
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
        if (revokeResult) {
          revokeResult.innerHTML = `<div class="alert ${cls}" role="alert">${data.message || 'Done.'}</div>`;
        }
        if (data.status) {
          setTimeout(() => window.location.reload(), 600);
        }
      })
      .catch(() => {
        if (revokeResult) {
          revokeResult.innerHTML = '<div class="alert alert-danger" role="alert">Revoke request failed.</div>';
        }
      });
  });
});
</script>
<?php include __DIR__ . '/../lib/footer.php'; ?>
