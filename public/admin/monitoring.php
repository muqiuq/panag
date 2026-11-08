<?php
// Admin: state of the security monitoring and test actions. Settings are only shown here – they are changed
// via environment variables (see admin/config.php).
require_once __DIR__ . '/../../src/bootstrap.php';
require_permission('admin');

ensure_session();
$admin = current_user();
$flash = $_SESSION['monitoring_flash'] ?? null;
unset($_SESSION['monitoring_flash']);
$aiTest = $_SESSION['monitoring_ai_test'] ?? null;
unset($_SESSION['monitoring_ai_test']);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_csrf_token($_POST['csrf_token'] ?? null);
    $message = ['type' => 'danger', 'message' => 'Unknown action.'];
    switch ($_POST['action'] ?? '') {
        case 'run':
            set_time_limit(120);
            $stats = run_monitor_cycle();
            $message = $stats['status'] === 'disabled'
                ? ['type' => 'warning', 'message' => 'Monitoring is off (MONITOR_ENABLED=false).']
                : ['type' => $stats['status'] === 'ok' ? 'success' : 'warning', 'message' => 'Cycle ' . $stats['status'] . ': ' . ($stats['findings'] ?? 0) . ' finding(s), ' . ($stats['alerts'] ?? 0) . ' alert(s)' . (!empty($stats['errors']) ? ' – ' . implode('; ', $stats['errors']) : '') . '.'];
            break;
        case 'test_mail':
            $to = trim((string)($_POST['to'] ?? ''));
            if (!filter_var($to, FILTER_VALIDATE_EMAIL)) {
                $message = ['type' => 'danger', 'message' => 'Enter a valid e-mail address.'];
                break;
            }
            $error = send_test_mail($to);
            log_event('monitor_test_mail', 'Test mail to ' . $to . ($error ? ' failed: ' . $error : ''), (int)$admin['id'], $admin['username'], $admin['user_ip']);
            $message = $error === null ? ['type' => 'success', 'message' => 'Test mail sent to ' . $to . '.'] : ['type' => 'danger', 'message' => 'Test mail failed: ' . $error];
            break;
        case 'test_ai':
            if (($problem = ai_config_problem()) !== null) {
                $message = ['type' => 'warning', 'message' => 'AI triage is off: ' . $problem];
                break;
            }
            $result = ai_assess(ai_test_features());
            ai_record_usage($result, time());
            $_SESSION['monitoring_ai_test'] = $result;
            $message = $result['ok'] ? ['type' => 'success', 'message' => 'AI test answered (synthetic case, no real data).'] : ['type' => 'danger', 'message' => 'AI test failed: ' . $result['error']];
            break;
        case 'geoip_update':
            set_time_limit(300);
            $messages = geoip_maybe_update(time(), true);
            $failed = array_filter($messages, fn($m) => strpos($m, 'failed') !== false);
            $message = ['type' => $failed ? 'danger' : 'success', 'message' => implode(' ', $messages)];
            break;
        case 'geoip_upload':
            $kind = ($_POST['kind'] ?? '') === 'asn' ? 'asn' : 'country';
            $file = $_FILES['database'] ?? null;
            if (!$file || !is_uploaded_file($file['tmp_name'])) {
                $message = ['type' => 'danger', 'message' => 'No file uploaded (max. 32 MB).'];
                break;
            }
            $error = geoip_install_file($file['tmp_name'], $kind);
            if ($error === null) {
                monitor_state_set('geoip.updated_at', time());
                log_event('geoip_uploaded', ucfirst($kind) . ' database uploaded', (int)$admin['id'], $admin['username'], $admin['user_ip']);
            }
            $message = $error === null ? ['type' => 'success', 'message' => ucfirst($kind) . ' database installed.'] : ['type' => 'danger', 'message' => $error];
            break;
    }
    $_SESSION['monitoring_flash'] = $message;
    header('Location: ' . url_for('admin/monitoring.php'));
    exit;
}

$lastRun = monitor_state('monitor.last_run');
$lastPollOk = (int)monitor_state('monitor.last_poll_ok_at', 0);
$peers = db()->query('SELECT p.*, u.username FROM wg_peers p LEFT JOIN users u ON u.id = p.user_id ORDER BY p.name')->fetchAll(PDO::FETCH_ASSOC);
$mails = db()->query('SELECT * FROM mail_log ORDER BY id DESC LIMIT 15')->fetchAll(PDO::FETCH_ASSOC);
$usage = ai_usage_today();
$geoip = geoip_status();
$settings = [
    ['Monitoring', MONITOR_ENABLED ? 'on' : 'off'],
    ['Allowed countries', implode(', ', MONITOR_ALLOWED_COUNTRIES)],
    ['Learning phase', MONITOR_LEARNING_DAYS . ' days'],
    ['Rapid change window', format_duration_human(MONITOR_TRAVEL_WINDOW)],
    ['Failed logins', MONITOR_FAILED_LOGINS . ' in ' . format_duration_human(MONITOR_FAILED_LOGINS_WINDOW)],
    ['Bundling / cooldown', format_duration_human(MONITOR_BUNDLE_WINDOW) . ' / ' . format_duration_human(MONITOR_COOLDOWN)],
    ['Daily digest', MONITOR_DIGEST_TIME],
    ['Mail users', MONITOR_NOTIFY_USERS ? 'yes' : 'no'],
    ['Mail', mail_config_problem() ?? (SMTP_HOST . ':' . SMTP_PORT . ' (' . SMTP_SECURITY . ')')],
    ['Admin recipients', implode(', ', admin_alert_recipients()) ?: 'none – add e-mail addresses to admins or set ALERT_ADMIN_EMAILS'],
    ['AI', ai_config_problem() ?? (OPENROUTER_MODEL . ' via ' . implode(', ', OPENROUTER_PROVIDERS) . ', effort ' . OPENROUTER_REASONING_EFFORT)],
    ['Retention', 'IP addresses ' . MONITOR_IP_RETENTION_DAYS . ' days, alerts ' . MONITOR_ALERT_RETENTION_DAYS . ' days'],
];
include view_path('header');
?>
<?php if ($flash): ?>
  <div class="alert alert-<?= e($flash['type']) ?>" role="alert"><?= e($flash['message']) ?></div>
<?php endif; ?>
<?php if (monitor_is_stale()): ?>
  <div class="alert alert-warning" role="alert">No monitor cycle in the last 15 minutes – check the RouterOS scheduler (docs/deploy-mikrotik.md).</div>
<?php endif; ?>
<div class="row g-4">
  <div class="col-lg-6">
    <div class="card shadow-sm h-100">
      <div class="card-header d-flex justify-content-between align-items-center">
        <span>Status</span>
        <span class="badge <?= MONITOR_ENABLED ? 'text-bg-success' : 'text-bg-secondary' ?>"><?= MONITOR_ENABLED ? 'on' : 'off' ?></span>
      </div>
      <div class="card-body">
        <dl class="row small mb-3" data-testid="monitor-status">
          <dt class="col-5">Last cycle</dt>
          <dd class="col-7"><?= is_array($lastRun) ? e(date('Y-m-d H:i:s', (int)$lastRun['at'])) . ' · ' . e((string)$lastRun['status']) . ' · ' . (int)($lastRun['duration_ms'] ?? 0) . ' ms' : 'never' ?></dd>
          <?php if (is_array($lastRun) && !empty($lastRun['errors'])): ?>
            <dt class="col-5">Errors</dt><dd class="col-7 text-danger"><?= e(implode('; ', $lastRun['errors'])) ?></dd>
          <?php endif; ?>
          <dt class="col-5">Last router poll</dt><dd class="col-7"><?= $lastPollOk ? e(date('Y-m-d H:i:s', $lastPollOk)) : 'never' ?></dd>
          <dt class="col-5">Open alerts</dt><dd class="col-7"><a href="<?= e(url_for('admin/alerts.php')) ?>"><?= open_alert_count() ?></a></dd>
        </dl>
        <form method="post">
          <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
          <input type="hidden" name="action" value="run">
          <button class="btn btn-sm btn-primary"<?= MONITOR_ENABLED ? '' : ' disabled' ?>>Run cycle now</button>
        </form>
      </div>
    </div>
  </div>
  <div class="col-lg-6">
    <div class="card shadow-sm h-100">
      <div class="card-header">Effective settings <span class="text-muted small">– change via environment variables</span></div>
      <div class="card-body">
        <dl class="row small mb-2">
          <?php foreach ($settings as [$label, $value]): ?>
            <dt class="col-5"><?= e($label) ?></dt><dd class="col-7 text-break"><?= e((string)$value) ?></dd>
          <?php endforeach; ?>
        </dl>
        <a href="<?= e(url_for('admin/config.php')) ?>" class="small">All settings and their sources</a>
      </div>
    </div>
  </div>

  <div class="col-12">
    <div class="card shadow-sm">
      <div class="card-header">WireGuard peers</div>
      <div class="card-body">
        <div class="table-responsive">
          <table class="table table-sm align-middle mb-0" id="monitorPeersTable" data-sortable>
            <thead><tr><th>Peer</th><th>User</th><th data-sort="ip">Endpoint</th><th>Country</th><th data-sort="number">ASN</th><th data-sort="number">Last handshake</th><th data-sort="number">Endpoint since</th></tr></thead>
            <tbody>
              <?php if (!$peers): ?><tr><td colspan="7" class="text-muted">No peers polled yet.</td></tr><?php endif; ?>
              <?php foreach ($peers as $p): ?>
                <tr>
                  <td><?= e($p['name'] ?: substr((string)$p['public_key'], 0, 10) . '…') ?></td>
                  <td><?= $p['username'] ? e($p['username']) : '<span class="text-warning-emphasis">unknown</span>' ?></td>
                  <td><code><?= e($p['endpoint'] ?? '') ?></code></td>
                  <td><?= e($p['country'] ?? '') ?></td>
                  <td data-sort-value="<?= e((string)($p['asn'] ?? '')) ?>"><?= $p['asn'] ? 'AS' . (int)$p['asn'] . (is_hosting_asn((int)$p['asn']) ? ' <span class="badge text-bg-warning">hosting</span>' : '') : '' ?></td>
                  <td data-sort-value="<?= e((string)($p['last_handshake_at'] ?? '')) ?>"><?= $p['last_handshake_at'] ? e(date('Y-m-d H:i', (int)$p['last_handshake_at'])) : 'never' ?></td>
                  <td data-sort-value="<?= e((string)($p['endpoint_changed_at'] ?? '')) ?>"><?= $p['endpoint_changed_at'] ? e(date('Y-m-d H:i', (int)$p['endpoint_changed_at'])) : '' ?></td>
                </tr>
              <?php endforeach; ?>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>

  <div class="col-lg-6">
    <div class="card shadow-sm h-100">
      <div class="card-header">GeoIP</div>
      <div class="card-body">
        <?php foreach ($geoip as $db): ?>
          <div class="mb-2 small" data-testid="geoip-<?= e($db['kind']) ?>">
            <strong><?= $db['kind'] === 'asn' ? 'ASN' : 'Country' ?>:</strong>
            <?php if (!$db['exists']): ?>
              <span class="text-danger">missing</span> (<code><?= e($db['path']) ?></code>)<?= $db['kind'] === 'asn' ? ' – ASN rules are off' : ' – location rules are off' ?>
            <?php elseif ($db['error']): ?>
              <span class="text-danger"><?= e($db['error']) ?></span>
            <?php else: ?>
              <?= e((string)$db['type']) ?>, built <?= e(date('Y-m-d', (int)$db['built'])) ?>, <?= e(number_format((int)$db['size'] / 1048576, 1)) ?> MB
            <?php endif; ?>
          </div>
        <?php endforeach; ?>
        <p class="small text-muted"><?= e(GEOIP_ATTRIBUTION) ?>. Auto-update: <?= GEOIP_AUTO_UPDATE ? 'monthly' : 'off' ?>.</p>
        <form method="post" class="mb-3">
          <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
          <input type="hidden" name="action" value="geoip_update">
          <button class="btn btn-sm btn-outline-secondary">Download DB-IP Lite now</button>
        </form>
        <form method="post" enctype="multipart/form-data" class="row g-2 align-items-center">
          <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
          <input type="hidden" name="action" value="geoip_upload">
          <div class="col-sm-4">
            <select name="kind" class="form-select form-select-sm" aria-label="Database kind"><option value="country">Country</option><option value="asn">ASN</option></select>
          </div>
          <div class="col-sm-5"><input type="file" name="database" accept=".mmdb" class="form-control form-control-sm" aria-label="MMDB file" required></div>
          <div class="col-sm-3"><button class="btn btn-sm btn-outline-primary w-100">Upload</button></div>
        </form>
      </div>
    </div>
  </div>
  <div class="col-lg-6">
    <div class="card shadow-sm h-100">
      <div class="card-header">Mail</div>
      <div class="card-body">
        <form method="post" class="row g-2 align-items-end mb-3">
          <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
          <input type="hidden" name="action" value="test_mail">
          <div class="col-sm-8">
            <label class="form-label small" for="test-mail-to">Send a test mail to</label>
            <input id="test-mail-to" type="email" name="to" class="form-control form-control-sm" value="<?= e((string)($admin['email'] ?? (ALERT_ADMIN_EMAILS[0] ?? ''))) ?>" required>
          </div>
          <div class="col-sm-4"><button class="btn btn-sm btn-outline-primary w-100">Send test mail</button></div>
        </form>
        <table class="table table-sm small mb-0" id="mailLogTable" data-sortable>
          <thead><tr><th data-sort="number">Time</th><th>Kind</th><th>To</th><th>Result</th></tr></thead>
          <tbody>
            <?php if (!$mails): ?><tr><td colspan="4" class="text-muted">No mails yet.</td></tr><?php endif; ?>
            <?php foreach ($mails as $m): ?>
              <tr><td data-sort-value="<?= (int)$m['created_at'] ?>"><?= e(date('m-d H:i', (int)$m['created_at'])) ?></td><td><?= e($m['kind']) ?></td><td><?= e($m['recipient']) ?></td>
                <td><?= (int)$m['ok'] ? 'sent' : '<span class="text-danger">' . e((string)$m['error']) . '</span>' ?></td></tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </div>
    </div>
  </div>
  <div class="col-12">
    <div class="card shadow-sm">
      <div class="card-header">AI triage</div>
      <div class="card-body">
        <p class="small mb-2">Today: <?= (int)$usage['calls'] ?> of <?= (int)MONITOR_AI_MAX_CALLS_PER_DAY ?> calls<?= $usage['failures'] ? ', ' . (int)$usage['failures'] . ' failed' : '' ?>, <?= (int)$usage['prompt_tokens'] ?> input / <?= (int)$usage['completion_tokens'] ?> output tokens.
          Only pseudonymised facts are sent; zero data retention and <code>data_collection: deny</code> are always enforced.</p>
        <form method="post" class="mb-2">
          <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
          <input type="hidden" name="action" value="test_ai">
          <button class="btn btn-sm btn-outline-primary"<?= ai_config_problem() === null ? '' : ' disabled' ?>>Test AI with a synthetic case</button>
        </form>
        <?php if (is_array($aiTest) && $aiTest['ok']): ?>
          <div class="small" data-testid="ai-test-result">
            <span class="badge <?= severity_badge_class((string)$aiTest['result']['severity']) ?>"><?= e($aiTest['result']['severity']) ?></span>
            <?= e($aiTest['result']['summary_admin']) ?> <span class="text-muted">(<?= e((string)($aiTest['model'] ?? '')) ?><?= !empty($aiTest['provider']) ? ' via ' . e((string)$aiTest['provider']) : '' ?>)</span>
          </div>
        <?php endif; ?>
      </div>
    </div>
  </div>
</div>
<?php include view_path('footer'); ?>
