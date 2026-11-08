<?php
// Admin: security alerts (docs/plan-security-monitoring.md). List with filters; ?id= shows one alert with its
// findings, the AI assessment, deliveries and actions (status, known place, revoke access).
require_once __DIR__ . '/../../src/bootstrap.php';
require_permission('admin');

ensure_session();
$admin = current_user();
$flash = $_SESSION['alert_flash'] ?? null;
unset($_SESSION['alert_flash']);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_csrf_token($_POST['csrf_token'] ?? null);
    $alert = fetch_alert((int)($_POST['id'] ?? 0));
    $back = url_for('admin/alerts.php') . ($alert ? '?id=' . (int)$alert['id'] : '');
    $message = ['type' => 'danger', 'message' => 'Alert not found.'];
    if ($alert) {
        switch ($_POST['action'] ?? '') {
            case 'status':
                $status = (string)($_POST['status'] ?? '');
                if (isset(ALERT_STATUSES[$status])) {
                    alert_set_status($alert, $status, $admin, trim((string)($_POST['comment'] ?? '')));
                    $message = ['type' => 'success', 'message' => 'Status set to ' . ALERT_STATUSES[$status] . '.'];
                }
                break;
            case 'known_place':
                $kind = (string)($_POST['kind'] ?? '');
                $value = (string)($_POST['value'] ?? '');
                if ($alert['user_id'] !== null && in_array([$kind, $value], alert_places($alert), true)) {
                    place_remember((int)$alert['user_id'], $kind, $value, 'admin', time());
                    log_event('known_place_added', place_label($kind, $value) . ' for alert #' . $alert['id'], (int)$admin['id'], $admin['username'], $admin['user_ip']);
                    $message = ['type' => 'success', 'message' => place_label($kind, $value) . ' is now a known place for this user.'];
                }
                break;
            case 'revoke':
                $target = $alert['user_id'] !== null ? fetch_user_by_id((int)$alert['user_id']) : null;
                if ($target) {
                    $result = remove_address_list_entries((string)$target['user_ip']);
                    log_event('revoke_access', 'Removed ' . $result['deleted'] . ' of ' . $result['total'] . ' entries for ' . $target['user_ip'] . ' (alert #' . $alert['id'] . ')', (int)$target['id'], $target['username'], $target['user_ip']);
                    $message = $result['success']
                        ? ['type' => 'success', 'message' => 'Removed ' . $result['deleted'] . ' active entries of ' . $target['username'] . '.']
                        : ['type' => 'danger', 'message' => 'Revoking failed: ' . $result['message']];
                }
                break;
        }
    }
    $_SESSION['alert_flash'] = $message;
    header('Location: ' . $back);
    exit;
}

$detail = isset($_GET['id']) ? fetch_alert((int)$_GET['id']) : null;
$statusFilter = (string)($_GET['status'] ?? 'active');
include view_path('header');
?>
<?php if ($flash): ?>
  <div class="alert alert-<?= e($flash['type']) ?>" role="alert"><?= e($flash['message']) ?></div>
<?php endif; ?>
<?php if (monitor_is_stale()): ?>
  <div class="alert alert-warning" role="alert">The last monitor cycle is older than 15 minutes – is the RouterOS scheduler running? See <a href="<?= e(url_for('admin/monitoring.php')) ?>">Monitoring</a>.</div>
<?php endif; ?>

<?php if ($detail):
  $ai = alert_ai($detail);
  $deliveries = db()->prepare('SELECT recipient, delivered_at FROM alert_deliveries WHERE alert_id = :a ORDER BY delivered_at');
  $deliveries->execute([':a' => $detail['id']]);
  $deliveries = $deliveries->fetchAll(PDO::FETCH_ASSOC);
  $places = alert_places($detail);
  $ruleRef = monitor_rule_reference();
?>
  <a href="<?= e(url_for('admin/alerts.php')) ?>" class="small">&larr; Alerts</a>
  <div class="d-flex flex-wrap align-items-center gap-2 mb-3">
    <h1 class="h4 mb-0">Alert #<?= (int)$detail['id'] ?></h1>
    <span class="badge <?= severity_badge_class((string)$detail['severity']) ?> fs-6"><?= e(strtoupper((string)$detail['severity'])) ?></span>
    <span class="badge bg-body-tertiary text-body border fs-6" data-testid="alert-status"><?= e(ALERT_STATUSES[$detail['status']] ?? $detail['status']) ?></span>
    <?php if ($detail['user_response'] === 'not_me'): ?><span class="badge text-bg-danger fs-6">User: not me</span><?php endif; ?>
    <?php if ($detail['user_response'] === 'me'): ?><span class="badge text-bg-success fs-6">User: that was me</span><?php endif; ?>
  </div>
  <div class="row g-4">
    <div class="col-lg-8">
      <div class="card shadow-sm mb-4">
        <div class="card-header d-flex justify-content-between align-items-center">Findings <a href="<?= e(url_for('admin/alerts.php')) ?>#rules" class="small">What the rules mean</a></div>
        <div class="card-body">
          <dl class="row small mb-3">
            <dt class="col-sm-3">User</dt><dd class="col-sm-9"><?= $detail['user_id'] !== null ? '<a href="' . e(url_for('admin/user.php')) . '?id=' . (int)$detail['user_id'] . '">' . e($detail['user_label']) . '</a>' : e($detail['user_label'] ?? 'system') ?></dd>
            <dt class="col-sm-3">Created</dt><dd class="col-sm-9"><?= e(date('Y-m-d H:i:s', (int)$detail['created_at'])) ?></dd>
            <dt class="col-sm-3">Updated</dt><dd class="col-sm-9"><?= e(date('Y-m-d H:i:s', (int)$detail['updated_at'])) ?></dd>
          </dl>
          <ul class="list-group">
            <?php foreach (alert_findings($detail) as $f): ?>
              <li class="list-group-item">
                <div class="d-flex flex-wrap gap-2 align-items-center">
                  <span class="badge <?= severity_badge_class((string)$f['severity']) ?>"><?= e($f['severity']) ?></span>
                  <strong><a href="<?= e(url_for('admin/alerts.php')) ?>#rule-<?= e($f['rule']) ?>" class="link-body-emphasis" title="<?= e($ruleRef[$f['rule']]['when'] ?? '') ?>"><?= e($f['rule']) ?></a> · <?= e(MONITOR_RULES[$f['rule']] ?? '') ?></strong>
                  <span class="text-muted small ms-auto"><?= e(date('Y-m-d H:i', (int)$f['at'])) ?></span>
                </div>
                <div><?= e($f['text']) ?></div>
              </li>
            <?php endforeach; ?>
          </ul>
        </div>
      </div>
      <div class="card shadow-sm mb-4">
        <div class="card-header">AI assessment</div>
        <div class="card-body" data-testid="ai-assessment">
          <?php if ($ai): ?>
            <p class="mb-2"><span class="badge <?= severity_badge_class((string)$ai['severity']) ?>"><?= e($ai['severity']) ?></span>
              <?= $ai['likely_benign'] ? 'Probably harmless' : 'Probably <strong>not</strong> harmless' ?> · confidence <?= e($ai['confidence']) ?> · suggests <?= e(str_replace('_', ' ', (string)$ai['recommended_action'])) ?></p>
            <p><?= e($ai['summary_admin']) ?></p>
            <?php if ($ai['signals']): ?><p class="small mb-1">Signals: <?= e(implode(' · ', $ai['signals'])) ?></p><?php endif; ?>
            <p class="small text-muted mb-0"><?= e((string)($ai['model'] ?? '')) ?><?= !empty($ai['provider']) ? ' via ' . e((string)$ai['provider']) : '' ?>, <?= e(date('Y-m-d H:i', (int)($ai['at'] ?? 0))) ?>. The AI can raise, never lower the rule severity.</p>
          <?php else: ?>
            <p class="text-muted mb-0"><?= e(ai_config_problem() ?? 'Not assessed (only alerts from medium are sent to the AI, within the daily limit).') ?></p>
          <?php endif; ?>
        </div>
      </div>
    </div>
    <div class="col-lg-4">
      <div class="card shadow-sm mb-4">
        <div class="card-header">Status</div>
        <div class="card-body">
          <?php if ($detail['status_by']): ?>
            <p class="small">Last change by <?= e($detail['status_by']) ?>, <?= e(date('Y-m-d H:i', (int)$detail['status_at'])) ?><?= $detail['status_comment'] ? ': ' . e($detail['status_comment']) : '' ?></p>
          <?php endif; ?>
          <form method="post" class="vstack gap-2">
            <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
            <input type="hidden" name="action" value="status">
            <input type="hidden" name="id" value="<?= (int)$detail['id'] ?>">
            <label class="form-label mb-0" for="alert-status-select">Status</label>
            <select id="alert-status-select" name="status" class="form-select form-select-sm">
              <?php foreach (ALERT_STATUSES as $key => $label): ?>
                <option value="<?= e($key) ?>" <?= $detail['status'] === $key ? 'selected' : '' ?>><?= e($label) ?></option>
              <?php endforeach; ?>
            </select>
            <label class="form-label mb-0" for="alert-comment">Comment</label>
            <input id="alert-comment" type="text" name="comment" class="form-control form-control-sm" maxlength="300">
            <button class="btn btn-sm btn-primary">Save status</button>
          </form>
        </div>
      </div>
      <?php if ($detail['user_id'] !== null): ?>
        <div class="card shadow-sm mb-4">
          <div class="card-header">Actions</div>
          <div class="card-body vstack gap-2">
            <?php foreach ($places as [$kind, $value]): ?>
              <form method="post">
                <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
                <input type="hidden" name="action" value="known_place">
                <input type="hidden" name="id" value="<?= (int)$detail['id'] ?>">
                <input type="hidden" name="kind" value="<?= e($kind) ?>">
                <input type="hidden" name="value" value="<?= e($value) ?>">
                <button class="btn btn-sm btn-outline-secondary w-100"<?= place_is_known((int)$detail['user_id'], $kind, $value) ? ' disabled' : '' ?>>Mark <?= e(place_label($kind, $value)) ?> as known for this user</button>
              </form>
            <?php endforeach; ?>
            <form method="post" data-confirm="Revoke all active access of this user now?">
              <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
              <input type="hidden" name="action" value="revoke">
              <input type="hidden" name="id" value="<?= (int)$detail['id'] ?>">
              <button class="btn btn-sm btn-outline-danger w-100">Revoke all access of this user</button>
            </form>
          </div>
        </div>
      <?php endif; ?>
      <div class="card shadow-sm">
        <div class="card-header">Mail</div>
        <div class="card-body small">
          <?php if ($detail['notified_at']): ?>
            <p class="mb-1">Sent <?= e(date('Y-m-d H:i', (int)$detail['notified_at'])) ?></p>
          <?php elseif ($detail['notify_error']): ?>
            <p class="text-danger mb-1">Not delivered: <?= e($detail['notify_error']) ?></p>
          <?php else: ?>
            <p class="mb-1">Pending<?= in_array($detail['severity'], ['info', 'low'], true) ? ' (daily digest)' : '' ?><?= $detail['notify_attempts'] ? ', ' . (int)$detail['notify_attempts'] . ' failed attempt(s)' : '' ?></p>
          <?php endif; ?>
          <?php foreach ($deliveries as $d): ?>
            <div><?= e($d['recipient']) ?> · <?= e(date('H:i', (int)$d['delivered_at'])) ?></div>
          <?php endforeach; ?>
        </div>
      </div>
    </div>
  </div>
<?php else:
  $search = trim((string)($_GET['q'] ?? ''));
  $order = alerts_order(isset($_GET['sort']) ? (string)$_GET['sort'] : null, isset($_GET['dir']) ? (string)$_GET['dir'] : null);
  $list = alert_list($statusFilter, $search, $order, (int)($_GET['page'] ?? 1));
  $alerts = $list['rows'];
  $query = ['status' => $statusFilter, 'q' => $search];
  $pagination = [
      'page' => $list['page'],
      'pages' => $list['pages'],
      'link' => fn(int $p) => '?' . http_build_query($query + ['sort' => $order['key'], 'dir' => $order['dir'], 'page' => $p]),
      'label' => 'Alerts pagination',
  ];
  $header = fn(string $label, string $key) => sort_header_cell($label, $key, $order['key'], $order['dir'], $query);
?>
  <div class="card shadow-sm">
    <div class="card-header d-flex flex-wrap justify-content-between align-items-center gap-2">
      <span>Security alerts <span class="text-muted small" data-testid="alerts-count"><?= $list['total'] ?> · page <?= $list['page'] ?> of <?= $list['pages'] ?></span></span>
      <form method="get" class="d-flex flex-wrap gap-2" role="search">
        <select name="status" class="form-select form-select-sm w-auto" aria-label="Status filter">
          <?php foreach (['active' => 'Open + acknowledged', 'all' => 'All'] + ALERT_STATUSES as $key => $label): ?>
            <option value="<?= e($key) ?>" <?= $statusFilter === $key ? 'selected' : '' ?>><?= e($label) ?></option>
          <?php endforeach; ?>
        </select>
        <input type="search" name="q" value="<?= e($search) ?>" class="form-control form-control-sm w-auto" placeholder="User, rule or text" aria-label="Search alerts">
        <input type="hidden" name="sort" value="<?= e($order['key']) ?>">
        <input type="hidden" name="dir" value="<?= e($order['dir']) ?>">
        <button class="btn btn-sm btn-outline-secondary">Show</button>
      </form>
    </div>
    <div class="card-body">
      <?php if (!MONITOR_ENABLED): ?>
        <p class="text-muted">Monitoring is off (<code>MONITOR_ENABLED=false</code>).</p>
      <?php endif; ?>
      <div class="table-responsive">
        <table class="table table-sm align-middle mb-0" id="alertsTable" data-server-sorted>
          <thead>
            <tr><?= $header('Time', 'time') ?><?= $header('Severity', 'severity') ?><?= $header('User', 'user') ?><th>Rules <a href="#rules" class="small fw-normal">(what?)</a></th><th>Summary</th><?= $header('Status', 'status') ?><th>Mail</th></tr>
          </thead>
          <tbody>
            <?php if (!$alerts): ?>
              <tr><td colspan="7" class="text-muted"><?= $search !== '' ? 'No alerts match “' . e($search) . '”.' : 'No alerts.' ?></td></tr>
            <?php endif; ?>
            <?php foreach ($alerts as $a): ?>
              <tr>
                <td class="text-nowrap"><a href="?id=<?= (int)$a['id'] ?>"><?= e(date('Y-m-d H:i', (int)$a['created_at'])) ?></a></td>
                <td><span class="badge <?= severity_badge_class((string)$a['severity']) ?>"><?= e($a['severity']) ?></span></td>
                <td><?= e($a['user_label'] ?? 'system') ?></td>
                <td class="text-nowrap"><?php foreach (array_values(array_filter(explode(',', (string)$a['rules']))) as $i => $code): ?><?= $i ? ', ' : '' ?><a href="#rule-<?= e($code) ?>" title="<?= e(MONITOR_RULES[$code] ?? $code) ?>"><code><?= e($code) ?></code></a><?php endforeach; ?></td>
                <td><a href="?id=<?= (int)$a['id'] ?>" class="link-body-emphasis"><?= e($a['summary']) ?></a><?= $a['user_response'] === 'not_me' ? ' <span class="badge text-bg-danger">not me</span>' : '' ?></td>
                <td><?= e(ALERT_STATUSES[$a['status']] ?? $a['status']) ?></td>
                <td class="small"><?= $a['notified_at'] ? 'sent' : ($a['notify_error'] ? '<span class="text-danger">failed</span>' : 'pending') ?></td>
              </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </div>
      <?php include view_path('partials/pagination'); ?>
    </div>
  </div>
  <div class="card shadow-sm mt-4" id="rules">
    <div class="card-header">Detection rules <span class="text-muted small">– thresholds as currently configured (<a href="<?= e(url_for('admin/config.php')) ?>">Config</a>)</span></div>
    <div class="card-body">
      <div class="table-responsive">
        <table class="table table-sm align-middle mb-0" data-testid="rule-reference">
          <thead>
            <tr><th>Rule</th><th>Name</th><th>Severity</th><th>Fires when</th><th>Asks the user</th></tr>
          </thead>
          <tbody>
            <?php foreach (monitor_rule_reference() as $code => $rule): ?>
              <tr id="rule-<?= e($code) ?>">
                <td><code><?= e($code) ?></code></td>
                <td class="fw-semibold"><?= e($rule['name']) ?></td>
                <td class="text-nowrap"><?php foreach ($rule['severity'] as $sev): ?><span class="badge <?= severity_badge_class($sev) ?> me-1"><?= e($sev) ?></span><?php endforeach; ?></td>
                <td class="small"><?= e($rule['when']) ?></td>
                <td class="small"><?= $rule['asks_user'] ? (MONITOR_NOTIFY_USERS ? 'yes' : 'no (MONITOR_NOTIFY_USERS=false)') : 'no' ?></td>
              </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </div>
      <p class="small text-muted mt-3 mb-0">Findings of one user within <?= e(format_duration_human(MONITOR_BUNDLE_WINDOW)) ?> are bundled into one alert; the same finding is not raised again for <?= e(format_duration_human(MONITOR_COOLDOWN)) ?>. "Asks the user" means the user gets a mail with "Was this you?" (if they have an e-mail address). Known places (countries, networks confirmed by the user or an admin) do not alert.</p>
    </div>
  </div>
<?php endif; ?>
<?php include view_path('footer'); ?>
