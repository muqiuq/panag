<?php
// Admin: audit log – paginated, so filtering and sorting happen on the server (columns: AUDIT_LOG_SORT_COLUMNS).
require_once __DIR__ . '/../../src/bootstrap.php';
require_permission('view_logs');

$search = trim((string)($_GET['q'] ?? ''));
$actionFilter = trim((string)($_GET['action'] ?? ''));
$order = audit_log_order(isset($_GET['sort']) ? (string)$_GET['sort'] : null, isset($_GET['dir']) ? (string)$_GET['dir'] : null);
$page = max(1, (int)($_GET['page'] ?? 1));
$perPage = 100;

$params = [];
$where = 'WHERE 1=1';
if ($actionFilter !== '') {
    $where .= ' AND action = :action';
    $params[':action'] = $actionFilter;
}
if ($search !== '') {
    $where .= ' AND (details LIKE :q OR username LIKE :q2 OR action LIKE :q3 OR user_ip LIKE :q4)';
    $like = '%' . $search . '%';
    $params += [':q' => $like, ':q2' => $like, ':q3' => $like, ':q4' => $like];
}

$countStmt = db()->prepare('SELECT COUNT(*) FROM audit_log ' . $where);
$countStmt->execute($params);
$total = (int)$countStmt->fetchColumn();
$totalPages = max(1, (int)ceil($total / $perPage));
$page = min($page, $totalPages);

$stmt = db()->prepare('SELECT * FROM audit_log ' . $where . ' ' . $order['sql'] . ' LIMIT :limit OFFSET :offset');
foreach ($params as $k => $v) {
    $stmt->bindValue($k, $v);
}
$stmt->bindValue(':limit', $perPage, PDO::PARAM_INT);
$stmt->bindValue(':offset', ($page - 1) * $perPage, PDO::PARAM_INT);
$stmt->execute();
$rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

$actions = db()->query('SELECT DISTINCT action FROM audit_log ORDER BY action')->fetchAll(PDO::FETCH_COLUMN) ?: [];
$query = ['q' => $search, 'action' => $actionFilter, 'sort' => $order['key'], 'dir' => $order['dir']];
$pageLink = fn(int $p) => '?' . http_build_query(array_merge($query, ['page' => $p]));
$header = fn(string $label, string $key) => sort_header_cell($label, $key, $order['key'], $order['dir'], ['q' => $search, 'action' => $actionFilter]);

include view_path('header');
?>
<div class="card shadow-sm mb-4">
  <div class="card-header d-flex justify-content-between align-items-center">
    <span>Audit log</span>
    <span class="text-muted small">Page <?= $page ?> of <?= $totalPages ?> (<?= $total ?> entries)</span>
  </div>
  <div class="card-body">
    <form class="row g-2 mb-3" method="get">
      <input type="hidden" name="sort" value="<?= e($order['key']) ?>">
      <input type="hidden" name="dir" value="<?= e($order['dir']) ?>">
      <div class="col-md-4">
        <input type="search" class="form-control" name="q" placeholder="Search details, user, IP, action" aria-label="Search" value="<?= e($search) ?>">
      </div>
      <div class="col-md-3">
        <select class="form-select" name="action" aria-label="Action">
          <option value="">All actions</option>
          <?php foreach ($actions as $a): ?>
            <option value="<?= e($a) ?>" <?= $actionFilter === $a ? 'selected' : '' ?>><?= e($a) ?></option>
          <?php endforeach; ?>
        </select>
      </div>
      <div class="col-md-2 d-grid">
        <button class="btn btn-primary" type="submit">Filter</button>
      </div>
    </form>

    <?php $pagination = ['page' => $page, 'pages' => $totalPages, 'link' => $pageLink, 'label' => 'Audit log pagination']; include view_path('partials/pagination'); ?>

    <div class="table-responsive">
      <table class="table table-sm align-middle" id="auditLogTable" data-server-sorted>
        <thead>
          <tr>
            <?= $header('Time', 'time') ?>
            <?= $header('Action', 'action') ?>
            <?= $header('User', 'user') ?>
            <?= $header('User IP', 'user_ip') ?>
            <?= $header('Details', 'details') ?>
            <?= $header('IP', 'ip') ?>
          </tr>
        </thead>
        <tbody>
          <?php if (empty($rows)): ?>
            <tr><td colspan="6" class="text-muted">No entries.</td></tr>
          <?php endif; ?>
          <?php foreach ($rows as $row): ?>
            <tr>
              <td class="text-nowrap"><?= e(date('Y-m-d H:i:s', (int)$row['created_at'])) ?></td>
              <td><span class="badge text-bg-secondary"><?= e($row['action']) ?></span></td>
              <td><?= !empty($row['username']) ? e($row['username']) : '<span class="text-muted">n/a</span>' ?></td>
              <td><?= !empty($row['user_ip']) ? e($row['user_ip']) : '<span class="text-muted">n/a</span>' ?></td>
              <td><?= e($row['details'] ?? '') ?></td>
              <td><?= e($row['ip'] ?? '') ?></td>
            </tr>
          <?php endforeach; ?>
        </tbody>
      </table>
    </div>
  </div>
</div>
<?php include view_path('footer'); ?>
