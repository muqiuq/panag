<?php
require_once __DIR__ . '/../lib/functions.php';
require_admin();

$search = trim($_GET['q'] ?? '');
$actionFilter = trim($_GET['action'] ?? '');
$page = max(1, (int)($_GET['page'] ?? 1));
$perPage = 100;
$offset = ($page - 1) * $perPage;

$params = [];
$where = 'WHERE 1=1';
if ($actionFilter !== '') {
  $where .= ' AND action = :action';
  $params[':action'] = $actionFilter;
}
if ($search !== '') {
  $where .= ' AND (details LIKE :q OR username LIKE :q2 OR action LIKE :q3)';
  $like = '%' . $search . '%';
  $params[':q'] = $like;
  $params[':q2'] = $like;
  $params[':q3'] = $like;
}

$countStmt = db()->prepare('SELECT COUNT(*) FROM audit_log ' . $where);
$countStmt->execute($params);
$total = (int)$countStmt->fetchColumn();
$totalPages = max(1, (int)ceil($total / $perPage));
if ($page > $totalPages) {
  $page = $totalPages;
  $offset = ($page - 1) * $perPage;
}

$dataSql = 'SELECT * FROM audit_log ' . $where . ' ORDER BY id DESC LIMIT :limit OFFSET :offset';
$stmt = db()->prepare($dataSql);
foreach ($params as $k => $v) {
  $stmt->bindValue($k, $v);
}
$stmt->bindValue(':limit', $perPage, PDO::PARAM_INT);
$stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
$stmt->execute();
$rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

$actionStmt = db()->query('SELECT DISTINCT action FROM audit_log ORDER BY action');
$actions = $actionStmt ? $actionStmt->fetchAll(PDO::FETCH_COLUMN) : [];

include __DIR__ . '/../lib/header.php';
?>
<div class="card shadow-sm mb-4">
  <div class="card-header d-flex justify-content-between align-items-center">
    <span>Audit log</span>
    <span class="text-muted small">Page <?= (int)$page ?> of <?= (int)$totalPages ?> (<?= (int)$total ?> entries)</span>
  </div>
  <div class="card-body">
    <form class="row g-2 mb-3" method="get">
      <div class="col-md-4">
        <input type="text" class="form-control" name="q" placeholder="Search details, user, action" value="<?= htmlspecialchars($search) ?>">
      </div>
      <div class="col-md-3">
        <select class="form-select" name="action">
          <option value="">All actions</option>
          <?php foreach ($actions as $a): ?>
            <option value="<?= htmlspecialchars($a) ?>" <?= $actionFilter === $a ? 'selected' : '' ?>><?= htmlspecialchars($a) ?></option>
          <?php endforeach; ?>
        </select>
      </div>
      <div class="col-md-2 d-grid">
        <button class="btn btn-primary" type="submit">Filter</button>
      </div>
    </form>

    <nav aria-label="Audit log pagination" class="mb-3">
      <ul class="pagination mb-0">
        <?php
          $queryBase = ['q' => $search, 'action' => $actionFilter];
          $prevPage = max(1, $page - 1);
          $nextPage = min($totalPages, $page + 1);
          $prevQuery = http_build_query(array_merge($queryBase, ['page' => $prevPage]));
          $nextQuery = http_build_query(array_merge($queryBase, ['page' => $nextPage]));
        ?>
        <li class="page-item <?= $page <= 1 ? 'disabled' : '' ?>">
          <a class="page-link" href="?<?= htmlspecialchars($prevQuery) ?>" aria-label="Previous">&laquo;</a>
        </li>
        <li class="page-item disabled"><span class="page-link">Page <?= (int)$page ?> / <?= (int)$totalPages ?></span></li>
        <li class="page-item <?= $page >= $totalPages ? 'disabled' : '' ?>">
          <a class="page-link" href="?<?= htmlspecialchars($nextQuery) ?>" aria-label="Next">&raquo;</a>
        </li>
      </ul>
    </nav>

    <div class="table-responsive">
      <table class="table table-sm align-middle">
        <thead>
          <tr>
            <th>Time</th>
            <th>Action</th>
            <th>User</th>
            <th>User IP</th>
            <th>Details</th>
            <th>IP</th>
          </tr>
        </thead>
        <tbody>
          <?php if (empty($rows)): ?>
            <tr><td colspan="6" class="text-muted">No entries.</td></tr>
          <?php else: ?>
            <?php foreach ($rows as $row): ?>
              <tr>
                <td><?= htmlspecialchars(date('Y-m-d H:i:s', (int)$row['created_at'])) ?></td>
                <td><span class="badge bg-secondary"><?= htmlspecialchars($row['action']) ?></span></td>
                <td>
                  <?php if (!empty($row['username'])): ?>
                    <?= htmlspecialchars($row['username']) ?>
                  <?php else: ?>
                    <span class="text-muted">n/a</span>
                  <?php endif; ?>
                </td>
                <td>
                  <?php if (!empty($row['user_ip'])): ?>
                    <?= htmlspecialchars($row['user_ip']) ?>
                  <?php else: ?>
                    <span class="text-muted">n/a</span>
                  <?php endif; ?>
                </td>
                <td><?= htmlspecialchars($row['details'] ?? '') ?></td>
                <td><?= htmlspecialchars($row['ip'] ?? '') ?></td>
              </tr>
            <?php endforeach; ?>
          <?php endif; ?>
        </tbody>
      </table>
    </div>
  </div>
</div>
<?php include __DIR__ . '/../lib/footer.php'; ?>
