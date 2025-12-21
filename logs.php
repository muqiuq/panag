<?php
require_once __DIR__ . '/functions.php';
require_admin();

$search = trim($_GET['q'] ?? '');
$actionFilter = trim($_GET['action'] ?? '');

$params = [];
$sql = 'SELECT * FROM audit_log WHERE 1=1';
if ($actionFilter !== '') {
    $sql .= ' AND action = :action';
    $params[':action'] = $actionFilter;
}
if ($search !== '') {
    $sql .= ' AND (details LIKE :q OR username LIKE :q2 OR action LIKE :q3)';
    $like = '%' . $search . '%';
    $params[':q'] = $like;
    $params[':q2'] = $like;
    $params[':q3'] = $like;
}
$sql .= ' ORDER BY id DESC LIMIT 200';
$stmt = db()->prepare($sql);
$stmt->execute($params);
$rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

$actionStmt = db()->query('SELECT DISTINCT action FROM audit_log ORDER BY action');
$actions = $actionStmt ? $actionStmt->fetchAll(PDO::FETCH_COLUMN) : [];

include __DIR__ . '/header.php';
?>
<div class="card shadow-sm mb-4">
  <div class="card-header d-flex justify-content-between align-items-center">
    <span>Audit log</span>
    <span class="text-muted small">Showing latest 200 entries</span>
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

    <div class="table-responsive">
      <table class="table table-sm align-middle">
        <thead>
          <tr>
            <th>Time</th>
            <th>Action</th>
            <th>User</th>
            <th>Details</th>
            <th>IP</th>
          </tr>
        </thead>
        <tbody>
          <?php if (empty($rows)): ?>
            <tr><td colspan="5" class="text-muted">No entries.</td></tr>
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
<?php include __DIR__ . '/footer.php'; ?>
