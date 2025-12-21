<?php
require_once __DIR__ . '/../lib/functions.php';
require_admin();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  require_csrf_token($_POST['csrf_token'] ?? null);
    $action = $_POST['action'] ?? '';
    if ($action === 'create') {
        save_network(null, trim($_POST['name'] ?? ''), (int)($_POST['accesslevel'] ?? 0), trim($_POST['address'] ?? ''));
    } elseif ($action === 'update') {
        save_network((int)($_POST['id'] ?? 0), trim($_POST['name'] ?? ''), (int)($_POST['accesslevel'] ?? 0), trim($_POST['address'] ?? ''));
    } elseif ($action === 'delete') {
        delete_network((int)($_POST['id'] ?? 0));
    }
    header('Location: ' . url_for('admin/config_networks.php'));
    exit;
}

$networks = get_all_networks();
  include __DIR__ . '/../lib/header.php';
?>
<div class="card shadow-sm mb-4">
  <div class="card-header">Add network</div>
  <div class="card-body">
    <form method="post" class="row g-3">
      <input type="hidden" name="action" value="create">
      <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
      <div class="col-md-4">
        <label class="form-label">Name</label>
        <input type="text" name="name" class="form-control" required>
      </div>
      <div class="col-md-3">
        <label class="form-label">Access level</label>
        <input type="number" name="accesslevel" class="form-control" min="0" max="<?= (int)MAX_ACCESS_LEVEL ?>" value="0" required>
      </div>
      <div class="col-md-4">
        <label class="form-label">Address</label>
        <input type="text" name="address" class="form-control" placeholder="10.0.0.0/24" required>
      </div>
      <div class="col-md-1 d-flex align-items-end">
        <button class="btn btn-primary w-100" type="submit">Add</button>
      </div>
    </form>
  </div>
</div>

<div class="card shadow-sm">
  <div class="card-header">Existing networks</div>
  <div class="card-body">
    <div class="table-responsive">
      <table class="table table-sm align-middle">
        <thead>
          <tr>
            <th>Name</th>
            <th>Access level</th>
            <th>Address</th>
            <th class="text-end">Actions</th>
          </tr>
        </thead>
        <tbody>
          <?php foreach ($networks as $n): ?>
            <tr>
              <form method="post">
                <td><input type="text" name="name" class="form-control form-control-sm" value="<?= htmlspecialchars($n['name']) ?>" required></td>
                <td><input type="number" name="accesslevel" class="form-control form-control-sm" min="0" max="<?= (int)MAX_ACCESS_LEVEL ?>" value="<?= (int)$n['accesslevel'] ?>" required></td>
                <td><input type="text" name="address" class="form-control form-control-sm" value="<?= htmlspecialchars($n['address']) ?>" required></td>
                <td class="text-end">
                  <input type="hidden" name="id" value="<?= (int)$n['id'] ?>">
                  <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
                  <button class="btn btn-sm btn-success" name="action" value="update">Save</button>
                  <button class="btn btn-sm btn-danger" name="action" value="delete" onclick="return confirm('Delete network?');">Delete</button>
                </td>
              </form>
            </tr>
          <?php endforeach; ?>
        </tbody>
      </table>
    </div>
  </div>
</div>
<?php include __DIR__ . '/../lib/footer.php'; ?>
