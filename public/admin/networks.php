<?php
// Admin: networks (sortable table). Add/edit in a dialog; "Default for N users" opens the reverse view of
// the default networks (all users eligible for the network, saved immediately). JS: public/js/networks.js
require_once __DIR__ . '/../../src/bootstrap.php';
require_permission('manage_networks');

ensure_session();
$admin = current_user();
$flash = $_SESSION['network_flash'] ?? null;
unset($_SESSION['network_flash']);
$back = static function (string $type, string $message): void {
    $_SESSION['network_flash'] = ['type' => $type, 'message' => $message];
    header('Location: ' . url_for('admin/networks.php'));
    exit;
};

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_csrf_token($_POST['csrf_token'] ?? null);
    $action = $_POST['action'] ?? '';
    if ($action === 'save') {
        $id = (int)($_POST['id'] ?? 0);
        $name = trim((string)($_POST['name'] ?? ''));
        $address = trim((string)($_POST['address'] ?? ''));
        $level = max(0, min((int)($_POST['accesslevel'] ?? 0), (int)MAX_ACCESS_LEVEL));
        $sensitive = !empty($_POST['sensitive']);
        $existing = $id > 0 ? fetch_network_by_id($id) : null;
        if ($id > 0 && !$existing) {
            $back('danger', 'Network not found.');
        }
        $errors = validate_network_input($name, $address);
        if ($errors) {
            $back('danger', 'Network not saved: ' . implode(' ', $errors));
        }
        $removed = save_network($existing ? $id : null, $name, $level, $address, $sensitive);
        log_event($existing ? 'network_updated' : 'network_created', $name . ' (' . $address . ', L' . $level . ($sensitive ? ', sensitive' : '') . ') by ' . $admin['username']
            . ($removed ? ' – removed from the default networks of ' . $removed . ' user(s)' : ''), (int)$admin['id'], $admin['username'], $admin['user_ip']);
        $back('success', 'Network ' . $name . ' saved.' . ($removed ? ' It is sensitive now and was removed from the default networks of ' . $removed . ' user(s).' : ''));
    } elseif ($action === 'delete') {
        $network = fetch_network_by_id((int)($_POST['id'] ?? 0));
        if ($network) {
            delete_network((int)$network['id']);
            log_event('network_deleted', $network['name'] . ' (' . $network['address'] . ') by ' . $admin['username'], (int)$admin['id'], $admin['username'], $admin['user_ip']);
            $back('success', 'Network ' . $network['name'] . ' deleted.');
        }
        $back('danger', 'Network not found.');
    }
    $back('danger', 'Unknown action.');
}

$networks = get_all_networks();
$counts = default_network_counts();
$users = db()->query('SELECT id, username, user_ip, accesslevel FROM users ORDER BY username COLLATE NOCASE')->fetchAll(PDO::FETCH_ASSOC);
$assignments = [];
foreach (default_network_assignments() as $a) {
    $assignments[$a['network_id']][] = $a['user_id'];
}
$pageData = [
    'users' => array_map(fn($u) => ['id' => (int)$u['id'], 'name' => $u['username'], 'ip' => $u['user_ip'], 'level' => (int)$u['accesslevel']], $users),
    'networks' => array_map(fn($n) => ['id' => (int)$n['id'], 'name' => $n['name'], 'level' => (int)$n['accesslevel']], $networks),
    'assignments' => (object)$assignments,
];
$pageScripts = ['js/networks.js'];
include view_path('header');
?>
<?php if ($flash): ?>
  <div class="alert alert-<?= e($flash['type']) ?>" role="alert"><?= e($flash['message']) ?></div>
<?php endif; ?>

<div class="card shadow-sm mb-4">
  <div class="card-header d-flex flex-wrap justify-content-between align-items-center gap-2">
    <span>Networks <span class="badge text-bg-secondary"><?= count($networks) ?></span></span>
    <div class="d-flex gap-2">
      <input type="search" class="form-control form-control-sm w-auto" placeholder="Filter networks" aria-label="Filter networks" data-table-filter="networksAdminTable">
      <button type="button" class="btn btn-sm btn-primary" data-bs-toggle="modal" data-bs-target="#networkModal">Add network</button>
    </div>
  </div>
  <div class="card-body">
    <?php if (empty($networks)): ?>
      <p class="text-muted mb-0">No networks yet.</p>
    <?php else: ?>
      <div class="table-responsive">
        <table class="table table-sm align-middle mb-0" id="networksAdminTable" data-sortable>
          <thead>
            <tr><th>Name</th><th data-sort="ip">Address</th><th data-sort="number">Level</th><th data-sort="number">Default for</th><th data-sort="none" class="text-end"><span class="visually-hidden">Actions</span></th></tr>
          </thead>
          <tbody>
            <?php foreach ($networks as $n): $nid = (int)$n['id']; $count = $counts[$nid] ?? 0; ?>
              <tr data-network-id="<?= $nid ?>">
                <td><?= e($n['name']) ?><?php if (network_is_sensitive($n)): ?> <span class="badge text-bg-warning" title="Never a default network – single grants only">sensitive</span><?php endif; ?></td>
                <td><code><?= e($n['address']) ?></code></td>
                <td data-sort-value="<?= (int)$n['accesslevel'] ?>">L<?= (int)$n['accesslevel'] ?></td>
                <td data-sort-value="<?= network_is_sensitive($n) ? -1 : $count ?>">
                  <?php if (network_is_sensitive($n)): ?>
                    <span class="text-muted small">never (sensitive)</span>
                  <?php else: ?>
                  <button type="button" class="btn btn-sm btn-link p-0" data-bs-toggle="modal" data-bs-target="#defaultUsersModal" data-network-defaults="<?= $nid ?>"
                          aria-label="Default users of <?= e($n['name']) ?>"><span data-count><?= $count ?></span> user<?= $count === 1 ? '' : 's' ?></button>
                  <?php endif; ?>
                </td>
                <td class="text-end text-nowrap">
                  <button type="button" class="btn btn-sm btn-outline-secondary" data-bs-toggle="modal" data-bs-target="#networkModal"
                          data-id="<?= $nid ?>" data-name="<?= e($n['name']) ?>" data-address="<?= e($n['address']) ?>" data-level="<?= (int)$n['accesslevel'] ?>" data-sensitive="<?= network_is_sensitive($n) ? '1' : '0' ?>"
                          aria-label="Edit <?= e($n['name']) ?>">Edit</button>
                  <form method="post" class="d-inline" data-confirm="Delete network <?= e($n['name']) ?>? It is removed from the default networks of <?= $count ?> user(s).">
                    <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
                    <input type="hidden" name="action" value="delete">
                    <input type="hidden" name="id" value="<?= $nid ?>">
                    <button class="btn btn-sm btn-outline-danger" aria-label="Delete <?= e($n['name']) ?>">Delete</button>
                  </form>
                </td>
              </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </div>
    <?php endif; ?>
  </div>
</div>

<p class="small text-muted">Export and import of networks, and the full backup: <a href="<?= e(url_for('admin/config.php')) ?>#backup">Config → Backup and restore</a>.</p>

<div class="modal fade" id="networkModal" tabindex="-1" aria-labelledby="networkModalTitle" aria-hidden="true">
  <div class="modal-dialog modal-dialog-centered">
    <form method="post" class="modal-content" autocomplete="off">
      <div class="modal-header">
        <h2 class="modal-title h5" id="networkModalTitle">Add network</h2>
        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <div class="modal-body">
        <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
        <input type="hidden" name="action" value="save">
        <input type="hidden" name="id" value="">
        <div class="mb-3">
          <label class="form-label" for="net-name">Name</label>
          <input id="net-name" type="text" name="name" class="form-control" required>
        </div>
        <div class="mb-3">
          <label class="form-label" for="net-address">Address</label>
          <input id="net-address" type="text" name="address" class="form-control" placeholder="10.0.0.0/24" required
                 pattern="^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$" title="IPv4 network (10.0.0.0/24) or host (10.0.0.5)">
        </div>
        <div class="mb-0">
          <label class="form-label" for="net-level">Access level</label>
          <input id="net-level" type="number" name="accesslevel" class="form-control" min="0" max="<?= (int)MAX_ACCESS_LEVEL ?>" value="0" required>
          <div class="form-text">Users with this level or higher can request the network.</div>
        </div>
        <div class="form-check mt-3 mb-0">
          <input class="form-check-input" type="checkbox" name="sensitive" value="1" id="net-sensitive" aria-describedby="net-sensitive-help">
          <label class="form-check-label" for="net-sensitive">Sensitive network</label>
          <div class="form-text" id="net-sensitive-help">Never a default network – users grant it one at a time (extended duration). Marking it removes it from all default networks.</div>
        </div>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Cancel</button>
        <button type="submit" class="btn btn-primary">Save network</button>
      </div>
    </form>
  </div>
</div>

<div class="modal fade" id="defaultUsersModal" tabindex="-1" aria-labelledby="defaultUsersTitle" aria-hidden="true">
  <div class="modal-dialog modal-dialog-centered modal-dialog-scrollable">
    <div class="modal-content">
      <div class="modal-header">
        <h2 class="modal-title h5" id="defaultUsersTitle">Default for</h2>
        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <div class="modal-body">
        <p class="text-muted small" data-default-users-hint></p>
        <input type="search" class="form-control form-control-sm mb-2" placeholder="Filter users" aria-label="Filter users" data-default-users-filter>
        <ul class="list-group" data-default-users-list></ul>
      </div>
      <div class="modal-footer">
        <span class="text-muted small me-auto">Changes are saved immediately.</span>
        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
      </div>
    </div>
  </div>
</div>
<script type="application/json" id="networksPageData"><?= json_encode($pageData, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?></script>
<?php include view_path('footer'); ?>
