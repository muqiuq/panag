<?php
// Admin: users × networks matrix of the default networks – overview and bulk changes. A click on a cell
// adds/removes the default (saved immediately). Cells where the user's level is too low are locked.
// JS: public/js/matrix.js
require_once __DIR__ . '/../../src/bootstrap.php';
require_permission('manage_users');

$users = db()->query('SELECT id, username, user_ip, role, accesslevel FROM users ORDER BY username COLLATE NOCASE')->fetchAll(PDO::FETCH_ASSOC);
$networks = get_all_networks();
$selected = [];
foreach (default_network_assignments() as $a) {
    $selected[$a['user_id']][$a['network_id']] = true;
}
$pageScripts = ['js/matrix.js'];
include view_path('header');
?>
<div class="card shadow-sm">
  <div class="card-header d-flex flex-wrap justify-content-between align-items-center gap-2">
    <span>Default networks matrix</span>
    <div class="d-flex flex-wrap gap-2">
      <input type="search" class="form-control form-control-sm w-auto" placeholder="Filter users" aria-label="Filter users" data-matrix-filter="users">
      <input type="search" class="form-control form-control-sm w-auto" placeholder="Filter networks" aria-label="Filter networks" data-matrix-filter="networks">
    </div>
  </div>
  <div class="card-body">
    <p class="small text-muted">
      Click a cell to add or remove a default network – changes are saved immediately.
      <span class="matrix-legend">✓</span> default ·
      <span class="matrix-legend">–</span> level too low or sensitive network (single grants only) ·
      <span class="matrix-legend matrix-legend-invalid">!</span> above the level, not granted (click to remove)
    </p>
    <?php if (empty($users) || empty($networks)): ?>
      <p class="text-muted mb-0">No users or networks yet.</p>
    <?php else: ?>
      <div class="matrix-wrap">
        <table class="table table-sm table-bordered align-middle mb-0 matrix" id="matrixTable" data-sortable>
          <thead>
            <tr>
              <th class="matrix-corner">User</th>
              <th data-sort="number">Level</th>
              <?php foreach ($networks as $n): ?>
                <th data-sort="number" class="matrix-net" data-network-col="<?= (int)$n['id'] ?>" data-filter-text="<?= e($n['name'] . ' ' . $n['address']) ?>"
                    data-sort-key="net-<?= (int)$n['id'] ?>" title="<?= e($n['address']) ?> · requires L<?= (int)$n['accesslevel'] ?>">
                  <span class="d-block"><?= e($n['name']) ?></span><small class="fw-normal text-muted">L<?= (int)$n['accesslevel'] ?><?= network_is_sensitive($n) ? ' · sensitive' : '' ?></small>
                </th>
              <?php endforeach; ?>
            </tr>
          </thead>
          <tbody>
            <?php foreach ($users as $u): $uid = (int)$u['id']; ?>
              <tr data-user-id="<?= $uid ?>" data-filter-text="<?= e($u['username'] . ' ' . $u['user_ip'] . ' ' . $u['role']) ?>">
                <th scope="row" class="matrix-user">
                  <a href="<?= e(url_for('admin/user.php')) ?>?id=<?= $uid ?>#networks"><?= e($u['username']) ?></a>
                  <small class="d-block"><code><?= e($u['user_ip']) ?></code></small>
                </th>
                <td data-sort-value="<?= (int)$u['accesslevel'] ?>">L<?= (int)$u['accesslevel'] ?></td>
                <?php foreach ($networks as $n):
                  $nid = (int)$n['id'];
                  $eligible = user_can_access_network($u, $n);
                  $sensitive = network_is_sensitive($n);
                  $isSel = isset($selected[$uid][$nid]);
                  $title = $sensitive ? 'Sensitive network – never a default, single grants only'
                      : ($eligible ? $n['name'] . ' for ' . $u['username'] : 'Requires L' . (int)$n['accesslevel'] . ' – ' . $u['username'] . ' has L' . (int)$u['accesslevel']);
                ?>
                  <td class="matrix-cell" data-sort-value="<?= $isSel ? '1' : '0' ?>">
                    <button type="button" class="matrix-toggle<?= $isSel && !$eligible ? ' is-invalid' : '' ?>" data-user-id="<?= $uid ?>" data-network-id="<?= $nid ?>"
                            data-eligible="<?= $eligible && !$sensitive ? '1' : '0' ?>" aria-pressed="<?= $isSel ? 'true' : 'false' ?>"
                            aria-label="<?= e($n['name']) ?> for <?= e($u['username']) ?>"
                            title="<?= e($title) ?>"
                            <?= (!$eligible || $sensitive) && !$isSel ? 'disabled' : '' ?>><?= $isSel ? ($eligible ? '✓' : '!') : ($eligible && !$sensitive ? '' : '–') ?></button>
                  </td>
                <?php endforeach; ?>
              </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </div>
    <?php endif; ?>
  </div>
</div>
<?php include view_path('footer'); ?>
