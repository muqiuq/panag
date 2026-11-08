<?php
// Default networks editor (JS: public/js/default-networks.js) – admin user page and own profile.
// Expects $dnUser: the user whose default networks are edited. Every change is saved immediately.
$dnUser = $dnUser ?? throw new LogicException('default_networks_editor needs $dnUser');
$dnSelected = array_flip(get_user_default_network_ids((int)$dnUser['id']));
$dnNetworks = get_all_networks();
$dnAbove = count(array_filter($dnNetworks, fn($n) => !user_can_access_network($dnUser, $n)));
$dnId = 'dn-' . (int)$dnUser['id'];
$dnLevel = (int)$dnUser['accesslevel'];
?>
<div data-default-networks data-user-id="<?= (int)$dnUser['id'] ?>">
  <div class="d-flex flex-wrap align-items-center gap-3 mb-2">
    <input type="search" class="form-control form-control-sm w-auto" placeholder="Search networks" aria-label="Search networks" data-dn-search>
    <div class="form-check mb-0">
      <input class="form-check-input" type="checkbox" id="<?= $dnId ?>-only" data-dn-only-selected>
      <label class="form-check-label" for="<?= $dnId ?>-only">Only selected</label>
    </div>
    <?php if ($dnAbove > 0): ?>
      <div class="form-check mb-0">
        <input class="form-check-input" type="checkbox" id="<?= $dnId ?>-all" data-dn-show-all>
        <label class="form-check-label" for="<?= $dnId ?>-all">Show all (<?= $dnAbove ?> above L<?= $dnLevel ?>)</label>
      </div>
    <?php endif; ?>
    <div class="btn-group btn-group-sm ms-auto">
      <button type="button" class="btn btn-outline-secondary" data-dn-bulk="all">Select all</button>
      <button type="button" class="btn btn-outline-secondary" data-dn-bulk="none">Select none</button>
    </div>
  </div>
  <div class="table-responsive">
    <table class="table table-sm align-middle mb-1" data-sortable id="<?= $dnId ?>-table">
      <thead>
        <tr><th data-sort="number" class="col-toggle">Default</th><th>Name</th><th data-sort="ip">Address</th><th data-sort="number">Level</th></tr>
      </thead>
      <tbody>
        <?php foreach ($dnNetworks as $n):
          $nid = (int)$n['id'];
          $eligible = user_can_access_network($dnUser, $n);
          $sensitive = network_is_sensitive($n);
          $selected = isset($dnSelected[$nid]);
          $toggleId = $dnId . '-' . $nid;
        ?>
          <tr data-network-id="<?= $nid ?>" data-eligible="<?= $eligible ? '1' : '0' ?>" data-sensitive="<?= $sensitive ? '1' : '0' ?>" data-selected="<?= $selected ? '1' : '0' ?>"
              <?= $eligible ? '' : 'class="network-locked" title="Requires L' . (int)$n['accesslevel'] . ' – ' . e($dnUser['username']) . ' has L' . $dnLevel . '"' ?>
              <?= !$eligible && !$selected ? 'hidden' : '' ?>>
            <td data-sort-value="<?= $selected ? '1' : '0' ?>">
              <div class="form-check form-switch mb-0">
                <input class="form-check-input" type="checkbox" role="switch" id="<?= $toggleId ?>" data-dn-toggle aria-label="Default: <?= e($n['name']) ?>"
                       <?= $selected ? 'checked' : '' ?> <?= ($sensitive || !$eligible) && !$selected ? 'disabled' : '' ?>>
              </div>
            </td>
            <td>
              <label for="<?= $toggleId ?>"><?= e($n['name']) ?></label>
              <span class="badge text-bg-warning ms-1" data-dn-invalid <?= $selected && !$eligible ? '' : 'hidden' ?>>Above level – not granted</span>
              <?php if ($sensitive): ?><span class="badge bg-body-tertiary text-body border ms-1" title="Sensitive networks are never default networks – grant them one at a time">sensitive – single grants only</span><?php endif; ?>
            </td>
            <td><code><?= e($n['address']) ?></code></td>
            <td data-sort-value="<?= (int)$n['accesslevel'] ?>">L<?= (int)$n['accesslevel'] ?></td>
          </tr>
        <?php endforeach; ?>
      </tbody>
    </table>
  </div>
  <p class="text-muted small mb-1" data-dn-empty hidden>No networks match.</p>
  <p class="text-muted small mb-0" data-dn-summary aria-live="polite"></p>
</div>
