<?php
require_once __DIR__ . '/../../src/bootstrap.php';
require_permission('view_config');

$constants = [];
foreach (panag_config_sources() as $name => $source) {
  if (!defined($name)) {
    continue;
  }
  $value = constant($name);
  $constants[] = [
    'name' => $name,
    'value' => $value,
    'type' => gettype($value),
    'source' => $source,
    'masked' => stripos($name, 'PASSWORD') !== false || stripos($name, 'TOKEN') !== false,
  ];
}
usort($constants, fn($a, $b) => strcmp($a['name'], $b['name']));

include view_path('header');
?>
<div class="card shadow-sm">
  <div class="card-header d-flex justify-content-between align-items-center">
    <span>Application configuration (environment variables)</span>
    <div class="d-flex align-items-center gap-2">
      <input type="search" class="form-control form-control-sm w-auto" placeholder="Filter" aria-label="Filter configuration" data-table-filter="configTable">
      <span class="badge text-bg-secondary">Secrets hidden</span>
    </div>
  </div>
  <div class="card-body">
    <?php if (empty($constants)): ?>
      <p class="text-muted mb-0">No configuration constants found.</p>
    <?php else: ?>
      <div class="table-responsive">
        <table class="table table-sm align-middle" id="configTable" data-sortable>
          <thead>
            <tr>
              <th>Name</th>
              <th class="col-narrow">Source</th>
              <th class="col-narrow">Type</th>
              <th>Value</th>
            </tr>
          </thead>
          <tbody>
            <?php foreach ($constants as $item): ?>
              <tr>
                <td class="fw-semibold"><?= htmlspecialchars($item['name']) ?></td>
                <td><span class="badge <?= $item['source'] === 'env' ? 'bg-primary' : 'text-bg-light border' ?>"><?= htmlspecialchars($item['source']) ?></span></td>
                <td class="text-muted small"><?= htmlspecialchars($item['type']) ?></td>
                <td>
                  <?php
                  $val = $item['value'];
                  if (!empty($item['masked'])) {
                    echo $val === '' ? '<span class="text-muted">(empty)</span>' : '*****';
                  } elseif (is_bool($val)) {
                    echo $val ? 'true' : 'false';
                  } elseif (is_array($val)) {
                    echo '<pre class="mb-0 small">' . htmlspecialchars(json_encode($val, JSON_PRETTY_PRINT)) . '</pre>';
                  } elseif (is_null($val)) {
                    echo '<span class="text-muted">null</span>';
                  } else {
                    echo htmlspecialchars((string)$val);
                  }
                  ?>
                </td>
              </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </div>
    <?php endif; ?>
  </div>
</div>
<?php include view_path('footer');
