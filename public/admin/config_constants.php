<?php
require_once __DIR__ . '/../../src/bootstrap.php';
require_admin();

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
    <span class="badge bg-secondary">Secrets hidden</span>
  </div>
  <div class="card-body">
    <?php if (empty($constants)): ?>
      <p class="text-muted mb-0">No configuration constants found.</p>
    <?php else: ?>
      <div class="table-responsive">
        <table class="table table-sm align-middle">
          <thead>
            <tr>
              <th>Name</th>
              <th style="width: 100px;">Source</th>
              <th style="width: 100px;">Type</th>
              <th>Value</th>
            </tr>
          </thead>
          <tbody>
            <?php foreach ($constants as $item): ?>
              <tr>
                <td class="fw-semibold"><?= htmlspecialchars($item['name']) ?></td>
                <td><span class="badge <?= $item['source'] === 'env' ? 'bg-primary' : 'bg-light text-dark' ?>"><?= htmlspecialchars($item['source']) ?></span></td>
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
