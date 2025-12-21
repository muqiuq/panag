<?php
require_once __DIR__ . '/../lib/functions.php';
require_admin();

$definePath = __DIR__ . '/../lib/define.php';
$constantNames = [];
if (is_readable($definePath)) {
    $contents = file_get_contents($definePath);
    if ($contents !== false) {
        if (preg_match_all('/define\(\s*[\"\']([A-Z0-9_]+)[\"\']\s*,/i', $contents, $matchesDef)) {
            $constantNames = array_merge($constantNames, $matchesDef[1]);
        }
        if (preg_match_all('/\bconst\s+([A-Z0-9_]+)\s*=\s*/i', $contents, $matchesConst)) {
            $constantNames = array_merge($constantNames, $matchesConst[1]);
        }
    }
}
$constantNames = array_values(array_unique($constantNames));

$constants = [];
foreach ($constantNames as $name) {
  if (!defined($name)) {
    continue;
  }
  $value = constant($name);
  $isPasswordLike = stripos($name, 'PASSWORD') !== false;
  $constants[] = [
    'name' => $name,
    'value' => $value,
    'type' => gettype($value),
    'masked' => $isPasswordLike,
  ];
}

usort($constants, function ($a, $b) {
    return strcmp($a['name'], $b['name']);
});

include __DIR__ . '/../lib/header.php';
?>
<div class="card shadow-sm">
  <div class="card-header d-flex justify-content-between align-items-center">
    <span>Application configuration (from define.php)</span>
    <span class="badge bg-secondary">Passwords hidden</span>
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
              <th style="width: 120px;">Type</th>
              <th>Value</th>
            </tr>
          </thead>
          <tbody>
            <?php foreach ($constants as $item): ?>
              <tr>
                <td class="fw-semibold"><?= htmlspecialchars($item['name']) ?></td>
                <td class="text-muted small"><?= htmlspecialchars($item['type']) ?></td>
                <td>
                  <?php
                  $val = $item['value'];
                  if (!empty($item['masked'])) {
                    echo '*****';
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
<?php include __DIR__ . '/../lib/footer.php';
