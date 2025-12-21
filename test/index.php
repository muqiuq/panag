<?php
require_once __DIR__ . '/../functions.php';

if (!defined('ALLOW_TESTS') || !ALLOW_TESTS) {
    http_response_code(403);
    $disabled = true;
} else {
    $disabled = false;
}

$tests = [
    'test_showdata.php' => 'Show SQLite contents',
    'test_api.php' => 'MikroTik API health check',
    'test_add_entry.php' => 'Add address-list entry harness',
    'rights_test.php' => 'Filesystem rights test',
    'create_demo_data.php' => 'Create demo data',
];
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PANAG Test Index</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 2rem; }
    h1 { margin-bottom: 1rem; }
    ul { list-style: none; padding: 0; }
    li { margin: 0.5rem 0; }
    a { text-decoration: none; color: #0d6efd; }
    a:hover { text-decoration: underline; }
    .disabled { color: #6c757d; }
  </style>
</head>
<body>
  <h1>PANAG Test Index</h1>
  <?php if ($disabled): ?>
    <p class="disabled">Tests are disabled. Enable ALLOW_TESTS in define.php to use these utilities.</p>
  <?php else: ?>
    <ul>
      <?php foreach ($tests as $file => $label): ?>
        <li><a href="<?= htmlspecialchars($file) ?>"><?= htmlspecialchars($label) ?></a> <small>(<?= htmlspecialchars($file) ?>)</small></li>
      <?php endforeach; ?>
    </ul>
  <?php endif; ?>
</body>
</html>
