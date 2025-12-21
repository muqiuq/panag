<?php
require_once __DIR__ . '/../functions.php';

if (!defined('ALLOW_TESTS') || !ALLOW_TESTS) {
  http_response_code(403);
  echo 'Tests are disabled.';
  exit;
}

$results = [];
$overall = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $dir = __DIR__ . '/tmp_rights_test';
    $file = $dir . '/probe.txt';
    $cleanupNotes = [];

    $addResult = function (bool $ok, string $msg) use (&$results) {
        $results[] = ['ok' => $ok, 'msg' => $msg];
    };

    $cleanup = function () use ($dir, $file, &$cleanupNotes) {
        if (is_file($file)) {
            if (@unlink($file)) {
                $cleanupNotes[] = 'Removed test file at ' . $file;
            }
        }
        if (is_dir($dir)) {
            if (@rmdir($dir)) {
                $cleanupNotes[] = 'Removed test folder at ' . $dir;
            }
        }
    };

    // Start clean
    $cleanup();

    // Create directory
    $dirOk = @mkdir($dir, 0775, true);
    $addResult($dirOk, ($dirOk ? 'Created' : 'Failed to create') . ' test folder at ' . $dir);

    // Create file
    $writeOk = @file_put_contents($file, 'PANAG rights probe') !== false;
    $addResult($writeOk, ($writeOk ? 'Created and wrote' : 'Failed to write') . ' test file at ' . $file);

    // Read file
    if (is_file($file)) {
        $readOk = @file_get_contents($file) === 'PANAG rights probe';
        $addResult($readOk, ($readOk ? 'Read' : 'Failed to read') . ' test file at ' . $file);
    } else {
        $addResult(false, 'Cannot read test file at ' . $file . ' because it does not exist');
    }

    // Cleanup
    $cleanup();
    if (!empty($cleanupNotes)) {
        foreach ($cleanupNotes as $note) {
            $results[] = ['ok' => true, 'msg' => $note];
        }
    }

    $overall = array_reduce($results, fn($carry, $row) => $carry && $row['ok'], true);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Filesystem rights test</title>
  <link rel="stylesheet" href="../css/bootstrap.min.css">
  <link rel="stylesheet" href="../css/main.css">
  <style>
    body { margin: 2rem; }
    .card { max-width: 720px; margin: 0 auto; }
  </style>
</head>
<body class="bg-light">
<div class="card shadow-sm">
  <div class="card-header">Filesystem rights test</div>
  <div class="card-body">
    <p>This test tries to create a folder and file under the application directory and cleans up afterwards.</p>
    <form method="post" class="mb-3">
      <button type="submit" class="btn btn-primary">Run test</button>
    </form>
    <?php if ($overall !== null): ?>
      <div class="mt-2 alert <?= $overall ? 'alert-success' : 'alert-danger' ?>" role="alert">
        <?= $overall ? 'All checks passed.' : 'One or more checks failed.' ?>
      </div>
      <ul class="list-group">
        <?php foreach ($results as $row): ?>
          <li class="list-group-item d-flex justify-content-between align-items-center">
            <span><?= htmlspecialchars($row['msg']) ?></span>
            <span class="badge <?= $row['ok'] ? 'bg-success' : 'bg-danger' ?>"><?= $row['ok'] ? 'OK' : 'Fail' ?></span>
          </li>
        <?php endforeach; ?>
      </ul>
    <?php endif; ?>
  </div>
</div>
</body>
</html>
