<?php
require_once __DIR__ . '/functions.php';
ensure_session();
$user = current_user();
$sessionExpires = session_expires_at();
$basePath = base_path();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?= htmlspecialchars(APP_NAME) ?></title>
    <link rel="icon" type="image/svg+xml" href="<?= htmlspecialchars(url_for('favicon.svg')) ?>">
    <link rel="stylesheet" href="<?= htmlspecialchars(url_for('css/bootstrap.min.css')) ?>">
    <link rel="stylesheet" href="<?= htmlspecialchars(url_for('css/main.css')) ?>">
</head>
<body data-base-path="<?= htmlspecialchars($basePath) ?>">
<nav class="navbar navbar-expand-lg navbar-dark bg-danger mb-4">
  <div class="container-fluid">
    <a class="navbar-brand" href="<?= htmlspecialchars(url_for('index.php')) ?>"><?= htmlspecialchars(APP_NAME) ?></a>
    <div class="collapse navbar-collapse">
      <ul class="navbar-nav ms-auto align-items-center gap-3">
        <?php if ($user): ?>
          <li class="nav-item d-flex align-items-center"><span class="navbar-text fw-semibold">User: <?= htmlspecialchars($user['username']) ?></span></li>
          <?php if ((int)$user['isadmin'] === 1): ?>
            <li class="nav-item"><a class="nav-link fw-semibold" href="<?= htmlspecialchars(url_for('config_networks.php')) ?>">Networks</a></li>
            <li class="nav-item"><a class="nav-link fw-semibold" href="<?= htmlspecialchars(url_for('config_user.php')) ?>">Users</a></li>
          <?php endif; ?>
          <li class="nav-item"><a class="nav-link fw-semibold" href="<?= htmlspecialchars(url_for('logout.php')) ?>">Logout</a></li>
        <?php endif; ?>
      </ul>
    </div>
  </div>
</nav>
<div class="container">
