<?php
ensure_session();
$user = current_user();
$impersonator = $user ? impersonator() : null;
$sessionExpires = session_expires_at();
$basePath = base_path();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?= htmlspecialchars(APP_NAME) ?></title>
    <meta name="csrf-token" content="<?= htmlspecialchars(csrf_token()) ?>">
    <link rel="icon" type="image/svg+xml" href="<?= htmlspecialchars(url_for('favicon.svg')) ?>">
    <link rel="stylesheet" href="<?= htmlspecialchars(url_for('css/bootstrap.min.css')) ?>">
    <link rel="stylesheet" href="<?= htmlspecialchars(url_for('css/main.css')) ?>">
</head>
  <body data-base-path="<?= htmlspecialchars($basePath) ?>" data-csrf-token="<?= htmlspecialchars(csrf_token()) ?>">
<?php include view_path('partials/dev_banner'); ?>
<?php if ($impersonator): ?>
<div class="bg-info-subtle border-bottom border-info py-2" role="status" data-testid="impersonation-banner">
  <form method="post" action="<?= htmlspecialchars(url_for('impersonate_stop.php')) ?>" class="container-fluid d-flex flex-wrap align-items-center gap-2 small">
    <span>You (<?= htmlspecialchars($impersonator['username']) ?>) are acting as <strong><?= htmlspecialchars($user['username']) ?></strong> (<?= htmlspecialchars($user['user_ip']) ?>). Grants and revokes affect this user's address list.</span>
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
    <button type="submit" class="btn btn-sm btn-info">Back to admin</button>
  </form>
</div>
<?php endif; ?>
<nav class="navbar navbar-expand-lg navbar-dark bg-danger mb-4">
  <div class="container-fluid">
    <a class="navbar-brand d-flex align-items-center gap-2" href="<?= htmlspecialchars(url_for('index.php')) ?>">
      <img src="<?= htmlspecialchars(url_for('favicon.svg')) ?>" alt="Logo" width="24" height="24">
      <span><?= htmlspecialchars(APP_NAME) ?></span>
    </a>
    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#mainNav" aria-controls="mainNav" aria-expanded="false" aria-label="Toggle navigation">
      <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="mainNav">
      <ul class="navbar-nav ms-auto align-items-lg-center gap-3">
        <?php if ($user): ?>
          <li class="nav-item d-flex align-items-center"><span class="navbar-text fw-semibold">User: <?= htmlspecialchars($user['username']) ?> (<?= htmlspecialchars($user['user_ip']) ?>, L<?= (int)$user['accesslevel'] ?><?= user_role($user) !== 'user' ? ', ' . htmlspecialchars(role_label((string)user_role($user))) : '' ?>)</span></li>
          <li class="nav-item"><a class="nav-link fw-semibold" href="<?= htmlspecialchars(url_for('profile.php')) ?>">Profile</a></li>
          <?php if (is_admin($user)): ?>
            <li class="nav-item"><a class="nav-link fw-semibold" href="<?= htmlspecialchars(url_for('admin/config_networks.php')) ?>">Networks</a></li>
            <li class="nav-item"><a class="nav-link fw-semibold" href="<?= htmlspecialchars(url_for('admin/config_user.php')) ?>">Users</a></li>
            <li class="nav-item"><a class="nav-link fw-semibold" href="<?= htmlspecialchars(url_for('admin/logs.php')) ?>">Logs</a></li>
            <li class="nav-item"><a class="nav-link fw-semibold" href="<?= htmlspecialchars(url_for('admin/config_constants.php')) ?>">Config</a></li>
            <li class="nav-item"><a class="nav-link fw-semibold" href="<?= htmlspecialchars(url_for('admin/status.php')) ?>">Status</a></li>
          <?php else: ?>
            <li class="nav-item"><a class="nav-link fw-semibold" href="<?= htmlspecialchars(url_for('status_public.php')) ?>">Status</a></li>
          <?php endif; ?>
          <li class="nav-item"><a class="nav-link fw-semibold" href="<?= htmlspecialchars(url_for('logout.php')) ?>">Logout</a></li>
        <?php endif; ?>
      </ul>
    </div>
  </div>
</nav>
<div class="container">
