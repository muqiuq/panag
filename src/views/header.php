<?php
ensure_session();
$user = current_user();
$impersonator = $user ? impersonator() : null;
$basePath = base_path();
$currentScript = basename((string)($_SERVER['SCRIPT_NAME'] ?? ''));
$navLink = static function (string $path, string $label) use ($currentScript): string {
    $active = basename($path) === $currentScript;
    return '<li class="nav-item"><a class="nav-link fw-semibold' . ($active ? ' active' : '') . '"' . ($active ? ' aria-current="page"' : '')
        . ' href="' . e(url_for($path)) . '">' . e($label) . '</a></li>';
};
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?= e(APP_NAME) ?></title>
    <meta name="csrf-token" content="<?= e(csrf_token()) ?>">
    <link rel="icon" type="image/svg+xml" href="<?= e(url_for('favicon.svg')) ?>">
    <link rel="stylesheet" href="<?= e(url_for('css/bootstrap.min.css')) ?>">
    <link rel="stylesheet" href="<?= e(url_for('css/main.css')) ?>">
</head>
<body data-base-path="<?= e($basePath) ?>" data-csrf-token="<?= e(csrf_token()) ?>"<?= $user ? ' data-palette="on"' : '' ?>>
<?php include view_path('partials/dev_banner'); ?>
<?php if ($impersonator): ?>
<div class="bg-info-subtle border-bottom border-info py-2" role="status" data-testid="impersonation-banner">
  <form method="post" action="<?= e(url_for('impersonate_stop.php')) ?>" class="container-fluid d-flex flex-wrap align-items-center gap-2 small">
    <span>You (<?= e($impersonator['username']) ?>) are acting as <strong><?= e($user['username']) ?></strong> (<?= e($user['user_ip']) ?>). Grants and revokes affect this user's address list.</span>
    <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
    <button type="submit" class="btn btn-sm btn-info">Back to admin</button>
  </form>
</div>
<?php endif; ?>
<nav class="navbar navbar-expand-lg navbar-dark bg-danger mb-4">
  <div class="container-fluid">
    <a class="navbar-brand d-flex align-items-center gap-2" href="<?= e(url_for('index.php')) ?>">
      <img src="<?= e(url_for('favicon.svg')) ?>" alt="Logo" width="24" height="24">
      <span><?= e(APP_NAME) ?></span>
    </a>
    <?php if ($user): ?>
      <button type="button" class="btn btn-sm btn-outline-light ms-auto me-2 d-lg-none" data-palette-open aria-label="Search networks and commands">Search</button>
    <?php endif; ?>
    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#mainNav" aria-controls="mainNav" aria-expanded="false" aria-label="Toggle navigation">
      <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="mainNav">
      <ul class="navbar-nav ms-auto align-items-lg-center gap-lg-3">
        <?php if ($user): ?>
          <li class="nav-item d-none d-lg-block">
            <button type="button" class="btn btn-sm btn-outline-light palette-open-btn" data-palette-open aria-keyshortcuts="/ Control+K Meta+K">
              Search <kbd>/</kbd>
            </button>
          </li>
          <li class="nav-item d-flex align-items-center"><span class="navbar-text fw-semibold">User: <?= e($user['username']) ?> (<?= e($user['user_ip']) ?>, L<?= (int)$user['accesslevel'] ?><?= user_role($user) !== 'user' ? ', ' . e(role_label((string)user_role($user))) : '' ?>)</span></li>
          <?= $navLink('profile.php', 'Profile') ?>
          <?php if (is_admin($user)): ?>
            <?= $navLink('admin/users.php', 'Users') ?>
            <?= $navLink('admin/networks.php', 'Networks') ?>
            <?= $navLink('admin/matrix.php', 'Matrix') ?>
            <?= $navLink('admin/logs.php', 'Logs') ?>
            <?= $navLink('admin/config.php', 'Config') ?>
            <?= $navLink('admin/status.php', 'Status') ?>
          <?php else: ?>
            <?= $navLink('status_public.php', 'Status') ?>
          <?php endif; ?>
          <li class="nav-item"><a class="nav-link fw-semibold" href="<?= e(url_for('logout.php')) ?>">Logout</a></li>
        <?php endif; ?>
      </ul>
    </div>
  </div>
</nav>
<div class="container">
