<?php
// Admin: effective configuration. Everything is set via environment variables (src/config.php); this page only
// shows it. Secrets are never displayed – only whether they are set and where they come from.
// Also: backup and restore (users, networks, everything) – the forms post to admin/backup.php.
require_once __DIR__ . '/../../src/bootstrap.php';
require_permission('view_config');

function config_value_html(string $name, array $meta): string
{
    $value = constant($name);
    if (panag_config_is_secret($name)) {
        $set = $value !== '' && $value !== null;
        return $set ? '<span class="badge text-bg-success">set</span>' : '<span class="text-muted">not set</span>';
    }
    if (is_bool($value)) {
        return $value ? 'true' : 'false';
    }
    if (is_array($value)) {
        return $value === [] ? '<span class="text-muted">(empty)</span>' : e(implode(', ', array_map('strval', $value)));
    }
    if ($meta['type'] === 'duration') {
        return e(format_duration_human((int)$value)) . ' <span class="text-muted small">(' . (int)$value . ' s)</span>';
    }
    return $value === '' || $value === null ? '<span class="text-muted">(empty)</span>' : e((string)$value);
}

function config_source_html(array $meta): string
{
    if ($meta['source'] === 'file') {
        return '<span class="badge text-bg-primary">env file</span> <code class="small">' . e((string)$meta['file']) . '</code>';
    }
    return $meta['source'] === 'env' ? '<span class="badge text-bg-primary">env</span>' : '<span class="badge bg-body-tertiary text-body border">default</span>';
}

$groups = [];
foreach (panag_config_items() as $name => $meta) {
    $groups[$meta['group']][$name] = $meta;
}
$warnings = panag_config_warnings();
$derived = [
    ['APP_VERSION', APP_VERSION, 'Version of this image'],
    ['APP_ROOT', APP_ROOT, 'Application directory'],
    ['DB_PATH', DB_PATH, 'SQLite database (DATA_DIR/panag.sqlite)'],
    ['Schema version', (string)schema_version(db()) . ' of ' . latest_schema_version(), 'Applied database migrations'],
    ['Default access', format_duration_human(MIN_GRANT_DURATION) . ' – ' . format_duration_human(max_grant_duration('default')), 'Effective limits (hard maximum 14 h)'],
    ['Extended access', format_duration_human(MIN_GRANT_DURATION) . ' – ' . format_duration_human(max_grant_duration('extended')), 'Effective limits (hard maximum 12 h)'],
    ['Mail', mail_config_problem() ?? 'ready (' . SMTP_HOST . ':' . SMTP_PORT . ', ' . SMTP_SECURITY . ')', 'Result of the mail configuration check'],
    ['AI triage', ai_config_problem() ?? 'ready (' . OPENROUTER_MODEL . ')', 'Result of the AI configuration check'],
    ['Pseudonym key', (string)MONITOR_PSEUDONYM_KEY !== '' ? 'from MONITOR_PSEUDONYM_KEY' : (is_file(rtrim(DATA_DIR, '/') . '/monitor.key') ? 'generated (DATA_DIR/monitor.key)' : 'not created yet'), 'HMAC key for AI pseudonyms (value never shown)'],
    ['PHP', PHP_VERSION . ' (' . PHP_SAPI . ', ' . (PHP_INT_SIZE * 8) . ' bit)', 'Runtime'],
];
// Container variables read by Apache/PHP outside of src/config.php.
$container = [
    ['APACHE_MAX_WORKERS', getenv('APACHE_MAX_WORKERS'), 'Apache prefork workers (docker/httpd.conf)'],
    ['PHP_DISPLAY_ERRORS', getenv('PHP_DISPLAY_ERRORS'), 'PHP display_errors (docker/php.ini), On only in dev'],
    ['SEED_DEMO', getenv('SEED_DEMO'), 'Insert demo data on start (dev only)'],
];
ensure_session();
$flash = $_SESSION['config_flash'] ?? null;
unset($_SESSION['config_flash']);
$csrf = csrf_token();
include view_path('header');
?>
<?php if ($flash): ?>
  <div class="alert alert-<?= e($flash['type']) ?>" role="alert" data-testid="config-flash"><?= e($flash['message']) ?> <a href="#backup" class="alert-link">Backup and restore</a></div>
<?php endif; ?>
<div class="card shadow-sm mb-4">
  <div class="card-header d-flex flex-wrap justify-content-between align-items-center gap-2">
    <span>Configuration <span class="text-muted small">– set via environment variables, shown read-only</span></span>
    <div class="d-flex align-items-center gap-2">
      <input type="search" class="form-control form-control-sm w-auto" placeholder="Filter" aria-label="Filter configuration" data-table-filter="configTable">
      <span class="badge text-bg-secondary">Secrets hidden</span>
    </div>
  </div>
  <div class="card-body">
    <?php if ($warnings): ?>
      <div class="alert alert-warning" role="alert" data-testid="config-warnings">
        <strong><?= count($warnings) ?> configuration problem(s):</strong>
        <ul class="mb-0">
          <?php foreach ($warnings as $w): ?>
            <li><code><?= e($w['name']) ?></code>: <?= e($w['message']) ?></li>
          <?php endforeach; ?>
        </ul>
      </div>
    <?php endif; ?>
    <p class="text-muted small">Every setting can be given as <code>NAME</code> or – for secrets – as <code>NAME_FILE=/path</code>. RouterOS: <code>/container/envs</code>; Docker: <code>.env</code> / Compose. See <code>.env.example</code>.</p>
    <div class="table-responsive">
      <table class="table table-sm align-middle" id="configTable" data-sortable>
        <thead>
          <tr><th>Group</th><th>Name</th><th>Value</th><th>Source</th><th>Default</th><th>Description</th></tr>
        </thead>
        <tbody>
          <?php foreach ($groups as $groupName => $items): ?>
            <?php foreach ($items as $name => $meta): ?>
              <tr>
                <td class="text-muted small"><?= e($groupName) ?></td>
                <td class="fw-semibold text-nowrap"><?= e($name) ?><?= panag_config_is_secret($name) ? ' <span class="badge text-bg-secondary">secret</span>' : '' ?></td>
                <td class="text-break"><?= config_value_html($name, $meta) ?></td>
                <td class="text-nowrap" data-sort-value="<?= e($meta['source']) ?>"><?= config_source_html($meta) ?></td>
                <td class="small text-muted text-break"><?php
                  $def = $meta['default'];
                  echo panag_config_is_secret($name) ? '' : e(is_array($def) ? implode(', ', $def) : (is_bool($def) ? ($def ? 'true' : 'false') : (string)$def));
                ?></td>
                <td class="small"><?= e($meta['description']) ?></td>
              </tr>
            <?php endforeach; ?>
          <?php endforeach; ?>
        </tbody>
      </table>
    </div>
  </div>
</div>

<div class="row g-4">
  <div class="col-lg-7">
    <div class="card shadow-sm h-100">
      <div class="card-header">Derived and fixed values</div>
      <div class="card-body">
        <table class="table table-sm align-middle mb-0" id="derivedTable" data-sortable>
          <thead><tr><th>Name</th><th>Value</th><th>Description</th></tr></thead>
          <tbody>
            <?php foreach ($derived as [$name, $value, $desc]): ?>
              <tr><td class="fw-semibold"><?= e($name) ?></td><td class="text-break"><?= e($value) ?></td><td class="small"><?= e($desc) ?></td></tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </div>
    </div>
  </div>
  <div class="col-lg-5">
    <div class="card shadow-sm h-100">
      <div class="card-header">Container</div>
      <div class="card-body">
        <table class="table table-sm align-middle mb-0" id="containerTable" data-sortable>
          <thead><tr><th>Name</th><th>Value</th><th>Description</th></tr></thead>
          <tbody>
            <?php foreach ($container as [$name, $value, $desc]): ?>
              <tr><td class="fw-semibold"><?= e($name) ?></td><td><?= $value === false || $value === '' ? '<span class="text-muted">(not set)</span>' : e((string)$value) ?></td><td class="small"><?= e($desc) ?></td></tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</div>

<div class="card shadow-sm mt-4" id="backup">
  <div class="card-header">Backup and restore</div>
  <div class="card-body">
    <p class="small text-muted">Exports contain the OTP secrets of all users – store them safely. Settings from environment variables and the files in DATA_DIR (GeoIP databases, pseudonym key) are not part of any backup.</p>
    <div class="row g-4">
      <div class="col-lg-6">
        <h2 class="h6">Users</h2>
        <form method="post" action="<?= e(url_for('admin/backup.php')) ?>" class="mb-2">
          <input type="hidden" name="csrf_token" value="<?= e($csrf) ?>">
          <input type="hidden" name="action" value="export_users">
          <button class="btn btn-sm btn-outline-primary">Export users (JSON)</button>
        </form>
        <form method="post" action="<?= e(url_for('admin/backup.php')) ?>" enctype="multipart/form-data" class="d-flex flex-wrap gap-2 align-items-center">
          <input type="hidden" name="csrf_token" value="<?= e($csrf) ?>">
          <input type="hidden" name="action" value="import_users">
          <input type="file" name="users_file" accept="application/json,.json" class="form-control form-control-sm w-auto flex-grow-1" required aria-label="Users file (JSON)">
          <button class="btn btn-sm btn-outline-success" type="submit">Import users</button>
        </form>
        <p class="small text-muted mt-1 mb-0">Adds users whose user IP is not present yet; existing user IPs are skipped. New users have no default networks.</p>
      </div>
      <div class="col-lg-6">
        <h2 class="h6">Networks</h2>
        <form method="post" action="<?= e(url_for('admin/backup.php')) ?>" class="mb-2">
          <input type="hidden" name="csrf_token" value="<?= e($csrf) ?>">
          <input type="hidden" name="action" value="export_networks">
          <button class="btn btn-sm btn-outline-primary">Export networks (JSON)</button>
        </form>
        <form method="post" action="<?= e(url_for('admin/backup.php')) ?>" enctype="multipart/form-data" class="d-flex flex-wrap gap-2 align-items-center">
          <input type="hidden" name="csrf_token" value="<?= e($csrf) ?>">
          <input type="hidden" name="action" value="import_networks">
          <input type="file" name="network_file" accept="application/json,.json" class="form-control form-control-sm w-auto flex-grow-1" required aria-label="Networks file (JSON)">
          <select name="import_mode" class="form-select form-select-sm w-auto" aria-label="Network import mode">
            <option value="replace">Replace</option>
            <option value="append">Append</option>
          </select>
          <button class="btn btn-sm btn-outline-success" type="submit">Import networks</button>
        </form>
        <p class="small text-muted mt-1 mb-0">Replace overwrites all networks (and their default assignments); Append adds to the list.</p>
      </div>
    </div>
    <hr class="my-4">
    <h2 class="h6">Everything</h2>
    <p class="small mb-2">One file with all data: users, networks, default networks, settings, status messages, audit log, monitoring data and alerts.</p>
    <form method="post" action="<?= e(url_for('admin/backup.php')) ?>" class="mb-3">
      <input type="hidden" name="csrf_token" value="<?= e($csrf) ?>">
      <input type="hidden" name="action" value="export_full">
      <button class="btn btn-sm btn-primary">Download full backup</button>
    </form>
    <form method="post" action="<?= e(url_for('admin/backup.php')) ?>" enctype="multipart/form-data" class="border border-danger-subtle rounded p-3" data-testid="restore-form">
      <input type="hidden" name="csrf_token" value="<?= e($csrf) ?>">
      <input type="hidden" name="action" value="restore_full">
      <p class="small mb-2"><strong>Restore replaces all current data</strong> with the backup. A copy of the current database is saved in <code>DATA_DIR/backups</code> first. Older backups are migrated to the current schema. If your own account is not in the backup, you are logged out.</p>
      <div class="d-flex flex-wrap gap-2 align-items-center">
        <input type="file" name="backup_file" accept="application/json,.json" class="form-control form-control-sm w-auto flex-grow-1" required aria-label="Full backup file (JSON)">
        <label class="visually-hidden" for="restore-confirm">Type RESTORE to confirm</label>
        <input type="text" id="restore-confirm" name="confirm" class="form-control form-control-sm w-auto" placeholder="Type RESTORE" autocomplete="off" required pattern="RESTORE">
        <button class="btn btn-sm btn-danger" type="submit">Restore everything</button>
      </div>
    </form>
  </div>
</div>
<?php include view_path('footer');
