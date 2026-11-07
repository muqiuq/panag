<?php
// Admin: effective configuration. Everything is set via environment variables (src/config.php); this page only
// shows it. Secrets are never displayed – only whether they are set and where they come from.
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
    return $meta['source'] === 'env' ? '<span class="badge text-bg-primary">env</span>' : '<span class="badge text-bg-light border">default</span>';
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
include view_path('header');
?>
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
                <td class="fw-semibold text-nowrap"><?= e($name) ?><?= panag_config_is_secret($name) ? ' <span class="badge text-bg-dark">secret</span>' : '' ?></td>
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
<?php include view_path('footer');
