<?php
// Admin: detection rules of the security monitoring – switch rules on/off, override their severity, change their
// thresholds (src/monitor/rule_settings.php). Defaults come from the environment; changes apply from the next
// monitor cycle and are logged (and reported by rule P6).
require_once __DIR__ . '/../../src/bootstrap.php';
require_permission('admin');

ensure_session();
$admin = current_user();
$flash = $_SESSION['rules_flash'] ?? null;
unset($_SESSION['rules_flash']);
$submitted = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_csrf_token($_POST['csrf_token'] ?? null);
    if (isset($_POST['reset'])) {
        reset_rule_settings($admin);
        $_SESSION['rules_flash'] = ['type' => 'success', 'message' => 'All detection rules are back to their defaults.', 'errors' => []];
        header('Location: ' . url_for('admin/rules.php'));
        exit;
    }
    $result = save_rule_settings($_POST, $admin);
    if ($result['ok']) {
        $_SESSION['rules_flash'] = ['type' => 'success', 'message' => $result['changes'] ? 'Saved: ' . implode('; ', $result['changes']) . '.' : 'Nothing changed.', 'errors' => []];
        header('Location: ' . url_for('admin/rules.php'));
        exit;
    }
    // Show the form again with what was typed.
    http_response_code(422);
    $flash = ['type' => 'danger', 'message' => 'Not saved – please correct:', 'errors' => $result['errors']];
    $submitted = $_POST;
}

$reference = monitor_rule_reference();
$paramsOf = [];
foreach (RULE_PARAMS as $name => $def) {
    if ($name === 'learning_days') {
        continue; // shared by several rules – shown above the table
    }
    foreach ($def['rules'] as $code) {
        $paramsOf[$code][] = $name;
    }
}
$paramValue = static fn(string $name): string => $submitted !== null && isset($submitted['params'][$name])
    ? (string)$submitted['params'][$name]
    : rule_param_display($name, rule_param($name));
$paramInput = static function (string $name) use ($paramValue): string {
    $def = RULE_PARAMS[$name];
    $id = 'param-' . $name;
    $default = rule_param_display($name, rule_param_default($name));
    $source = rule_param_source($name);
    $help = 'Default: ' . ($default === '' ? 'none' : $default) . (isset($def['env']) ? ' (' . $def['env'] . ')' : '');
    return '<div class="rule-param">'
        . '<label class="form-label small mb-0" for="' . $id . '">' . e($def['label']) . ($source === 'web' ? ' <span class="badge bg-body-tertiary text-body border">changed</span>' : '') . '</label>'
        . '<input type="text" class="form-control form-control-sm" id="' . $id . '" name="params[' . e($name) . ']" value="' . e($paramValue($name)) . '" aria-describedby="' . $id . '-help">'
        . '<div class="form-text mt-0" id="' . $id . '-help">' . e($help) . '</div>'
        . '</div>';
};
$isOn = static fn(string $code): bool => $submitted !== null ? !empty($submitted['enabled'][$code]) || in_array($code, RULES_ALWAYS_ON, true) : rule_enabled($code);
$severityOf = static fn(string $code): string => $submitted !== null ? (string)($submitted['severity'][$code] ?? '') : (string)(rule_severity($code) ?? '');
$off = array_keys(array_filter($reference, fn($r) => !$r['enabled']));

include view_path('header');
?>
<?php if ($flash): ?>
  <div class="alert alert-<?= e($flash['type']) ?>" role="alert" data-testid="rules-flash">
    <?= e($flash['message']) ?>
    <?php if ($flash['errors']): ?>
      <ul class="mb-0 mt-1"><?php foreach ($flash['errors'] as $err): ?><li><?= e($err) ?></li><?php endforeach; ?></ul>
    <?php endif; ?>
  </div>
<?php endif; ?>
<?php if (!MONITOR_ENABLED): ?>
  <div class="alert alert-warning" role="status">Monitoring is off (<code>MONITOR_ENABLED=false</code>) – the rules take effect once it is switched on.</div>
<?php endif; ?>

<form method="post" class="card shadow-sm mb-4" id="rules-form">
  <div class="card-header d-flex flex-wrap justify-content-between align-items-center gap-2">
    <span>Detection rules</span>
    <span class="text-muted small"><?= $off ? 'Off: ' . e(implode(', ', $off)) : 'All rules on' ?> · changes apply from the next monitor cycle</span>
  </div>
  <div class="card-body">
    <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
    <p class="small text-muted">Defaults come from the environment variables (<a href="<?= e(url_for('admin/config.php')) ?>">Config</a>) or are built in. A value equal to its default is not stored, so later changes of the environment still apply. Changing the rules is logged and reported as a sensitive admin action (P6).</p>
    <div class="row g-3 mb-3">
      <div class="col-sm-6 col-lg-3">
        <?= $paramInput('learning_days') ?>
      </div>
      <div class="col-sm-6 col-lg-9 small text-muted align-self-center">
        Used by W1, W6, P3 and P4: behaviour-based rules stay quiet for new users until this many days have passed and <?= BASELINE_MIN_EVENTS ?> events were seen.
      </div>
    </div>
    <div class="table-responsive">
      <table class="table table-sm align-top mb-0" id="rulesTable">
        <thead>
          <tr><th>Rule</th><th class="text-center">On</th><th>Severity</th><th>Settings</th><th>Fires when</th></tr>
        </thead>
        <tbody>
          <?php foreach ($reference as $code => $rule):
            $alwaysOn = in_array($code, RULES_ALWAYS_ON, true);
            $own = implode(' / ', $rule['severity']);
          ?>
            <tr id="rule-<?= e($code) ?>" class="<?= $isOn($code) ? '' : 'rule-off' ?>">
              <td class="text-nowrap"><code><?= e($code) ?></code> <span class="fw-semibold"><?= e($rule['name']) ?></span><?= $rule['asks_user'] ? '<div class="small text-muted">asks the user</div>' : '' ?></td>
              <td class="text-center">
                <div class="form-check form-switch d-inline-block mb-0">
                  <input class="form-check-input" type="checkbox" role="switch" name="enabled[<?= e($code) ?>]" value="1" id="on-<?= e($code) ?>"
                         aria-label="<?= e($code) ?> on" <?= $isOn($code) ? 'checked' : '' ?> <?= $alwaysOn ? 'disabled title="Always on – the user\'s own report"' : '' ?>>
                </div>
              </td>
              <td>
                <select class="form-select form-select-sm w-auto" name="severity[<?= e($code) ?>]" aria-label="<?= e($code) ?> severity" <?= $alwaysOn ? 'disabled' : '' ?>>
                  <option value="">default (<?= e($own) ?>)</option>
                  <?php foreach (array_keys(SEVERITIES) as $level): ?>
                    <option value="<?= e($level) ?>" <?= $severityOf($code) === $level ? 'selected' : '' ?>><?= e($level) ?></option>
                  <?php endforeach; ?>
                </select>
              </td>
              <td class="rule-params">
                <?php foreach ($paramsOf[$code] ?? [] as $name): ?>
                  <?= $paramInput($name) ?>
                <?php endforeach; ?>
                <?php if (in_array($code, RULE_PARAMS['learning_days']['rules'], true)): ?>
                  <div class="small text-muted">learning phase: <?= e((string)rule_param('learning_days')) ?> days (above)</div>
                <?php endif; ?>
              </td>
              <td class="small"><?= e($rule['when']) ?></td>
            </tr>
          <?php endforeach; ?>
        </tbody>
      </table>
    </div>
  </div>
  <div class="card-footer d-flex flex-wrap gap-2 align-items-center">
    <button class="btn btn-primary" type="submit">Save rules</button>
    <a class="btn btn-outline-secondary" href="<?= e(url_for('admin/alerts.php')) ?>#rules">Back to the alerts</a>
    <button class="btn btn-outline-secondary ms-auto" type="submit" name="reset" value="1" formnovalidate
            data-confirm="Reset all detection rules to their defaults (environment and built-in values)?">Reset all rules to defaults</button>
  </div>
</form>
<?php include view_path('footer'); ?>
