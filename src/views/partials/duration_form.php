<?php
// Access durations form (JS: public/js/durations.js) – own profile and admin user page.
// Expects $dfAction (form action), $dfInput (['default' => 'h:mm', 'extended' => 'h:mm']), $dfErrors (list).
$dfAction = $dfAction ?? throw new LogicException('duration_form needs $dfAction');
$dfInput = $dfInput ?? throw new LogicException('duration_form needs $dfInput');
$dfErrors = $dfErrors ?? [];
?>
<?php if ($dfErrors): ?>
  <div class="alert alert-danger" role="alert"><?= e(implode(' ', $dfErrors)) ?></div>
<?php endif; ?>
<form method="post" action="<?= e($dfAction) ?>" novalidate>
  <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
  <input type="hidden" name="action" value="save_durations">
  <?php foreach (['default' => 'Default access', 'extended' => 'Extended access'] as $kind => $label): ?>
    <div class="mb-3" data-duration-field>
      <label class="form-label" for="duration-<?= $kind ?>"><?= $label ?></label>
      <div class="d-flex flex-wrap gap-1 mb-2">
        <?php foreach (grant_duration_presets($kind) as $preset): ?>
          <button type="button" class="btn btn-sm btn-outline-secondary" data-preset="<?= e(format_duration_input($preset)) ?>"><?= e(format_duration_human($preset)) ?></button>
        <?php endforeach; ?>
      </div>
      <div class="input-group">
        <input type="text" class="form-control" id="duration-<?= $kind ?>" name="<?= $kind ?>_duration" value="<?= e($dfInput[$kind]) ?>"
               inputmode="numeric" autocomplete="off" aria-describedby="duration-<?= $kind ?>-help" <?= $dfErrors ? 'aria-invalid="true"' : '' ?>>
        <span class="input-group-text">h:mm</span>
      </div>
      <div class="form-text" id="duration-<?= $kind ?>-help">
        <?= e(format_duration_human(MIN_GRANT_DURATION)) ?> – <?= e(format_duration_human(max_grant_duration($kind))) ?><span data-until></span>
      </div>
    </div>
  <?php endforeach; ?>
  <p class="form-text">Default: “Grant default access”. Extended: every single network (dashboard table or search field).</p>
  <button class="btn btn-primary" type="submit">Save durations</button>
</form>
