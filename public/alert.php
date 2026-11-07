<?php
// "Was this you?" – the affected user answers an alert (link in the alert mail and banner on the dashboard).
// Opening the link changes nothing; the answer is a POST with CSRF token.
require_once __DIR__ . '/../src/bootstrap.php';
require_login();
$user = current_user();
$alert = fetch_alert((int)($_GET['id'] ?? $_POST['id'] ?? 0));
if ($alert && is_admin($user) && (int)$alert['user_id'] !== (int)$user['id']) {
    header('Location: ' . url_for('admin/alerts.php') . '?id=' . (int)$alert['id']);
    exit;
}
if (!$alert || (int)$alert['user_id'] !== (int)$user['id']) {
    http_response_code(404);
    include view_path('header');
    echo '<div class="alert alert-warning" role="alert">This notice does not exist or is not about your account.</div>';
    include view_path('footer');
    exit;
}

$message = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_csrf_token($_POST['csrf_token'] ?? null);
    $response = (string)($_POST['response'] ?? '');
    if (in_array($response, ['me', 'not_me'], true) && alert_answerable($alert, $user)) {
        $message = alert_user_respond($alert, $user, $response);
        $alert = fetch_alert((int)$alert['id']);
    }
}
$userFindings = array_values(array_filter(alert_findings($alert), fn($f) => !empty($f['user_text'])));
$ai = alert_ai($alert);
include view_path('header');
?>
<div class="row justify-content-center">
  <div class="col-lg-8">
    <div class="card shadow-sm">
      <div class="card-header">Unusual activity on your account</div>
      <div class="card-body">
        <?php if ($message): ?>
          <div class="alert alert-<?= $alert['user_response'] === 'not_me' ? 'warning' : 'success' ?>" role="alert"><?= e($message) ?></div>
        <?php endif; ?>
        <ul class="list-group mb-3">
          <?php foreach ($userFindings ?: alert_findings($alert) as $f): ?>
            <li class="list-group-item"><span class="text-muted small"><?= e(date('Y-m-d H:i', (int)$f['at'])) ?></span><br><?= e($f['user_text'] ?: (MONITOR_RULES[$f['rule']] ?? $f['rule'])) ?></li>
          <?php endforeach; ?>
        </ul>
        <?php if ($ai && $ai['summary_user'] !== ''): ?>
          <p><?= e($ai['summary_user']) ?></p>
        <?php endif; ?>
        <?php if (alert_answerable($alert, $user)): ?>
          <p class="fw-semibold">Was this you?</p>
          <div class="d-flex flex-wrap gap-2">
            <form method="post">
              <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
              <input type="hidden" name="id" value="<?= (int)$alert['id'] ?>">
              <input type="hidden" name="response" value="me">
              <button class="btn btn-success">That was me</button>
            </form>
            <form method="post" data-confirm="Your active access will be revoked immediately and the admins informed. Continue?">
              <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
              <input type="hidden" name="id" value="<?= (int)$alert['id'] ?>">
              <input type="hidden" name="response" value="not_me">
              <button class="btn btn-outline-danger">That wasn't me</button>
            </form>
          </div>
          <p class="small text-muted mt-3 mb-0">“That wasn't me” revokes all of your active access right away and alerts the admins. “That was me” remembers the location for your account.</p>
        <?php elseif ($alert['user_response'] !== null): ?>
          <p class="mb-0">You answered: <strong><?= $alert['user_response'] === 'me' ? 'That was me' : "That wasn't me" ?></strong> (<?= e(date('Y-m-d H:i', (int)$alert['user_response_at'])) ?>).</p>
        <?php else: ?>
          <p class="mb-0 text-muted">An admin has already dealt with this notice – no answer needed.</p>
        <?php endif; ?>
      </div>
    </div>
  </div>
</div>
<?php include view_path('footer'); ?>
