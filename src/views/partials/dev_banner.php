<?php
// Development helper: choose which client IP PANAG should assume (users are identified by IP).
// Only rendered and honoured when APP_ENV=dev.
if (!is_dev_mode()) {
    return;
}
$__devIp = client_ip();
$__devUsers = [];
try {
    $__devUsers = db()->query('SELECT username, user_ip, role FROM users ORDER BY user_ip')->fetchAll(PDO::FETCH_ASSOC);
} catch (Throwable $e) {
    // DB not ready – the free-text field still works.
}
?>
<div class="bg-warning-subtle border-bottom border-warning small py-1" data-testid="dev-banner">
  <form method="post" action="<?= htmlspecialchars(url_for('dev_ip.php')) ?>" class="container-fluid d-flex flex-wrap align-items-center gap-2">
    <strong>DEV MODE</strong>
    <span>acting as client IP</span>
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
    <input type="text" name="ip" list="devIpList" value="<?= htmlspecialchars($__devIp) ?>" class="form-control form-control-sm dev-ip-input" aria-label="Dev client IP">
    <datalist id="devIpList">
      <?php foreach ($__devUsers as $__u): ?>
        <option value="<?= htmlspecialchars($__u['user_ip']) ?>"><?= htmlspecialchars($__u['username']) ?><?= $__u['role'] !== 'user' ? ' (' . htmlspecialchars($__u['role']) . ')' : '' ?></option>
      <?php endforeach; ?>
    </datalist>
    <button class="btn btn-sm btn-outline-dark" type="submit">Switch (logs out)</button>
    <span class="text-muted">OTP: <code>./run.sh otp</code></span>
  </form>
</div>
