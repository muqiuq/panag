<?php
// "Status today" – the status messages of all users (dashboard for non-admins). JS: public/js/status-message.js
// keeps the own entry up to date. Expects $statusMessages = active_status_messages(…) and $user.
$statusMessages = $statusMessages ?? active_status_messages(time());
?>
<div class="card shadow-sm mt-4" id="team-status">
  <div class="card-header d-flex justify-content-between align-items-center">
    <span>Status today</span>
    <span class="text-muted small">cleared at <?= sprintf('%02d:00', STATUS_MESSAGE_RESET_HOUR) ?></span>
  </div>
  <div class="card-body">
    <p class="text-muted mb-0" data-status-none <?= $statusMessages ? 'hidden' : '' ?>>Nobody has set a status today.</p>
    <ul class="list-unstyled mb-0 status-list" data-status-list>
      <?php foreach ($statusMessages as $sm): ?>
        <li data-status-user="<?= $sm['id'] ?>">
          <strong><?= e($sm['username']) ?></strong>
          <span class="status-message" data-status-text><?= e($sm['message']) ?></span>
          <span class="text-muted small text-nowrap" data-status-time>since <?= e(date('H:i', $sm['at'])) ?></span>
        </li>
      <?php endforeach; ?>
    </ul>
  </div>
</div>
