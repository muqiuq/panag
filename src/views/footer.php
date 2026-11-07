<?php
// Closes the page opened by header.php. Pages list their own scripts in $pageScripts (paths below public/);
// they run after the shared ones. No inline JavaScript – the Content-Security-Policy forbids it.
$pageScripts = $pageScripts ?? [];
$sharedScripts = ['js/bootstrap.bundle.min.js', 'js/app.js', 'js/table-sort.js'];
if (current_user()) {
    $sharedScripts[] = 'js/palette.js';
}
?>
</div>
<footer class="py-3 border-top mt-4">
  <div class="container d-flex flex-column flex-md-row justify-content-between align-items-center small text-muted">
    <span><?= e(APP_NAME) ?> <?= e(APP_VERSION) ?> (Philipp's Admin Network Access Gatekeeper)</span>
    <span class="d-flex align-items-center gap-2">
      <a href="https://github.com/muqiuq/panag" class="link-secondary" target="_blank" rel="noopener">GitHub</a>
      <span>|</span>
      <span>© Philipp Albrecht &lt;philipp@uisa.ch&gt;</span>
    </span>
    <?php $exp = session_expires_at(); if ($exp): ?>
      <span>Session until <?= e(date('Y-m-d H:i', $exp)) ?></span>
    <?php endif; ?>
  </div>
</footer>
<?php foreach (array_merge($sharedScripts, $pageScripts) as $script): ?>
<script src="<?= e(url_for($script)) ?>"></script>
<?php endforeach; ?>
</body>
</html>
