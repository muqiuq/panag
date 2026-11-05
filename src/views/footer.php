</div>
<footer class="py-3 border-top mt-4">
		<div class="container d-flex flex-column flex-md-row justify-content-between align-items-center small text-muted">
				<span><?= htmlspecialchars(APP_NAME) ?> <?= htmlspecialchars(APP_VERSION) ?> (Philipp's Admin Network Access Gatekeeper)</span>
				<span class="d-flex align-items-center gap-2">
						<a href="https://github.com/muqiuq/panag" class="link-secondary" target="_blank" rel="noopener">GitHub</a>
						<span>|</span>
						<span>© Philipp Albrecht &lt;philipp@uisa.ch&gt;</span>
				</span>
				<?php $exp = session_expires_at(); if ($exp): ?>
					<span>Session until <?= htmlspecialchars(date('Y-m-d H:i', $exp)) ?></span>
				<?php endif; ?>
		</div>
</footer>
<script src="<?= htmlspecialchars(url_for('js/bootstrap.bundle.min.js')) ?>"></script>
</body>
</html>
