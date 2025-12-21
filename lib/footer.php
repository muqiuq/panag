</div>
<footer class="py-3 border-top mt-4">
		<div class="container d-flex flex-column flex-md-row justify-content-between align-items-center small text-muted">
				<span>PANAG (Philipp Admin Network Access Gatekeeper)</span>
				<span class="d-flex align-items-center gap-2">
						<?php if (function_exists('current_user')): $u = current_user(); if ($u && (int)$u['isadmin'] === 1): ?>
							<a href="<?= htmlspecialchars(url_for('test/index.php')) ?>" class="link-secondary">Tests</a>
							<span>|</span>
						<?php endif; endif; ?>
						<a href="https://github.com/example/panag" class="link-secondary" target="_blank" rel="noopener">GitHub</a>
						<span>|</span>
						<span>© Philipp Albrecht &lt;philipp@uisa.ch&gt;</span>
				</span>
				<?php if (function_exists('session_expires_at')): $exp = session_expires_at(); if ($exp): ?>
					<span>Session until <?= htmlspecialchars(date('Y-m-d H:i', $exp)) ?></span>
				<?php endif; endif; ?>
		</div>
</footer>
<script src="<?= htmlspecialchars(url_for('js/bootstrap.bundle.min.js')) ?>"></script>
</body>
</html>
