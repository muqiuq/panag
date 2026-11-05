<?php
require_once __DIR__ . '/../src/bootstrap.php';
logout_user();
header('Location: ' . url_for('login.php'));
exit;
?>
