<?php
require_once __DIR__ . '/functions.php';
logout_user();
header('Location: ' . url_for('login.php'));
exit;
?>
