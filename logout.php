<?php
require_once __DIR__ . '/lib/functions.php';
logout_user();
header('Location: ' . url_for('login.php'));
exit;
?>
