<?php
// Make config constants and functions known to PHPStan.
putenv('DATA_DIR=' . sys_get_temp_dir() . '/panag-phpstan');
require_once __DIR__ . '/../src/bootstrap.php';
require_once __DIR__ . '/../src/backup.php';
require_once __DIR__ . '/../src/statistics.php';
