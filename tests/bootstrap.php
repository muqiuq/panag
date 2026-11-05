<?php
// PHPUnit bootstrap: isolated data directory, then the normal application bootstrap.
$dataDir = sys_get_temp_dir() . '/panag-test-' . getmypid();
if (!is_dir($dataDir)) {
    mkdir($dataDir, 0775, true);
}
putenv('DATA_DIR=' . $dataDir);
putenv('APP_ENV=test');
putenv('MIKROTIK_BASE_URL=http://127.0.0.1:1/rest'); // never reach a real router from tests

require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../src/bootstrap.php';
require_once __DIR__ . '/support/FakeRouterClient.php';

register_shutdown_function(static function () use ($dataDir) {
    foreach (glob($dataDir . '/*') ?: [] as $file) {
        @unlink($file);
    }
    @rmdir($dataDir);
});
