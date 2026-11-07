<?php
// PHPUnit bootstrap: isolated data directory, then the normal application bootstrap.
$dataDir = sys_get_temp_dir() . '/panag-test-' . getmypid();
if (!is_dir($dataDir)) {
    mkdir($dataDir, 0775, true);
}
putenv('DATA_DIR=' . $dataDir);
putenv('APP_ENV=test');
putenv('MIKROTIK_BASE_URL=http://127.0.0.1:1/rest'); // never reach a real router from tests
// Security monitoring: on, with fakes for mail, GeoIP and AI (tests/support). Nothing leaves the process.
foreach ([
    'MONITOR_ENABLED=true', 'MONITOR_TOKEN=unit-monitor-token', 'MONITOR_ALLOWED_SOURCES=172.17.0.1/32',
    'MONITOR_ALLOWED_COUNTRIES=CH,DE', 'WIREGUARD_INTERFACE=wg0', 'GEOIP_AUTO_UPDATE=false',
    'SMTP_HOST=mail.invalid', 'MAIL_FROM=panag@example.test', 'ALERT_ADMIN_EMAILS=security@example.test',
    'APP_BASE_URL=https://panag.example.test', 'MONITOR_DIGEST_TIME=07:00',
    'MONITOR_AI=openrouter', 'OPENROUTER_API_KEY=unit-openrouter-key', 'OPENROUTER_PROVIDERS=TestProvider',
] as $setting) {
    putenv($setting);
}

require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../src/bootstrap.php';
require_once __DIR__ . '/support/FakeRouterClient.php';
require_once __DIR__ . '/support/MonitoringFakes.php';
require_once __DIR__ . '/../dev/geoip/MmdbWriter.php';

register_shutdown_function(static function () use ($dataDir) {
    foreach (glob($dataDir . '/*') ?: [] as $file) {
        @unlink($file);
    }
    @rmdir($dataDir);
});
