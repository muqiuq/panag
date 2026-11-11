<?php
use PHPUnit\Framework\TestCase;

final class ConfigTest extends TestCase
{
    protected function tearDown(): void
    {
        putenv('PANAG_TEST_VALUE');
        putenv('PANAG_TEST_VALUE_FILE');
    }

    public function testEnvValueAndDefault(): void
    {
        $this->assertSame('fallback', panag_env('PANAG_TEST_VALUE', 'fallback'));
        putenv('PANAG_TEST_VALUE=hello');
        $this->assertSame('hello', panag_env('PANAG_TEST_VALUE', 'fallback'));
    }

    public function testFileVariantForSecrets(): void
    {
        $file = tempnam(sys_get_temp_dir(), 'panag');
        file_put_contents($file, "s3cret\n");
        putenv('PANAG_TEST_VALUE_FILE=' . $file);
        $this->assertSame('s3cret', panag_env('PANAG_TEST_VALUE'));
        unlink($file);
    }

    public function testListAndBoolParsing(): void
    {
        putenv('PANAG_TEST_VALUE=10.0.0.0/8, 192.168.0.0/16 127.0.0.1');
        $this->assertSame(['10.0.0.0/8', '192.168.0.0/16', '127.0.0.1'], panag_env_list('PANAG_TEST_VALUE', []));
        putenv('PANAG_TEST_VALUE=yes');
        $this->assertTrue(panag_env_bool('PANAG_TEST_VALUE', false));
        putenv('PANAG_TEST_VALUE=0');
        $this->assertFalse(panag_env_bool('PANAG_TEST_VALUE', true));
    }

    public function testDataPathsLiveInDataDir(): void
    {
        $this->assertStringStartsWith(DATA_DIR, DB_PATH);
        $this->assertStringStartsWith(DATA_DIR, RESET_LOGIN_FILE);
        $this->assertSame('env', panag_config_sources()['DATA_DIR']);
    }

    public function testEverySettingIsDocumented(): void
    {
        $example = (string)file_get_contents(__DIR__ . '/../../.env.example');
        preg_match_all('/^#?\s*([A-Z][A-Z0-9_]+)(?:_FILE)?=/m', $example, $m);
        $documented = array_unique($m[1]);
        foreach (panag_config_items() as $name => $meta) {
            $this->assertContains($name, $documented, $name . ' is missing in .env.example');
            $this->assertNotSame('', $meta['description'], $name . ' needs a description');
            $this->assertNotSame('Other', $meta['group'], $name . ' needs a group');
        }
    }

    public function testSecretsAreNeverShown(): void
    {
        foreach (['MIKROTIK_PASSWORD', 'SETUP_TOKEN', 'MONITOR_TOKEN', 'SMTP_PASSWORD', 'OPENROUTER_API_KEY', 'MONITOR_PSEUDONYM_KEY'] as $name) {
            $this->assertTrue(panag_config_items()[$name]['secret'], $name . ' must be flagged as secret');
            $this->assertTrue(panag_config_is_secret($name));
        }
        $this->assertTrue(panag_config_is_secret('SOME_FUTURE_API_KEY'), 'name pattern as safety net');
        $this->assertFalse(panag_config_is_secret('SMTP_HOST'));
    }

    public function testFileOriginAndUnreadableFile(): void
    {
        $file = tempnam(sys_get_temp_dir(), 'panag');
        file_put_contents($file, "s3cret\n");
        putenv('PANAG_TEST_VALUE_FILE=' . $file);
        $this->assertSame(['value' => 's3cret', 'source' => 'file', 'file' => $file], panag_env_info('PANAG_TEST_VALUE'));
        unlink($file);
        $this->assertSame('default', panag_env_info('PANAG_TEST_VALUE')['source']);
        $this->assertContains('PANAG_TEST_VALUE_FILE points to a file that cannot be read: ' . $file, array_column(panag_config_warnings(), 'message'));
    }

    public function testFeatureChecks(): void
    {
        // tests/bootstrap.php configures mail and AI completely
        $this->assertNull(mail_config_problem());
        $this->assertNull(ai_config_problem());
        $this->assertNull(monitor_config_problem());
        $this->assertSame(1800, MONITOR_BUNDLE_WINDOW, 'durations are parsed to seconds');
        $this->assertSame(['CH', 'DE'], MONITOR_ALLOWED_COUNTRIES);
    }

    public function testDataDirSecretIsGeneratedOnceAndKept(): void
    {
        $file = rtrim(DATA_DIR, '/') . '/test.secret';
        @unlink($file);
        $secret = data_dir_secret('test.secret');
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $secret);
        $this->assertSame($secret, file_get_contents($file), 'no newline – the RouterOS scheduler sends the contents as header value');
        $this->assertSame('600', substr(sprintf('%o', fileperms($file)), -3));
        $this->assertSame($secret, data_dir_secret('test.secret'), 'reused, not regenerated');
        unlink($file);
    }
}
