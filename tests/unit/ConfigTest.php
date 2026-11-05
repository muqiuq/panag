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
}
