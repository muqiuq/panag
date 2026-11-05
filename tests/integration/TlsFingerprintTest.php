<?php
use PHPUnit\Framework\TestCase;

/**
 * Certificate pinning of RestRouterClient against a self-signed TLS server (openssl s_server),
 * the typical RouterOS www-ssl setup.
 */
final class TlsFingerprintTest extends TestCase
{
    private static ?BackgroundServer $server = null;
    private static string $dir;
    private static string $fingerprint;

    public static function setUpBeforeClass(): void
    {
        require_once __DIR__ . '/../support/BackgroundServer.php';
        if (trim((string)shell_exec('command -v openssl')) === '') {
            return;
        }
        self::$dir = sys_get_temp_dir() . '/panag-tls-' . getmypid();
        @mkdir(self::$dir);
        $cert = self::$dir . '/cert.pem';
        $key = self::$dir . '/key.pem';
        exec(sprintf(
            'openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=router.invalid -keyout %s -out %s 2>/dev/null',
            escapeshellarg($key),
            escapeshellarg($cert)
        ));
        self::$fingerprint = strtoupper(openssl_x509_fingerprint((string)file_get_contents($cert), 'sha256'));
        // -www answers every request with HTTP 200 and a status page.
        self::$server = new BackgroundServer(['openssl', 's_server', '-quiet', '-accept', '{port}', '-cert', $cert, '-key', $key, '-www']);
    }

    public static function tearDownAfterClass(): void
    {
        self::$server?->stop();
        foreach (glob((self::$dir ?? '/nonexistent') . '/*') ?: [] as $f) {
            @unlink($f);
        }
        @rmdir(self::$dir ?? '');
    }

    protected function setUp(): void
    {
        if (self::$server === null) {
            $this->markTestSkipped('openssl binary not available');
        }
    }

    private function request(string $fingerprint): array
    {
        $client = new RestRouterClient('https://127.0.0.1:' . self::$server->port . '/rest', 'admin', 'x', $fingerprint, 2, 5);
        return $client->request('GET', '/system/identity');
    }

    public function testMatchingPinnedFingerprintIsAccepted(): void
    {
        // Colon-separated, lowercase format as shown by RouterOS must work too.
        $pretty = strtolower(implode(':', str_split(self::$fingerprint, 2)));
        $resp = $this->request($pretty);
        $this->assertTrue($resp['success'], (string)$resp['error']);
        $this->assertSame(self::$fingerprint, $resp['fingerprint']);
    }

    public function testWrongPinnedFingerprintIsRejected(): void
    {
        $resp = $this->request(str_repeat('AB', 32));
        $this->assertFalse($resp['success']);
        $this->assertStringContainsString('fingerprint mismatch', (string)$resp['error']);
    }

    public function testSelfSignedWithoutPinningFailsAndShowsFingerprint(): void
    {
        $resp = $this->request('');
        $this->assertFalse($resp['success']);
        $this->assertSame(self::$fingerprint, $resp['fingerprint']);
        $this->assertStringContainsString(self::$fingerprint, (string)$resp['error']);
    }
}
