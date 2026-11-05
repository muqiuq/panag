<?php
use PHPUnit\Framework\TestCase;

/**
 * RestRouterClient against the mock RouterOS (dev/mock-routeros) over real HTTP.
 */
final class RestRouterClientTest extends TestCase
{
    private static BackgroundServer $server;
    private static string $stateFile;
    private RestRouterClient $client;

    public static function setUpBeforeClass(): void
    {
        require_once __DIR__ . '/../support/BackgroundServer.php';
        self::$stateFile = sys_get_temp_dir() . '/panag-mock-' . getmypid() . '.json';
        self::$server = new BackgroundServer(
            [PHP_BINARY, '-S', '127.0.0.1:{port}', __DIR__ . '/../../dev/mock-routeros/router.php'],
            ['MOCK_STATE_FILE' => self::$stateFile, 'MOCK_USERNAME' => 'admin', 'MOCK_PASSWORD' => 'mock', 'MOCK_TIMEOUT_SECONDS' => '3']
        );
    }

    public static function tearDownAfterClass(): void
    {
        self::$server->stop();
        @unlink(self::$stateFile);
    }

    protected function setUp(): void
    {
        $this->control('POST', '/_mock/reset');
        $this->client = $this->client('mock');
    }

    private function client(string $password, int $timeout = 5): RestRouterClient
    {
        return new RestRouterClient('http://127.0.0.1:' . self::$server->port . '/rest', 'admin', $password, '', 2, $timeout);
    }

    private function control(string $method, string $path, ?array $body = null): array
    {
        $ctx = stream_context_create(['http' => [
            'method' => $method,
            'header' => 'Content-Type: application/json',
            'content' => $body !== null ? json_encode($body) : '',
            'ignore_errors' => true,
        ]]);
        $raw = file_get_contents('http://127.0.0.1:' . self::$server->port . $path, false, $ctx);
        return json_decode((string)$raw, true) ?: [];
    }

    public function testAddListAndFilterAddressList(): void
    {
        $add = $this->client->addAddressListEntry('Whitelist 10.0.0.2', '10.10.0.0/24', 'Office', '01:00:00');
        $this->assertTrue($add['success'], (string)$add['error']);
        $this->assertMatchesRegularExpression('/^\*[0-9A-F]+$/', $add['data']['.id']);
        $this->client->addAddressListEntry('Whitelist 10.0.0.3', '10.10.0.0/24', 'Office', '00:15:00');

        $mine = $this->client->listAddressList('Whitelist 10.0.0.2');
        $this->assertTrue($mine['success']);
        $this->assertCount(1, $mine['data']);
        $this->assertSame('Office', $mine['data'][0]['comment']);
        $this->assertSame('true', $mine['data'][0]['dynamic']);
        $this->assertMatchesRegularExpression('/^(59m5\ds|1h)$/', $mine['data'][0]['timeout']);

        $all = $this->client->listAddressList();
        $this->assertCount(2, $all['data']);
    }

    public function testDuplicateIsRejectedLikeRouterOs(): void
    {
        $this->client->addAddressListEntry('Whitelist 10.0.0.2', '10.10.0.0/24', 'Office', '01:00:00');
        $dup = $this->client->addAddressListEntry('Whitelist 10.0.0.2', '10.10.0.0/24', 'Office', '01:00:00');
        $this->assertFalse($dup['success']);
        $this->assertSame(400, $dup['status']);
        $this->assertStringContainsString('already have such entry', (string)$dup['error']);
    }

    public function testUpdateTimeoutAndRemove(): void
    {
        $id = $this->client->addAddressListEntry('Whitelist 10.0.0.2', '10.10.0.0/24', 'Office', '00:15:00')['data']['.id'];
        $upd = $this->client->updateAddressListEntry($id, ['timeout' => '02:00:00']);
        $this->assertTrue($upd['success']);
        $this->assertMatchesRegularExpression('/^(2h|1h59m\d+s)$/', $upd['data']['timeout']);

        $del = $this->client->removeAddressListEntry($id);
        $this->assertTrue($del['success']);
        $this->assertSame(204, $del['status']);
        $this->assertCount(0, $this->client->listAddressList()['data']);
        $this->assertFalse($this->client->removeAddressListEntry($id)['success']);
    }

    public function testRejectsMalformedIds(): void
    {
        $this->assertFalse($this->client->removeAddressListEntry('../../system/reset')['success']);
    }

    public function testEntriesExpire(): void
    {
        $this->client->addAddressListEntry('Whitelist 10.0.0.2', '10.10.0.0/24', 'Office', '1s');
        $this->assertCount(1, $this->client->listAddressList()['data']);
        sleep(2);
        $this->assertCount(0, $this->client->listAddressList()['data']);
    }

    public function testSystemEndpoints(): void
    {
        $this->assertSame('mock-router', $this->client->identity()['data']['name']);
        $this->assertArrayHasKey('time', $this->client->clock()['data']);
        $this->assertArrayHasKey('uptime', $this->client->resource()['data']);
        $peers = $this->client->wireguardPeers();
        $this->assertTrue($peers['success']);
        $this->assertGreaterThanOrEqual(2, count($peers['data']));
    }

    public function testWrongCredentials(): void
    {
        $resp = $this->client('wrong')->identity();
        $this->assertFalse($resp['success']);
        $this->assertSame(401, $resp['status']);
    }

    public function testFaultInjection(): void
    {
        $this->control('POST', '/_mock/fault', ['mode' => '500']);
        $resp = $this->client->listAddressList();
        $this->assertFalse($resp['success']);
        $this->assertSame(500, $resp['status']);

        $this->control('POST', '/_mock/fault', ['mode' => 'timeout']);
        $started = microtime(true);
        $resp = $this->client('mock', 1)->identity();
        $this->assertFalse($resp['success']);
        $this->assertLessThan(2.5, microtime(true) - $started, 'client must honour its timeout');
        $this->control('POST', '/_mock/fault', ['mode' => 'none']);
    }

    public function testUnreachableRouterFailsFast(): void
    {
        $client = new RestRouterClient('http://127.0.0.1:1/rest', 'admin', 'x', '', 1, 2);
        $resp = $client->identity();
        $this->assertFalse($resp['success']);
        $this->assertNotEmpty($resp['error']);
    }
}
