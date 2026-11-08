<?php
use PHPUnit\Framework\TestCase;

/** Full backup and restore (admin/config.php#backup) – on separate database files, not the shared test DB. */
final class FullBackupTest extends TestCase
{
    private string $dir;

    public static function setUpBeforeClass(): void
    {
        require_once __DIR__ . '/../../src/backup.php';
    }

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/panag-fullbackup-' . bin2hex(random_bytes(4));
        mkdir($this->dir, 0770, true);
    }

    protected function tearDown(): void
    {
        $this->rmTree($this->dir);
    }

    private function rmTree(string $dir): void
    {
        foreach (scandir($dir) ?: [] as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            $path = $dir . '/' . $entry;
            is_dir($path) ? $this->rmTree($path) : unlink($path);
        }
        rmdir($dir);
    }

    private function database(string $name, ?int $schema = null): PDO
    {
        $pdo = db_connect('sqlite:' . $this->dir . '/' . $name . '.sqlite');
        migrate($pdo, null, $schema);
        return $pdo;
    }

    private function fill(PDO $pdo, string $prefix): void
    {
        $pdo->exec("INSERT INTO users (username, user_ip, otp_secret, role, accesslevel) VALUES ('{$prefix} Admin', '10.0.0.1', 'JBSWY3DPEHPK3PXP', 'admin', 15), ('{$prefix} User', '10.0.0.2', 'JBSWY3DPEHPK3PXP', 'user', 5)");
        $pdo->exec("INSERT INTO networks (name, accesslevel, address) VALUES ('{$prefix} Office', 1, '10.10.0.0/24'), ('{$prefix} DC', 8, '192.168.100.0/24')");
        $pdo->exec('INSERT INTO user_to_network (user_id, network_id) SELECT u.id, n.id FROM users u, networks n WHERE n.accesslevel <= u.accesslevel');
        $pdo->exec("INSERT INTO settings (key, value) VALUES ('{$prefix}.key', '\"{$prefix}\"')");
        $pdo->exec("INSERT INTO audit_log (user_id, username, user_ip, action, details, created_at) VALUES (1, '{$prefix} Admin', '10.0.0.1', 'login_success', 'ünïcödé ✓', 1800000000)");
    }

    /** @return array<string, list<array<string, mixed>>> */
    private function dump(PDO $pdo): array
    {
        $out = [];
        foreach (backup_tables($pdo) as $table) {
            $out[$table] = $pdo->query('SELECT * FROM "' . $table . '" ORDER BY rowid')->fetchAll(PDO::FETCH_ASSOC);
        }
        $out['sqlite_sequence'] = $pdo->query('SELECT name, seq FROM sqlite_sequence ORDER BY name')->fetchAll(PDO::FETCH_ASSOC);
        return $out;
    }

    public function testRoundTripReplacesEverything(): void
    {
        $source = $this->database('source');
        $this->fill($source, 'Src');
        $source->exec("UPDATE users SET status_message = 'on call', status_message_at = 1, status_message_until = 2 WHERE id = 2");
        $source->exec('DELETE FROM networks WHERE id = 2'); // a gap in the ids
        $json = export_full_backup_json($source, 1800000000);
        $backup = json_decode($json, true);
        $this->assertSame(FULL_BACKUP_FORMAT, $backup['format']);
        $this->assertSame(latest_schema_version(), $backup['schema_version']);
        $this->assertSame(2, $backup['sequences']['networks']);
        $this->assertArrayHasKey('alerts', $backup['tables']);

        $target = $this->database('target');
        $this->fill($target, 'Old');
        $target->exec("INSERT INTO networks (name, accesslevel, address) VALUES ('Old extra', 1, '10.20.0.0/24')");
        $before = $this->dump($target);

        $result = restore_full_backup($target, $json, $this->dir . '/backups');

        $this->assertSame($this->dump($source), $this->dump($target), 'identical data, ids and AUTOINCREMENT counters');
        $this->assertFileExists($result['safety_copy']);
        $copy = db_connect('sqlite:' . $result['safety_copy']);
        $this->assertSame($before['networks'], $this->dump($copy)['networks'], 'the safety copy holds the old data');
        $this->assertSame([], glob($this->dir . '/backups/tmp/*') ?: [], 'staging file removed');
        $this->assertSame([], $target->query('PRAGMA foreign_key_check')->fetchAll());
    }

    public function testOlderBackupsAreMigrated(): void
    {
        $old = $this->database('old', 5); // before status messages
        $this->fill($old, 'V5');
        $json = export_full_backup_json($old, 1800000000);
        $this->assertSame(5, json_decode($json, true)['schema_version']);

        $target = $this->database('target');
        restore_full_backup($target, $json, $this->dir . '/backups');
        $this->assertSame(latest_schema_version(), schema_version($target));
        $users = $target->query('SELECT username, status_message FROM users ORDER BY id')->fetchAll(PDO::FETCH_ASSOC);
        $this->assertSame([['username' => 'V5 Admin', 'status_message' => null], ['username' => 'V5 User', 'status_message' => null]], $users);
    }

    /** @return iterable<string, array{0: callable(array<string, mixed>): mixed, 1: string}> */
    public static function brokenBackups(): iterable
    {
        yield 'not a backup' => [fn($b) => ['users' => []], 'not a PANAG full backup'];
        yield 'future schema' => [fn($b) => ['schema_version' => latest_schema_version() + 1] + $b, 'schema version'];
        yield 'unknown table' => [fn($b) => array_replace_recursive($b, ['tables' => ['evil' => [['x' => 1]]]]), 'Unknown table in the backup: evil'];
        yield 'unknown column' => [function ($b) { $b['tables']['users'][0]['isroot'] = 1; return $b; }, 'Unknown column users.isroot'];
        yield 'nested value' => [function ($b) { $b['tables']['users'][0]['username'] = ['x']; return $b; }, 'Invalid value in users.username'];
        yield 'no admin' => [function ($b) { $b['tables']['users'][0]['role'] = 'user'; return $b; }, 'contains no admin'];
        yield 'dangling reference' => [function ($b) { $b['tables']['user_to_network'][] = ['user_id' => 99, 'network_id' => 1]; return $b; }, 'reference missing rows'];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('brokenBackups')]
    public function testBrokenBackupsChangeNothing(callable $break, string $error): void
    {
        $source = $this->database('source');
        $this->fill($source, 'Src');
        $backup = $break(export_full_backup($source, 1800000000));

        $target = $this->database('target');
        $this->fill($target, 'Keep');
        $before = $this->dump($target);
        try {
            restore_full_backup($target, (string)json_encode($backup), $this->dir . '/backups');
            $this->fail('restore should have been refused');
        } catch (InvalidArgumentException $e) {
            $this->assertStringContainsString($error, $e->getMessage());
        }
        $this->assertSame($before, $this->dump($target));
        $this->assertSame([], glob($this->dir . '/backups/*.sqlite') ?: [], 'no safety copy for refused restores');
        $this->assertSame([], glob($this->dir . '/backups/tmp/*') ?: []);
    }
}
