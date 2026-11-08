<?php
use PHPUnit\Framework\TestCase;

/**
 * Migrating a database created by PANAG V0.1 (no user_version, isadmin flag, orphaned rows).
 */
final class MigrationTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/panag-migration-' . uniqid();
        mkdir($this->dir);
    }

    protected function tearDown(): void
    {
        foreach (array_merge(glob($this->dir . '/*/*') ?: [], glob($this->dir . '/*') ?: []) as $f) {
            is_dir($f) ? @rmdir($f) : @unlink($f);
        }
        @rmdir($this->dir);
    }

    /** Exact schema written by init_db() in V0.1. */
    private function createV01Database(string $path): PDO
    {
        $pdo = new PDO('sqlite:' . $path);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->exec('CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, user_ip TEXT NOT NULL UNIQUE, otp_secret TEXT NOT NULL, isadmin INTEGER NOT NULL DEFAULT 0, accesslevel INTEGER NOT NULL DEFAULT 0)');
        $pdo->exec('CREATE TABLE networks (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, accesslevel INTEGER NOT NULL DEFAULT 0, address TEXT NOT NULL)');
        $pdo->exec('CREATE TABLE user_to_network (user_id INTEGER NOT NULL, network_id INTEGER NOT NULL, PRIMARY KEY (user_id, network_id), FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE, FOREIGN KEY (network_id) REFERENCES networks(id) ON DELETE CASCADE)');
        $pdo->exec('CREATE TABLE login_attempts (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, ip TEXT NOT NULL, success INTEGER NOT NULL, created_at INTEGER NOT NULL)');
        $pdo->exec('CREATE TABLE audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, username TEXT, user_ip TEXT, action TEXT NOT NULL, details TEXT, ip TEXT, created_at INTEGER NOT NULL)');
        $pdo->exec('CREATE TABLE otp_used (user_id INTEGER NOT NULL, otp_counter INTEGER NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (user_id, otp_counter), FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)');

        $pdo->exec("INSERT INTO users (id, username, user_ip, otp_secret, isadmin, accesslevel) VALUES
            (1, 'Alice Admin', '10.8.0.2', 'JBSWY3DPEHPK3PXP', 1, 15),
            (2, 'Bob', '10.8.0.3', 'JBSWY3DPEHPK3PXP', 0, 5)");
        $pdo->exec("INSERT INTO networks (id, name, accesslevel, address) VALUES (1, 'Office', 1, '10.10.0.0/24'), (2, 'DC', 8, '192.168.100.0/24')");
        // Valid mappings plus orphans left behind because V0.1 never enabled foreign keys.
        $pdo->exec('INSERT INTO user_to_network (user_id, network_id) VALUES (1, 1), (1, 2), (2, 1), (99, 1), (2, 42)');
        $pdo->exec('INSERT INTO otp_used (user_id, otp_counter, created_at) VALUES (1, 100, 1), (99, 100, 1)');
        $pdo->exec("INSERT INTO audit_log (user_id, username, user_ip, action, details, ip, created_at) VALUES (1, 'Alice Admin', '10.8.0.2', 'login_success', 'User logged in', '10.8.0.2', 1700000000)");
        return $pdo;
    }

    private function columns(PDO $pdo, string $table): array
    {
        return array_column($pdo->query("PRAGMA table_info({$table})")->fetchAll(PDO::FETCH_ASSOC), 'name');
    }

    public function testMigratesV01DatabaseWithoutDataLoss(): void
    {
        $path = $this->dir . '/v01.sqlite';
        $this->createV01Database($path);
        $pdo = db_connect('sqlite:' . $path);
        $this->assertSame(0, schema_version($pdo));

        $applied = migrate($pdo);

        $this->assertSame(['001_baseline', '002_roles_prefs', '003_cleanup', '004_monitoring', '005_sensitive_networks', '006_status_messages'], $applied);
        $this->assertSame(latest_schema_version(), schema_version($pdo));

        $users = $pdo->query('SELECT * FROM users ORDER BY id')->fetchAll(PDO::FETCH_ASSOC);
        $this->assertSame('admin', $users[0]['role']);
        $this->assertSame('user', $users[1]['role']);
        $this->assertSame(3600, (int)$users[1]['default_duration_sec']);
        $this->assertSame(900, (int)$users[1]['extended_duration_sec']);
        $this->assertSame('default', $users[1]['theme']);
        $this->assertNull($users[1]['email']);                    // 004: no address until set
        $this->assertNull($users[1]['status_message']);           // 006
        $this->assertSame(1, (int)$users[1]['notify_alerts']);
        $this->assertContains('meta', $this->columns($pdo, 'audit_log'));
        $this->assertSame([0, 0], array_map('intval', $pdo->query('SELECT sensitive FROM networks ORDER BY id')->fetchAll(PDO::FETCH_COLUMN))); // 005
        foreach (['wg_peers', 'wg_endpoints', 'user_locations', 'alerts', 'alert_deliveries', 'mail_log'] as $table) {
            $this->assertNotEmpty($this->columns($pdo, $table), $table);
        }
        $this->assertSame('JBSWY3DPEHPK3PXP', $users[0]['otp_secret']);
        $this->assertNotContains('isadmin', $this->columns($pdo, 'users'));

        $mappings = $pdo->query('SELECT user_id, network_id FROM user_to_network ORDER BY user_id, network_id')->fetchAll(PDO::FETCH_NUM);
        $this->assertSame([[1, 1], [1, 2], [2, 1]], array_map(fn($r) => array_map('intval', $r), $mappings));
        $this->assertSame(1, (int)$pdo->query('SELECT COUNT(*) FROM otp_used')->fetchColumn());
        $this->assertSame(1, (int)$pdo->query('SELECT COUNT(*) FROM audit_log')->fetchColumn());
        $this->assertSame(2, (int)$pdo->query('SELECT COUNT(*) FROM networks')->fetchColumn());
        $this->assertContains('settings', $pdo->query("SELECT name FROM sqlite_master WHERE type = 'table'")->fetchAll(PDO::FETCH_COLUMN));
        $this->assertSame('ok', $pdo->query('PRAGMA foreign_key_check')->fetchColumn() ?: 'ok');
    }

    public function testRoleConstraintIsEnforced(): void
    {
        $pdo = db_connect('sqlite:' . $this->dir . '/c.sqlite');
        migrate($pdo);
        $this->expectException(PDOException::class);
        $pdo->exec("INSERT INTO users (username, user_ip, otp_secret, role) VALUES ('x', '10.0.0.1', 'A', 'root')");
    }

    public function testFreshDatabaseAndIdempotence(): void
    {
        $pdo = db_connect('sqlite:' . $this->dir . '/fresh.sqlite');
        $this->assertCount(latest_schema_version(), migrate($pdo));
        $this->assertSame([], migrate($pdo));
        $this->assertSame([], pending_migrations($pdo));
        $this->assertContains('role', $this->columns($pdo, 'users'));
    }

    public function testBackupIsConsistentAndRotated(): void
    {
        $path = $this->dir . '/v01.sqlite';
        $this->createV01Database($path);
        $pdo = db_connect('sqlite:' . $path);

        $backup = backup_database($pdo, $this->dir . '/backups', 'test');
        $copy = new PDO('sqlite:' . $backup);
        $this->assertSame(2, (int)$copy->query('SELECT COUNT(*) FROM users')->fetchColumn());

        for ($i = 0; $i < 6; $i++) {
            touch($this->dir . '/backups/panag-20000101-00000' . $i . '-old.sqlite');
        }
        backup_database($pdo, $this->dir . '/backups', 'again', 3);
        $this->assertCount(3, glob($this->dir . '/backups/panag-*.sqlite'));
    }
}
