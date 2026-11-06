<?php
// Roles (user / superuser / admin) and per-user preferences.
return function (PDO $pdo): void {
    $pdo->exec("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'superuser', 'admin'))");
    $pdo->exec("UPDATE users SET role = CASE WHEN isadmin = 1 THEN 'admin' ELSE 'user' END");
    // Durations in seconds; defaults match the former global DEFAULT_TIMEOUT (1 h) / EXTENDED_TIMEOUT (15 min).
    $pdo->exec('ALTER TABLE users ADD COLUMN default_duration_sec INTEGER NOT NULL DEFAULT 3600');
    $pdo->exec('ALTER TABLE users ADD COLUMN extended_duration_sec INTEGER NOT NULL DEFAULT 900');
    $pdo->exec("ALTER TABLE users ADD COLUMN theme TEXT NOT NULL DEFAULT 'default'");
    $pdo->exec('CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    )');
};
