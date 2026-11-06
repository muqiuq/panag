<?php
// Schema of PANAG V0.1. Idempotent: existing V0.1 databases are left untouched.
return function (PDO $pdo): void {
    $pdo->exec('CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        user_ip TEXT NOT NULL UNIQUE,
        otp_secret TEXT NOT NULL,
        isadmin INTEGER NOT NULL DEFAULT 0,
        accesslevel INTEGER NOT NULL DEFAULT 0
    )');
    $pdo->exec('CREATE TABLE IF NOT EXISTS networks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        accesslevel INTEGER NOT NULL DEFAULT 0,
        address TEXT NOT NULL
    )');
    $pdo->exec('CREATE TABLE IF NOT EXISTS user_to_network (
        user_id INTEGER NOT NULL,
        network_id INTEGER NOT NULL,
        PRIMARY KEY (user_id, network_id),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (network_id) REFERENCES networks(id) ON DELETE CASCADE
    )');
    $pdo->exec('CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        ip TEXT NOT NULL,
        success INTEGER NOT NULL,
        created_at INTEGER NOT NULL
    )');
    $pdo->exec('CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        user_ip TEXT,
        action TEXT NOT NULL,
        details TEXT,
        ip TEXT,
        created_at INTEGER NOT NULL
    )');
    $pdo->exec('CREATE TABLE IF NOT EXISTS otp_used (
        user_id INTEGER NOT NULL,
        otp_counter INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (user_id, otp_counter),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )');
};
