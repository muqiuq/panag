<?php
// Security monitoring (docs/plan-security-monitoring.md): contact data, WireGuard state, known places,
// baselines, alerts and their delivery. Settings stay in environment variables; `settings` only keeps state.
return function (PDO $pdo): void {
    $pdo->exec('ALTER TABLE users ADD COLUMN email TEXT');
    $pdo->exec('ALTER TABLE users ADD COLUMN notify_alerts INTEGER NOT NULL DEFAULT 1');
    // Structured data for monitoring rules (e.g. granted network ids); NULL for older entries.
    $pdo->exec('ALTER TABLE audit_log ADD COLUMN meta TEXT');

    $pdo->exec('CREATE TABLE wg_peers (
        public_key TEXT PRIMARY KEY,
        name TEXT,
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        endpoint TEXT,
        country TEXT,
        asn INTEGER,
        last_handshake_at INTEGER,
        rx INTEGER NOT NULL DEFAULT 0,
        tx INTEGER NOT NULL DEFAULT 0,
        endpoint_changed_at INTEGER,
        polled_at INTEGER NOT NULL
    )');
    // Endpoint history. ip is cleared after MONITOR_IP_RETENTION_DAYS, country/asn stay.
    $pdo->exec('CREATE TABLE wg_endpoints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        public_key TEXT NOT NULL,
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        ip TEXT,
        country TEXT,
        asn INTEGER,
        asn_org TEXT,
        suspicious INTEGER NOT NULL DEFAULT 0,
        first_seen INTEGER NOT NULL,
        last_seen INTEGER NOT NULL
    )');
    $pdo->exec('CREATE INDEX idx_wg_endpoints_peer ON wg_endpoints (public_key, last_seen)');
    $pdo->exec('CREATE INDEX idx_wg_endpoints_user ON wg_endpoints (user_id, first_seen)');
    $pdo->exec('CREATE TABLE wg_traffic_days (
        public_key TEXT NOT NULL,
        day TEXT NOT NULL,
        bytes INTEGER NOT NULL DEFAULT 0,
        alerted INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (public_key, day)
    )');
    // Known places of a user: kind country (ISO code) or asn (number). pending = seen, not yet learned.
    $pdo->exec("CREATE TABLE user_locations (
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        kind TEXT NOT NULL CHECK (kind IN ('country', 'asn')),
        value TEXT NOT NULL,
        source TEXT NOT NULL CHECK (source IN ('pending', 'learned', 'confirmed', 'admin')),
        first_seen INTEGER NOT NULL,
        last_seen INTEGER NOT NULL,
        PRIMARY KEY (user_id, kind, value)
    )");
    $pdo->exec('CREATE TABLE user_baselines (
        user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        data TEXT NOT NULL,
        computed_at INTEGER NOT NULL
    )');
    $pdo->exec("CREATE TABLE alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        user_label TEXT,
        rules TEXT NOT NULL,
        severity TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
        notify_user INTEGER NOT NULL DEFAULT 0,
        summary TEXT NOT NULL,
        findings TEXT NOT NULL,
        ai TEXT,
        status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'false_positive', 'confirmed', 'resolved')),
        status_by TEXT,
        status_at INTEGER,
        status_comment TEXT,
        user_response TEXT CHECK (user_response IN ('me', 'not_me')),
        user_response_at INTEGER,
        notified_at INTEGER,
        notify_attempts INTEGER NOT NULL DEFAULT 0,
        notify_error TEXT
    )");
    $pdo->exec('CREATE INDEX idx_alerts_user ON alerts (user_id, created_at)');
    $pdo->exec('CREATE INDEX idx_alerts_status ON alerts (status, created_at)');
    $pdo->exec('CREATE TABLE alert_keys (
        dedupe_key TEXT NOT NULL,
        alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
        created_at INTEGER NOT NULL
    )');
    $pdo->exec('CREATE INDEX idx_alert_keys ON alert_keys (dedupe_key, created_at)');
    $pdo->exec("CREATE TABLE alert_events (
        alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
        ref_type TEXT NOT NULL CHECK (ref_type IN ('audit', 'wg')),
        ref_id INTEGER NOT NULL,
        PRIMARY KEY (alert_id, ref_type, ref_id)
    )");
    $pdo->exec('CREATE TABLE alert_deliveries (
        alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
        recipient TEXT NOT NULL,
        delivered_at INTEGER NOT NULL,
        PRIMARY KEY (alert_id, recipient)
    )');
    // Every mail attempt (alert, digest, test, health) – for the monitoring page and the hourly limit.
    $pdo->exec("CREATE TABLE mail_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at INTEGER NOT NULL,
        kind TEXT NOT NULL,
        recipient TEXT NOT NULL,
        subject TEXT NOT NULL,
        max_severity TEXT,
        ok INTEGER NOT NULL,
        error TEXT
    )");
    $pdo->exec('CREATE INDEX idx_mail_log_created ON mail_log (created_at)');
};
