<?php
// Remove rows orphaned while foreign keys were not enforced (V0.1), drop the legacy isadmin flag,
// and add indexes for the audit-log lookups done on every dashboard view.
return function (PDO $pdo): void {
    $pdo->exec('DELETE FROM user_to_network WHERE user_id NOT IN (SELECT id FROM users) OR network_id NOT IN (SELECT id FROM networks)');
    $pdo->exec('DELETE FROM otp_used WHERE user_id NOT IN (SELECT id FROM users)');
    $pdo->exec('ALTER TABLE users DROP COLUMN isadmin');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_audit_log_action_ip ON audit_log (action, user_ip)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_audit_log_created ON audit_log (created_at)');
};
