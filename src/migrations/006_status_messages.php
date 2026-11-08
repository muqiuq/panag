<?php
// Status message per user (PLAN.md, Phase 6): valid until the next 03:00, visible to every logged-in user.
return function (PDO $pdo): void {
    $pdo->exec('ALTER TABLE users ADD COLUMN status_message TEXT');
    $pdo->exec('ALTER TABLE users ADD COLUMN status_message_at INTEGER');
    $pdo->exec('ALTER TABLE users ADD COLUMN status_message_until INTEGER');
};
