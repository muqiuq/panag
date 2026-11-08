<?php
// Sensitive networks (PLAN.md, Phase 6): never a default network, only single grants.
return function (PDO $pdo): void {
    $pdo->exec('ALTER TABLE networks ADD COLUMN sensitive INTEGER NOT NULL DEFAULT 0');
};
