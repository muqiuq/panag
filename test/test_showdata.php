<?php
require_once __DIR__ . '/../lib/functions.php';

if (!defined('ALLOW_TESTS') || !ALLOW_TESTS) {
    http_response_code(403);
    echo 'Tests are disabled.';
    exit;
}

if (!ALLOW_DEMO_DATA) {
    http_response_code(401);
    echo 'Demo data disabled.';
    exit;
}

header('Content-Type: text/html; charset=UTF-8');

$pdo = db();
$tables = ['users', 'networks', 'user_to_network'];

echo '<!DOCTYPE html><html><head><title>DB Dump</title></head><body>';
echo '<h1>SQLite contents</h1>';
echo '<p>Database path: ' . htmlspecialchars(DB_PATH, ENT_QUOTES, 'UTF-8') . '</p>';

foreach ($tables as $table) {
    echo '<h2>' . htmlspecialchars($table, ENT_QUOTES, 'UTF-8') . '</h2>';
    $stmt = $pdo->query('SELECT * FROM ' . $table);
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    if (!$rows) {
        echo '<p><em>Empty</em></p>';
        continue;
    }
    echo '<pre>';
    foreach ($rows as $row) {
        echo htmlspecialchars(json_encode($row, JSON_PRETTY_PRINT), ENT_QUOTES, 'UTF-8') . "\n\n";
    }
    echo '</pre>';
}

echo '</body></html>';
?>
