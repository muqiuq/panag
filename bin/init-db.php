<?php
// Create the SQLite database and schema if missing. Run by the container entrypoint.
require __DIR__ . '/_cli.php';

db();
echo 'Database ready: ' . DB_PATH . PHP_EOL;
