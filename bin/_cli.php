<?php
// Shared bootstrap for CLI scripts.
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}
require_once __DIR__ . '/../src/bootstrap.php';

function cli_fail(string $message, int $code = 1): void
{
    fwrite(STDERR, $message . PHP_EOL);
    exit($code);
}

/** Parse --key=value / --flag arguments. */
function cli_options(array $argv): array
{
    $opts = [];
    foreach (array_slice($argv, 1) as $arg) {
        if (preg_match('/^--([a-z0-9-]+)(?:=(.*))?$/i', $arg, $m)) {
            $opts[$m[1]] = $m[2] ?? true;
        } else {
            $opts['_'][] = $arg;
        }
    }
    return $opts;
}
