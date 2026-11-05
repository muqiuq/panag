<?php
// Single entry point for all pages, CLI scripts and tests.
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/client_ip.php';
require_once __DIR__ . '/router/RouterClient.php';
require_once __DIR__ . '/router/RestRouterClient.php';
require_once __DIR__ . '/functions.php';

function view_path(string $name): string
{
    return __DIR__ . '/views/' . $name . '.php';
}
