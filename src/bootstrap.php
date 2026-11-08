<?php
// Single entry point for all pages, CLI scripts and tests.
if (is_file(__DIR__ . '/../vendor/autoload.php')) {
    require_once __DIR__ . '/../vendor/autoload.php'; // runtime libraries (MMDB reader, PHPMailer)
}
require_once __DIR__ . '/durations.php'; // before config.php: duration settings are parsed while loading
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/client_ip.php';
require_once __DIR__ . '/router/RouterClient.php';
require_once __DIR__ . '/router/RestRouterClient.php';
require_once __DIR__ . '/migrations.php';
require_once __DIR__ . '/roles.php';
require_once __DIR__ . '/functions.php';
require_once __DIR__ . '/access.php';
require_once __DIR__ . '/default_networks.php';
require_once __DIR__ . '/palette.php';
require_once __DIR__ . '/themes.php';
require_once __DIR__ . '/html.php';
require_once __DIR__ . '/config_checks.php';
require_once __DIR__ . '/monitor/state.php';
require_once __DIR__ . '/monitor/hosting_asns.php';
require_once __DIR__ . '/monitor/geoip.php';
require_once __DIR__ . '/monitor/places.php';
require_once __DIR__ . '/monitor/baseline.php';
require_once __DIR__ . '/monitor/rules.php';
require_once __DIR__ . '/monitor/alerts.php';
require_once __DIR__ . '/monitor/mailer.php';
require_once __DIR__ . '/monitor/notify.php';
require_once __DIR__ . '/monitor/ai.php';
require_once __DIR__ . '/monitor/cycle.php';

function view_path(string $name): string
{
    return __DIR__ . '/views/' . $name . '.php';
}
