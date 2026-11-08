<?php
// JSON API used by the pages' JavaScript. All state-changing calls require POST + X-CSRF-Token.
require_once __DIR__ . '/../src/bootstrap.php';
ensure_session();
header('Content-Type: application/json');
header('Cache-Control: no-store');

function json_response(bool $status, string $message, array $extra = [], ?int $httpCode = null): void
{
    if ($httpCode !== null) {
        http_response_code($httpCode);
    }
    echo json_encode(array_merge(['status' => $status, 'message' => $message], $extra));
    exit;
}

function json_input(): array
{
    $data = json_decode((string)file_get_contents('php://input'), true);
    return is_array($data) ? $data : [];
}

$user = current_user();
if (!$user) {
    json_response(false, 'Not authenticated', [], 401);
}

/** Active entries for the UI. entries = null when the router could not be read – clients keep what they show. */
function access_payload(array $user): array
{
    $entries = own_address_list_entries((string)$user['user_ip']);
    return ['entries' => $entries === null ? null : current_access_view($user, $entries)];
}

/** The user addressed by input "user_id" (defaults to the current user). Others only for admins. */
function target_user(array $user, array $input): array
{
    $id = (int)($input['user_id'] ?? $user['id']);
    if ($id !== (int)$user['id'] && !can($user, 'manage_users')) {
        json_response(false, 'Forbidden', [], 403); // before the lookup: do not reveal which ids exist
    }
    $target = $id === (int)$user['id'] ? $user : fetch_user_by_id($id);
    if (!$target) {
        json_response(false, 'User not found.', [], 404);
    }
    return $target;
}

function handle_default_access(array $user): void
{
    $nets = get_default_networks_for_user((int)$user['id']);
    if (empty($nets)) {
        json_response(false, 'No default networks configured.');
    }
    $nets = array_values(array_filter($nets, fn($n) => !network_is_sensitive($n))); // never stored, but never granted either
    $eligible = array_values(array_filter($nets, fn($n) => user_can_access_network($user, $n)));
    $skipped = array_column(array_filter($nets, fn($n) => !user_can_access_network($user, $n)), 'name');
    if (empty($eligible)) {
        json_response(false, 'No default networks eligible for your access level.');
    }
    $duration = user_grant_duration($user, 'default');
    $results = grant_networks($user, $eligible, 'default');
    $summary = grant_summary($results, 'Default access granted until ' . date('H:i', time() + $duration) . '.', 'Some networks could not be granted.');
    $message = $summary['message'] . ($skipped ? ' Skipped (above your level): ' . implode(', ', $skipped) . '.' : '');
    $log = 'Networks: ' . implode(', ', array_column($eligible, 'name')) . ' | ' . format_duration_human($duration) . ($skipped ? ' | skipped: ' . implode(', ', $skipped) : '');
    log_event('default_access_granted', $log, (int)$user['id'], $user['username'] ?? null, $user['user_ip'], ['networks' => array_map('intval', array_column($eligible, 'id'))]);
    json_response($summary['ok'], $message, ['details' => $results] + access_payload($user));
}

/** Grant one network with the extended duration – or a duration given by the user (palette: "vpn 2h"). */
function handle_grant_network(array $user): void
{
    $input = json_input();
    $network = fetch_network_by_id((int)($input['network_id'] ?? 0));
    if (!$network || !user_can_access_network($user, $network)) {
        json_response(false, 'Network not available.', [], 404);
    }
    $duration = null;
    if (isset($input['duration']) && trim((string)$input['duration']) !== '') {
        $duration = parse_duration_input((string)$input['duration']);
        $error = validate_grant_duration('extended', $duration);
        if ($error !== null) {
            json_response(false, $error, ['errors' => [$error]], 422);
        }
    }
    $results = grant_networks($user, [$network], 'extended', $duration);
    $effective = $duration ?? user_grant_duration($user, 'extended');
    log_event('extended_access_granted', 'Networks: ' . $network['name'] . ' | ' . format_duration_human($effective) . ' | ' . $results[0]['action'], (int)$user['id'], $user['username'] ?? null, $user['user_ip'], ['networks' => [(int)$network['id']]]);
    json_response($results[0]['success'], single_grant_message($results[0]), ['details' => $results] + access_payload($user));
}

function handle_entry_action(array $user, string $action): void
{
    $id = (string)(json_input()['id'] ?? '');
    if ($id === '') {
        json_response(false, 'Missing entry id.', [], 400);
    }
    $result = $action === 'revoke' ? revoke_own_entry($user, $id) : extend_own_entry($user, $id);
    json_response($result['success'], $result['message'], access_payload($user));
}

function handle_revoke_self(array $user): void
{
    $result = remove_address_list_entries($user['user_ip']);
    $msg = $result['success'] ? 'Your access was revoked.' : ('Failed to revoke: ' . ($result['message'] ?? ''));
    log_event('self_revoke', 'Removed ' . ($result['deleted'] ?? 0) . ' of ' . ($result['total'] ?? 0) . ' entries for own IP', (int)$user['id'], $user['username'] ?? null, $user['user_ip']);
    json_response($result['success'], $msg, ['deleted' => $result['deleted'] ?? 0, 'total' => $result['total'] ?? 0] + access_payload($user));
}

function handle_revoke_access(array $user): void
{
    if (!can($user, 'revoke_others')) {
        json_response(false, 'Forbidden', [], 403);
    }
    $targetId = (int)(json_input()['user_id'] ?? 0);
    $target = $targetId > 0 ? fetch_user_by_id($targetId) : null;
    if (!$target) {
        json_response(false, 'User not found.');
    }
    $result = remove_address_list_entries($target['user_ip']);
    $msg = $result['success'] ? 'Access of ' . $target['username'] . ' revoked.' : ('Failed to revoke: ' . ($result['message'] ?? ''));
    log_event('revoke_access', 'Removed ' . ($result['deleted'] ?? 0) . ' of ' . ($result['total'] ?? 0) . ' entries for ' . $target['user_ip'], (int)$target['id'], $target['username'] ?? null, $target['user_ip']);
    json_response($result['success'], $msg, ['deleted' => $result['deleted'] ?? 0, 'total' => $result['total'] ?? 0]);
}

function handle_save_prefs(array $user): void
{
    $input = json_input();
    $errors = update_user_durations(
        $user,
        parse_duration_input((string)($input['default_duration'] ?? '')),
        parse_duration_input((string)($input['extended_duration'] ?? ''))
    );
    if ($errors) {
        json_response(false, implode(' ', $errors), ['errors' => $errors], 422);
    }
    json_response(true, 'Durations saved.');
}

/** {user_id?, network_ids: [..], enabled: bool} – own defaults (superuser/admin) or any user's (admin). */
function handle_set_default_networks(array $user): void
{
    $input = json_input();
    $target = target_user($user, $input);
    $ids = is_array($input['network_ids'] ?? null) ? $input['network_ids'] : [];
    if (!$ids) {
        json_response(false, 'No networks given.', [], 400);
    }
    $result = change_default_networks($user, $target, $ids, !empty($input['enabled']));
    $extra = ['changed' => $result['changed'], 'rejected' => $result['rejected']];
    if ($result['status'] !== 403) {
        $extra['default_ids'] = get_user_default_network_ids((int)$target['id']);
    }
    json_response($result['status'] === 200, $result['message'], $extra, $result['status']);
}

function handle_reveal_otp(array $user): void
{
    if (!can($user, 'manage_users')) {
        json_response(false, 'Forbidden', [], 403);
    }
    $target = target_user($user, json_input());
    log_event('otp_revealed', 'OTP secret of ' . $target['username'] . ' (' . $target['user_ip'] . ') revealed by ' . $user['username'], (int)$target['id'], $target['username'], $target['user_ip']);
    json_response(true, 'OTP secret revealed.', ['secret' => $target['otp_secret'], 'uri' => otp_provisioning_uri($target)]);
}

/** {theme} – the own theme (palette "Theme: …"); the page switches without a reload. */
function handle_set_theme(array $user): void
{
    $theme = (string)(json_input()['theme'] ?? '');
    if (!set_user_theme($user, $theme)) {
        json_response(false, 'Unknown theme.', [], 422);
    }
    json_response(true, 'Theme: ' . THEMES[$theme]['label'] . '.', ['theme' => $theme, 'dark' => theme_is_dark($theme)]);
}

// action => [HTTP method, handler]
$routes = [
    'palette' => ['GET', fn() => json_response(true, 'Palette data.', palette_data($user))],
    'currentAccess' => ['GET', function () use ($user) {
        $payload = access_payload($user);
        json_response($payload['entries'] !== null, $payload['entries'] !== null ? 'Current accesses fetched.' : 'Router not reachable.', $payload);
    }],
    'defaultaccess' => ['POST', fn() => handle_default_access($user)],
    'grantNetwork' => ['POST', fn() => handle_grant_network($user)],
    'extendEntry' => ['POST', fn() => handle_entry_action($user, 'extend')],
    'revokeEntry' => ['POST', fn() => handle_entry_action($user, 'revoke')],
    'revokeMine' => ['POST', fn() => handle_revoke_self($user)],
    'revokeAccess' => ['POST', fn() => handle_revoke_access($user)],
    'savePrefs' => ['POST', fn() => handle_save_prefs($user)],
    'setDefaultNetworks' => ['POST', fn() => handle_set_default_networks($user)],
    'revealOtp' => ['POST', fn() => handle_reveal_otp($user)],
    'setTheme' => ['POST', fn() => handle_set_theme($user)],
];

$route = $routes[(string)($_GET['f'] ?? '')] ?? null;
if ($route === null) {
    json_response(false, 'Unknown action.', [], 400);
}
[$method, $handler] = $route;
if ($_SERVER['REQUEST_METHOD'] !== $method) {
    json_response(false, 'Method not allowed.', [], 405);
}
if ($method === 'POST') {
    require_csrf_token($_SERVER['HTTP_X_CSRF_TOKEN'] ?? null);
}
$handler();
