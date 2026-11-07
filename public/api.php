<?php
// JSON API used by the dashboard. All state-changing calls require POST + X-CSRF-Token.
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

function require_post_with_csrf(): void
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        json_response(false, 'Method not allowed.', [], 405);
    }
    require_csrf_token($_SERVER['HTTP_X_CSRF_TOKEN'] ?? null);
}

function access_payload(array $user): array
{
    return ['entries' => current_access_view($user)];
}

function handle_default_access(array $user): void
{
    $nets = get_default_networks_for_user((int)$user['id']);
    if (empty($nets)) {
        json_response(false, 'No default networks configured.');
    }
    $eligible = array_values(array_filter($nets, fn($n) => user_can_access_network($user, $n)));
    $skipped = array_column(array_filter($nets, fn($n) => !user_can_access_network($user, $n)), 'name');
    if (empty($eligible)) {
        json_response(false, 'No default networks eligible for your access level.');
    }
    $duration = user_grant_duration($user, 'default');
    $results = grant_networks($user, $eligible, 'default');
    $summary = grant_summary($results, 'Default access granted until ' . date('H:i', time() + $duration) . '.', 'Some networks could not be granted.');
    $message = $summary['message'] . ($skipped ? ' Skipped: ' . implode(', ', $skipped) . '.' : '');
    $log = 'Networks: ' . implode(', ', array_column($eligible, 'name')) . ' | ' . format_duration_human($duration) . ($skipped ? ' | skipped: ' . implode(', ', $skipped) : '');
    log_event('default_access_granted', $log, (int)$user['id'], $user['username'] ?? null, $user['user_ip']);
    json_response($summary['ok'], $message, ['details' => $results] + access_payload($user));
}

function handle_apply_extended(array $user): void
{
    $ids = json_input()['network_ids'] ?? [];
    if (!is_array($ids) || empty($ids)) {
        json_response(false, 'No networks selected.');
    }
    $map = array_column(get_all_networks(), null, 'id');
    $selected = [];
    foreach ($ids as $id) {
        if (isset($map[(int)$id]) && user_can_access_network($user, $map[(int)$id])) {
            $selected[] = $map[(int)$id];
        }
    }
    if (empty($selected)) {
        json_response(false, 'No eligible networks.');
    }
    grant_extended_and_respond($user, $selected, 'Extended access applied');
}

function handle_grant_network(array $user): void
{
    $id = (int)(json_input()['network_id'] ?? 0);
    $network = array_column(get_all_networks(), null, 'id')[$id] ?? null;
    if (!$network || !user_can_access_network($user, $network)) {
        json_response(false, 'Network not available.', [], 404);
    }
    grant_extended_and_respond($user, [$network], $network['name'] . ' granted');
}

function grant_extended_and_respond(array $user, array $networks, string $okPrefix): void
{
    $duration = user_grant_duration($user, 'extended');
    $results = grant_networks($user, $networks, 'extended');
    $summary = grant_summary($results, $okPrefix . ' until ' . date('H:i', time() + $duration) . '.', 'Some networks failed.');
    log_event('extended_access_granted', 'Networks: ' . implode(', ', array_column($networks, 'name')) . ' | ' . format_duration_human($duration), (int)$user['id'], $user['username'] ?? null, $user['user_ip']);
    json_response($summary['ok'], $summary['message'], ['details' => $results] + access_payload($user));
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
    $msg = $result['success'] ? 'Access revoked.' : ('Failed to revoke: ' . ($result['message'] ?? ''));
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

switch ($_GET['f'] ?? '') {
    case 'currentAccess':
        json_response(true, 'Current accesses fetched.', access_payload($user));
        // no break
    case 'defaultaccess':
        require_post_with_csrf();
        handle_default_access($user);
        // no break
    case 'applyExtended':
        require_post_with_csrf();
        handle_apply_extended($user);
        // no break
    case 'grantNetwork':
        require_post_with_csrf();
        handle_grant_network($user);
        // no break
    case 'extendEntry':
        require_post_with_csrf();
        handle_entry_action($user, 'extend');
        // no break
    case 'revokeEntry':
        require_post_with_csrf();
        handle_entry_action($user, 'revoke');
        // no break
    case 'revokeMine':
        require_post_with_csrf();
        handle_revoke_self($user);
        // no break
    case 'revokeAccess':
        require_post_with_csrf();
        handle_revoke_access($user);
        // no break
    case 'savePrefs':
        require_post_with_csrf();
        handle_save_prefs($user);
        // no break
    default:
        json_response(false, 'Unknown action.', [], 400);
}
