<?php
require_once __DIR__ . '/lib/functions.php';
ensure_session();
header('Content-Type: application/json');

function json_response(bool $status, string $message, array $extra = []): void
{
    echo json_encode(array_merge(['status' => $status, 'message' => $message], $extra));
    exit;
}

authenticate();
$csrfHeader = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? null;

function authenticate(): void
{
    if (!current_user()) {
        http_response_code(401);
        echo json_encode(['status' => false, 'message' => 'Not authenticated']);
        exit;
    }
}

function status_suffix(array $results): string
{
    $failedStatuses = array_values(array_unique(array_filter(array_map(function ($item) {
        return $item['success'] ? null : ($item['status'] ?? null);
    }, $results))));
    return $failedStatuses ? (' API codes: ' . implode(', ', $failedStatuses)) : '';
}

function handle_defaultaccess(array $user): void
{
    $nets = get_default_networks_for_user($user['id']);
    if (empty($nets)) {
        json_response(false, 'No default networks configured.');
    }
    $eligible = [];
    $skipped = [];
    foreach ($nets as $net) {
        if (user_can_access_network($user, $net)) {
            $eligible[] = $net;
        } else {
            $skipped[] = $net['name'] ?? 'network';
        }
    }
    if (empty($eligible)) {
        json_response(false, 'No default networks eligible for your access level.');
    }
    $results = apply_networks_to_user($user, $eligible, DEFAULT_TIMEOUT);
    $allOk = array_reduce($results, fn($carry, $item) => $carry && $item['success'], true);
    $message = $allOk ? 'Default access granted.' : ('Some networks could not be granted.' . status_suffix($results));
    if (!empty($skipped)) {
        $message .= ' Skipped: ' . implode(', ', $skipped) . '.';
    }
    $names = implode(', ', array_column($eligible, 'name'));
    $logMsg = 'Networks: ' . $names;
    if (!empty($skipped)) {
        $logMsg .= ' | skipped: ' . implode(', ', $skipped);
    }
    log_event('default_access_granted', $logMsg, (int)$user['id'], $user['username'] ?? null, $user['user_ip']);
    json_response($allOk, $message, ['details' => $results]);
}

function handle_apply_extended(array $user): void
{
    $input = json_decode(file_get_contents('php://input'), true) ?: [];
    $ids = $input['network_ids'] ?? [];
    if (!is_array($ids) || empty($ids)) {
        json_response(false, 'No networks selected.');
    }
    $allNetworks = get_all_networks();
    $map = [];
    foreach ($allNetworks as $n) {
        $map[$n['id']] = $n;
    }
    $selected = [];
    foreach ($ids as $id) {
        if (isset($map[$id]) && user_can_access_network($user, $map[$id])) {
            $selected[] = $map[$id];
        }
    }
    if (empty($selected)) {
        json_response(false, 'No eligible networks.');
    }
    $results = apply_networks_to_user($user, $selected, EXTENDED_TIMEOUT);
    $ok = array_reduce($results, fn($carry, $item) => $carry && $item['success'], true);
    $message = $ok ? 'Extended access applied.' : ('Some networks failed.' . status_suffix($results));
    $names = implode(', ', array_column($selected, 'name'));
    log_event('extended_access_granted', 'Networks: ' . $names, (int)$user['id'], $user['username'] ?? null, $user['user_ip']);
    json_response($ok, $message, ['details' => $results]);
}

function handle_current_access(array $user): void
{
    $entries = get_current_address_list_entries($user['user_ip']);
    json_response(true, 'Current accesses fetched.', ['entries' => $entries]);
}

function handle_revoke_self(array $user): void
{
    $result = remove_address_list_entries($user['user_ip']);
    $msg = $result['success'] ? 'Your access was revoked.' : ('Failed to revoke: ' . ($result['message'] ?? ''));
    log_event('self_revoke', 'Removed ' . ($result['deleted'] ?? 0) . ' of ' . ($result['total'] ?? 0) . ' entries for own IP', (int)$user['id'], $user['username'] ?? null, $user['user_ip']);
    json_response($result['success'], $msg, ['deleted' => $result['deleted'] ?? 0, 'total' => $result['total'] ?? 0]);
}

function handle_revoke_access(array $user): void
{
    if ((int)$user['isadmin'] !== 1) {
        http_response_code(403);
        json_response(false, 'Forbidden');
    }
    $input = json_decode(file_get_contents('php://input'), true) ?: [];
    $targetId = isset($input['user_id']) ? (int)$input['user_id'] : 0;
    if ($targetId <= 0) {
        json_response(false, 'Invalid user.');
    }
    $target = fetch_user_by_id($targetId);
    if (!$target) {
        json_response(false, 'User not found.');
    }
    $result = remove_address_list_entries($target['user_ip']);
    $msg = $result['success'] ? 'Access revoked.' : ('Failed to revoke: ' . ($result['message'] ?? ''));
    log_event('revoke_access', 'Removed ' . ($result['deleted'] ?? 0) . ' of ' . ($result['total'] ?? 0) . ' entries for ' . $target['user_ip'], (int)$target['id'], $target['username'] ?? null, $target['user_ip']);
    json_response($result['success'], $msg, ['deleted' => $result['deleted'] ?? 0, 'total' => $result['total'] ?? 0]);
}

$action = $_GET['f'] ?? '';
$user = current_user();

switch ($action) {
    case 'defaultaccess':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            json_response(false, 'Method not allowed.');
        }
        require_csrf_token($csrfHeader);
        handle_defaultaccess($user);
        break;

    case 'applyExtended':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            json_response(false, 'Method not allowed.');
        }
        require_csrf_token($csrfHeader);
        handle_apply_extended($user);
        break;

    case 'currentAccess':
        handle_current_access($user);
        break;

    case 'revokeMine':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            json_response(false, 'Method not allowed.');
        }
        require_csrf_token($csrfHeader);
        handle_revoke_self($user);
        break;

    case 'revokeAccess':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            json_response(false, 'Method not allowed.');
        }
        require_csrf_token($csrfHeader);
        handle_revoke_access($user);
        break;

    default:
        http_response_code(400);
        json_response(false, 'Unknown action.');
}
?>
