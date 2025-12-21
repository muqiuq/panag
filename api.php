<?php
require_once __DIR__ . '/functions.php';
ensure_session();
header('Content-Type: application/json');

function json_response(bool $status, string $message, array $extra = []): void
{
    echo json_encode(array_merge(['status' => $status, 'message' => $message], $extra));
    exit;
}

authenticate();

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
    $results = apply_networks_to_user($user, $nets);
    $allOk = array_reduce($results, fn($carry, $item) => $carry && $item['success'], true);
    $message = $allOk ? 'Default access granted.' : ('Some networks could not be granted.' . status_suffix($results));
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
    $results = apply_networks_to_user($user, $selected);
    $ok = array_reduce($results, fn($carry, $item) => $carry && $item['success'], true);
    $message = $ok ? 'Extended access applied.' : ('Some networks failed.' . status_suffix($results));
    json_response($ok, $message, ['details' => $results]);
}

function handle_current_access(array $user): void
{
    $entries = get_current_address_list_entries($user['username']);
    json_response(true, 'Current accesses fetched.', ['entries' => $entries]);
}

$action = $_GET['f'] ?? '';
$user = current_user();

switch ($action) {
    case 'defaultaccess':
        handle_defaultaccess($user);
        break;

    case 'applyExtended':
        handle_apply_extended($user);
        break;

    case 'currentAccess':
        handle_current_access($user);
        break;

    default:
        http_response_code(400);
        json_response(false, 'Unknown action.');
}
?>
