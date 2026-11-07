<?php
// Granting, extending and revoking access (RouterOS address-list entries "<ADDRESS_LIST_PREFIX><user_ip>").
//
// Rules:
//  - "Grant default access" uses the user's default duration for all default networks.
//  - Granting a single network (also a default one) uses the user's extended duration.
//  - Granting an already active network extends it, but never shortens it:
//    new timeout = max(remaining, duration).

function grant_comment(string $kind, string $networkName): string
{
    return 'PANAG ' . ($kind === 'default' ? 'default' : 'ext') . ': ' . $networkName;
}

function grant_kind_from_comment(?string $comment): ?string
{
    if ($comment === null) {
        return null;
    }
    if (strncmp($comment, 'PANAG default:', 14) === 0) {
        return 'default';
    }
    if (strncmp($comment, 'PANAG ext:', 10) === 0) {
        return 'extended';
    }
    return null;
}

/** The user's duration for a grant kind, clamped to the current limits. */
function user_grant_duration(array $user, string $kind): int
{
    $stored = (int)($kind === 'default' ? ($user['default_duration_sec'] ?? 3600) : ($user['extended_duration_sec'] ?? 900));
    return clamp_grant_duration($kind, $stored);
}

/**
 * Validate and store the user's own durations.
 * @return list<string> validation errors (empty = saved)
 */
function update_user_durations(array $user, ?int $defaultSec, ?int $extendedSec): array
{
    $errors = array_values(array_filter([
        validate_grant_duration('default', $defaultSec),
        validate_grant_duration('extended', $extendedSec),
    ]));
    if ($errors) {
        return $errors;
    }
    $stmt = db()->prepare('UPDATE users SET default_duration_sec = :d, extended_duration_sec = :e WHERE id = :id');
    $stmt->execute([':d' => $defaultSec, ':e' => $extendedSec, ':id' => (int)$user['id']]);
    log_event('durations_updated', 'Default ' . format_duration_human((int)$defaultSec) . ', extended ' . format_duration_human((int)$extendedSec), (int)$user['id'], $user['username'] ?? null, $user['user_ip'] ?? null);
    return [];
}

/** RouterOS shows single hosts without "/32". */
function normalize_address(string $address): string
{
    $address = trim($address);
    return substr($address, -3) === '/32' ? substr($address, 0, -3) : $address;
}

/** Remaining seconds of an address-list entry; null = permanent (no timeout). */
function entry_remaining_seconds(array $entry): ?int
{
    $timeout = (string)($entry['timeout'] ?? '');
    return $timeout === '' ? null : parse_routeros_duration($timeout);
}

/**
 * Grant (or extend) access to networks for a user.
 * @return list<array{network: string, address: string, success: bool, status: ?int, action: string, message: string}>
 */
function grant_networks(array $user, array $networks, string $kind): array
{
    $duration = user_grant_duration($user, $kind);
    $listName = address_list_name((string)$user['user_ip']);
    $current = router()->listAddressList($listName);
    if (!$current['success']) {
        return array_map(fn($n) => [
            'network' => (string)$n['name'], 'address' => (string)$n['address'], 'success' => false,
            'status' => $current['status'], 'action' => 'failed', 'message' => (string)($current['error'] ?? 'API error'),
        ], $networks);
    }
    $byAddress = [];
    foreach ($current['data'] as $entry) {
        $byAddress[normalize_address((string)($entry['address'] ?? ''))] = $entry;
    }

    $results = [];
    foreach ($networks as $network) {
        $result = ['network' => (string)$network['name'], 'address' => (string)$network['address'], 'success' => false, 'status' => null];
        if (!user_can_access_network($user, $network)) {
            $results[] = $result + ['action' => 'skipped', 'message' => 'Insufficient access level'];
            continue;
        }
        $existing = $byAddress[normalize_address((string)$network['address'])] ?? null;
        if ($existing === null) {
            $resp = router()->addAddressListEntry($listName, (string)$network['address'], grant_comment($kind, (string)$network['name']), format_routeros_timeout($duration));
            if (!$resp['success'] && $resp['status'] === 400 && stripos((string)$resp['error'], 'already have') !== false) {
                $results[] = ['success' => true, 'status' => 400, 'action' => 'unchanged', 'message' => 'Already present'] + $result;
                continue;
            }
            $results[] = ['success' => $resp['success'], 'status' => $resp['status'], 'action' => $resp['success'] ? 'added' : 'failed',
                'message' => $resp['success'] ? 'Granted for ' . format_duration_human($duration) : (string)($resp['error'] ?? 'Failed')] + $result;
            continue;
        }
        $remaining = entry_remaining_seconds($existing);
        if ($remaining === null) {
            $results[] = ['success' => true, 'action' => 'unchanged', 'message' => 'Permanent entry'] + $result;
            continue;
        }
        if ($remaining >= $duration) {
            $results[] = ['success' => true, 'action' => 'unchanged', 'message' => 'Already active, ' . format_duration_human($remaining) . ' left'] + $result;
            continue;
        }
        $resp = router()->updateAddressListEntry((string)$existing['.id'], ['timeout' => format_routeros_timeout($duration)]);
        $results[] = ['success' => $resp['success'], 'status' => $resp['status'], 'action' => $resp['success'] ? 'extended' : 'failed',
            'message' => $resp['success'] ? 'Extended to ' . format_duration_human($duration) : (string)($resp['error'] ?? 'Failed')] + $result;
    }
    return $results;
}

/** Find one of the user's own entries by RouterOS id. */
function find_own_entry(array $user, string $id): ?array
{
    $resp = router()->listAddressList(address_list_name((string)$user['user_ip']));
    if (!$resp['success']) {
        return null;
    }
    foreach ($resp['data'] as $entry) {
        if (($entry['.id'] ?? null) === $id) {
            return $entry;
        }
    }
    return null;
}

/** @return array{success: bool, message: string} */
function revoke_own_entry(array $user, string $id): array
{
    $entry = find_own_entry($user, $id);
    if ($entry === null) {
        return ['success' => false, 'message' => 'Entry not found.'];
    }
    $resp = router()->removeAddressListEntry($id);
    if ($resp['success']) {
        log_event('access_revoked', 'Revoked ' . ($entry['address'] ?? '?') . ' (' . ($entry['comment'] ?? '') . ')', (int)$user['id'], $user['username'] ?? null, $user['user_ip'] ?? null);
    }
    return ['success' => $resp['success'], 'message' => $resp['success'] ? 'Access to ' . ($entry['address'] ?? '') . ' revoked.' : 'Failed to revoke: ' . ($resp['error'] ?? '')];
}

/** Extend one entry by the duration of its kind (never shortens). @return array{success: bool, message: string} */
function extend_own_entry(array $user, string $id): array
{
    $entry = find_own_entry($user, $id);
    if ($entry === null) {
        return ['success' => false, 'message' => 'Entry not found.'];
    }
    $kind = grant_kind_from_comment($entry['comment'] ?? null) ?? 'extended';
    $duration = user_grant_duration($user, $kind);
    $remaining = entry_remaining_seconds($entry);
    if ($remaining === null || $remaining >= $duration) {
        return ['success' => true, 'message' => 'Nothing to extend – ' . ($remaining === null ? 'the entry is permanent.' : format_duration_human($remaining) . ' left.')];
    }
    $resp = router()->updateAddressListEntry($id, ['timeout' => format_routeros_timeout($duration)]);
    if ($resp['success']) {
        log_event('access_extended', 'Extended ' . ($entry['address'] ?? '?') . ' to ' . format_duration_human($duration), (int)$user['id'], $user['username'] ?? null, $user['user_ip'] ?? null);
    }
    return ['success' => $resp['success'], 'message' => $resp['success']
        ? 'Extended until ' . date('H:i', time() + $duration) . '.'
        : 'Failed to extend: ' . ($resp['error'] ?? '')];
}

/**
 * The user's active entries prepared for display/JSON.
 * @return list<array{id: string, address: string, network: string, kind: ?string, remaining_sec: ?int, expires_at: ?int, remaining: string, until: string}>
 */
function current_access_view(array $user, ?array $entries = null): array
{
    $entries = $entries ?? get_current_address_list_entries((string)$user['user_ip']);
    $names = [];
    foreach (get_all_networks() as $n) {
        $names[normalize_address((string)$n['address'])] = (string)$n['name'];
    }
    $now = time();
    $view = [];
    foreach ($entries as $e) {
        $address = (string)($e['address'] ?? '');
        $remaining = entry_remaining_seconds($e);
        $comment = (string)($e['comment'] ?? '');
        $view[] = [
            'id' => (string)($e['.id'] ?? ''),
            'address' => $address,
            'network' => $names[normalize_address($address)] ?? preg_replace('/^PANAG (default|ext): /', '', $comment),
            'kind' => grant_kind_from_comment($comment),
            'remaining_sec' => $remaining,
            'expires_at' => $remaining === null ? null : $now + $remaining,
            'remaining' => $remaining === null ? 'permanent' : format_duration_human($remaining) . ' left',
            'until' => $remaining === null ? '' : date('H:i', $now + $remaining),
        ];
    }
    usort($view, fn($a, $b) => ($a['remaining_sec'] ?? PHP_INT_MAX) <=> ($b['remaining_sec'] ?? PHP_INT_MAX));
    return $view;
}

/** Summary sentence for grant results ("... until 17:45."). */
function grant_summary(array $results, string $okMessage, string $failMessage): array
{
    $allOk = array_reduce($results, fn($carry, $r) => $carry && $r['success'], true);
    if ($allOk) {
        return ['ok' => true, 'message' => $okMessage];
    }
    $codes = array_values(array_unique(array_filter(array_map(fn($r) => $r['success'] ? null : ($r['status'] ?? null), $results))));
    return ['ok' => false, 'message' => $failMessage . ($codes ? ' API codes: ' . implode(', ', $codes) : '')];
}
