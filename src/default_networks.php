<?php
// Default networks: the per-user list granted at once by "Grant default access".
//
// Rules:
//  - Admins manage the default networks of every user. Superusers and admins manage their own
//    (permission edit_own_default_networks). Regular users only see theirs.
//  - A network can only be added when the user's access level is sufficient – for every role.
//  - Defaults that became ineligible later (the user's level was lowered) stay stored, are shown as
//    invalid and skipped when granting. Removing them is always allowed.

function can_edit_default_networks_of(?array $actor, array $target): bool
{
    if ($actor === null) {
        return false;
    }
    if (can($actor, 'manage_users')) {
        return true;
    }
    return (int)$actor['id'] === (int)$target['id'] && can($actor, 'edit_own_default_networks');
}

/** Default networks above the user's level (not granted). */
function ineligible_default_networks(array $user): array
{
    return array_values(array_filter(get_default_networks_for_user((int)$user['id']), fn($n) => !user_can_access_network($user, $n)));
}

/**
 * All users with the number of default networks and how many of them are above the user's level.
 * @return list<array<string, mixed>> users rows + default_count, invalid_default_count
 */
function users_with_default_counts(): array
{
    return db()->query('SELECT u.id, u.username, u.user_ip, u.role, u.accesslevel,
            COUNT(n.id) AS default_count,
            COALESCE(SUM(CASE WHEN n.accesslevel > u.accesslevel THEN 1 ELSE 0 END), 0) AS invalid_default_count
        FROM users u
        LEFT JOIN user_to_network un ON un.user_id = u.id
        LEFT JOIN networks n ON n.id = un.network_id
        GROUP BY u.id
        ORDER BY u.username COLLATE NOCASE')->fetchAll(PDO::FETCH_ASSOC);
}

/** All user ⇄ network default assignments. @return list<array{user_id: int, network_id: int}> */
function default_network_assignments(): array
{
    $rows = db()->query('SELECT user_id, network_id FROM user_to_network')->fetchAll(PDO::FETCH_ASSOC);
    return array_map(fn($r) => ['user_id' => (int)$r['user_id'], 'network_id' => (int)$r['network_id']], $rows);
}

/** @return array<int, int> network id => number of users having it as default */
function default_network_counts(): array
{
    $counts = [];
    foreach (default_network_assignments() as $a) {
        $counts[$a['network_id']] = ($counts[$a['network_id']] ?? 0) + 1;
    }
    return $counts;
}

/**
 * Add or remove default networks of $target on behalf of $actor.
 * Unknown ids and (when adding) networks above the target's level are rejected, never stored.
 *
 * @param list<int|string> $networkIds
 * @return array{status: int, message: string, changed: list<int>, rejected: list<int>}
 */
function change_default_networks(array $actor, array $target, array $networkIds, bool $enabled): array
{
    if (!can_edit_default_networks_of($actor, $target)) {
        return ['status' => 403, 'message' => 'Forbidden', 'changed' => [], 'rejected' => []];
    }
    $byId = array_column(get_all_networks(), null, 'id');
    $current = array_flip(get_user_default_network_ids((int)$target['id']));
    $changed = [];
    $rejected = [];
    $reasons = [];
    foreach (array_values(array_unique(array_map('intval', $networkIds))) as $id) {
        $network = $byId[$id] ?? null;
        if ($network === null) {
            $rejected[] = $id;
            $reasons[] = 'Unknown network #' . $id . '.';
            continue;
        }
        if ($enabled && !user_can_access_network($target, $network)) {
            $rejected[] = $id;
            $reasons[] = sprintf('%s requires level %d (%s has level %d).', $network['name'], (int)$network['accesslevel'], $target['username'], (int)$target['accesslevel']);
            continue;
        }
        if (isset($current[$id]) !== $enabled) {
            $changed[] = $id;
        }
    }

    if ($changed) {
        $pdo = db();
        $stmt = $pdo->prepare($enabled
            ? 'INSERT OR IGNORE INTO user_to_network (user_id, network_id) VALUES (:uid, :nid)'
            : 'DELETE FROM user_to_network WHERE user_id = :uid AND network_id = :nid');
        $pdo->beginTransaction();
        foreach ($changed as $id) {
            $stmt->execute([':uid' => (int)$target['id'], ':nid' => $id]);
        }
        $pdo->commit();
        $names = array_map(fn($id) => $byId[$id]['name'] . ' (' . $byId[$id]['address'] . ')', $changed);
        $by = (int)$actor['id'] === (int)$target['id'] ? '' : ' by ' . $actor['username'];
        log_event($enabled ? 'default_network_added' : 'default_network_removed', implode(', ', $names) . $by, (int)$target['id'], $target['username'], $target['user_ip']);
    }

    if ($rejected && !$changed) {
        return ['status' => 422, 'message' => implode(' ', $reasons), 'changed' => [], 'rejected' => $rejected];
    }
    $whose = (int)$actor['id'] === (int)$target['id'] ? 'your default networks' : 'the default networks of ' . $target['username'];
    $list = count($changed) === 1 ? $byId[$changed[0]]['name'] : count($changed) . ' networks';
    $message = $changed === []
        ? 'Nothing changed.'
        : $list . ($enabled ? ' added to ' : ' removed from ') . $whose . '.';
    if ($rejected) {
        $message .= ' Rejected: ' . implode(' ', $reasons);
    }
    return ['status' => 200, 'message' => $message, 'changed' => $changed, 'rejected' => $rejected];
}
