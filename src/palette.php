<?php
// Data for the command palette (public/js/palette.js): networks, active entries, commands.
// Loaded once per page via api.php?f=palette; filtering and ranking happen in the browser.
// Paths are relative to the web root – the client prefixes its base path.

/** Commands offered to $user, depending on the role. */
function palette_commands(array $user): array
{
    $commands = [];
    $eligibleDefaults = array_filter(get_default_networks_for_user((int)$user['id']), fn($n) => user_can_access_network($user, $n));
    if ($eligibleDefaults) {
        $commands[] = ['id' => 'grant-default', 'label' => 'Grant default access', 'keywords' => 'default all',
            'hint' => count($eligibleDefaults) . ' default network(s) for ' . format_duration_human(user_grant_duration($user, 'default')), 'api' => 'defaultaccess'];
    }
    $commands[] = ['id' => 'revoke-mine', 'label' => 'Revoke all my access', 'keywords' => 'remove delete clear', 'hint' => 'Removes all of your active entries', 'api' => 'revokeMine'];
    $commands[] = ['id' => 'durations', 'label' => 'Set durations', 'keywords' => 'time timeout profile settings', 'hint' => 'Profile', 'path' => 'profile.php#durations'];
    $commands[] = ['id' => 'my-defaults', 'label' => 'My default networks', 'keywords' => 'profile settings', 'hint' => 'Profile', 'path' => 'profile.php#networks'];

    $pages = [
        ['manage_users', 'Users', 'admin/users.php', 'accounts people'],
        ['manage_users', 'Matrix', 'admin/matrix.php', 'default networks assignment'],
        ['manage_networks', 'Networks', 'admin/networks.php', 'subnets'],
        ['view_logs', 'Logs', 'admin/logs.php', 'audit'],
        ['view_status', 'Status', 'admin/status.php', 'router wireguard'],
        ['view_config', 'Config', 'admin/config.php', 'environment settings'],
    ];
    foreach ($pages as [$permission, $name, $path, $keywords]) {
        if (can($user, $permission)) {
            $commands[] = ['id' => 'go-' . strtolower($name), 'label' => 'Go to ' . $name, 'keywords' => $keywords . ' admin', 'hint' => 'Admin', 'path' => $path];
        }
    }
    return $commands;
}

/** $entries: the user's raw address-list entries if already fetched (saves a router call on the dashboard). */
function palette_data(array $user, ?array $entries = null): array
{
    $entries = $entries ?? get_current_address_list_entries((string)$user['user_ip']);
    $defaultIds = array_flip(get_user_default_network_ids((int)$user['id']));

    $networks = array_map(fn($n) => [
        'id' => (int)$n['id'],
        'name' => (string)$n['name'],
        'address' => (string)$n['address'],
        'level' => (int)$n['accesslevel'],
        'is_default' => isset($defaultIds[(int)$n['id']]),
    ], eligible_networks_for_user($user));

    $users = [];
    if (can($user, 'manage_users')) {
        foreach (db()->query('SELECT id, username, user_ip, role FROM users ORDER BY username')->fetchAll(PDO::FETCH_ASSOC) as $u) {
            $users[] = ['id' => (int)$u['id'], 'name' => (string)$u['username'], 'ip' => (string)$u['user_ip'], 'role' => (string)$u['role'], 'path' => 'admin/user.php?id=' . (int)$u['id']];
        }
    }

    return [
        'networks' => $networks,
        'entries' => current_access_view($user, $entries),
        'commands' => palette_commands($user),
        'users' => $users,
        'durations' => [
            'extended' => user_grant_duration($user, 'extended'),
            'min' => MIN_GRANT_DURATION,
            'max_extended' => max_grant_duration('extended'),
        ],
    ];
}
