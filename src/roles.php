<?php
// Roles and permissions. All authorisation checks go through can().
//
//   user       – grants own default/extended access, own preferences
//   superuser  – additionally chooses its own default networks (only networks <= own access level)
//   admin      – everything: users, networks, logs, status, config, impersonation, revoking others

const ROLES = ['user', 'superuser', 'admin'];

const ROLE_PERMISSIONS = [
    'grant_access' => ['user', 'superuser', 'admin'],
    'revoke_own_access' => ['user', 'superuser', 'admin'],
    'edit_own_preferences' => ['user', 'superuser', 'admin'],
    'edit_own_default_networks' => ['superuser', 'admin'],
    'admin' => ['admin'],
    'manage_users' => ['admin'],
    'manage_networks' => ['admin'],
    'revoke_others' => ['admin'],
    'impersonate' => ['admin'],
    'view_logs' => ['admin'],
    'view_status' => ['admin'],
    'view_config' => ['admin'],
];

function is_valid_role(string $role): bool
{
    return in_array($role, ROLES, true);
}

function user_role(?array $user): ?string
{
    $role = $user['role'] ?? null;
    return is_string($role) && is_valid_role($role) ? $role : null;
}

function can(?array $user, string $permission): bool
{
    $role = user_role($user);
    if ($role === null) {
        return false;
    }
    if (!isset(ROLE_PERMISSIONS[$permission])) {
        throw new InvalidArgumentException('Unknown permission: ' . $permission);
    }
    return in_array($role, ROLE_PERMISSIONS[$permission], true);
}

function is_admin(?array $user): bool
{
    return can($user, 'admin');
}

function role_label(string $role): string
{
    return ['user' => 'User', 'superuser' => 'Superuser', 'admin' => 'Admin'][$role] ?? $role;
}

function admin_count(): int
{
    return (int)db()->query("SELECT COUNT(*) FROM users WHERE role = 'admin'")->fetchColumn();
}

/**
 * Would changing/deleting $target leave PANAG without any admin? Without an admin the setup page
 * re-opens for every whitelisted client, so the last admin must never be removed or demoted.
 */
function would_remove_last_admin(array $target, ?string $newRole): bool
{
    return user_role($target) === 'admin' && $newRole !== 'admin' && admin_count() <= 1;
}
