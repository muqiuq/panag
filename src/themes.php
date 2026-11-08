<?php
// Per-user themes (PLAN.md 4.9). The choice is stored in users.theme; header.php puts it on <html> as data-theme
// (styles: public/css/themes.css) plus Bootstrap's data-bs-theme, server-side, so nothing flickers. The cookie
// panag_theme mirrors it for the login page, where no user is known yet – it is not sensitive.

const THEMES = [
    'default' => ['label' => 'Default', 'description' => 'PANAG red on light grey', 'dark' => false],
    'dark' => ['label' => 'Dark mode', 'description' => 'Dark surfaces, easy on the eyes at night', 'dark' => true],
    'high-contrast' => ['label' => 'High contrast', 'description' => 'Black on white, strong borders and focus outlines (WCAG AAA)', 'dark' => false],
    'high-contrast-dark' => ['label' => 'High contrast dark', 'description' => 'White and yellow on black (WCAG AAA)', 'dark' => true],
    'slay' => ['label' => 'Slay', 'description' => 'Violet glam with a pride stripe ✨', 'dark' => false],
];

const THEME_COOKIE = 'panag_theme';

function theme_or_default(mixed $theme): string
{
    return is_string($theme) && isset(THEMES[$theme]) ? $theme : 'default';
}

/** Theme for the page: the user's choice, else the cookie (login page), else the default. */
function current_theme(?array $user): string
{
    if ($user !== null) {
        return theme_or_default($user['theme'] ?? null);
    }
    return theme_or_default($_COOKIE[THEME_COOKIE] ?? null);
}

function theme_is_dark(string $theme): bool
{
    return THEMES[theme_or_default($theme)]['dark'];
}

/** data-theme and data-bs-theme for <html> (or a preview element). */
function theme_attributes(string $theme): string
{
    $theme = theme_or_default($theme);
    return 'data-theme="' . e($theme) . '" data-bs-theme="' . (theme_is_dark($theme) ? 'dark' : 'light') . '"';
}

/** Store the theme of $user. @return bool false for an unknown theme */
function set_user_theme(array $user, string $theme): bool
{
    if (!isset(THEMES[$theme])) {
        return false;
    }
    db()->prepare('UPDATE users SET theme = :t WHERE id = :id')->execute([':t' => $theme, ':id' => (int)$user['id']]);
    if (!headers_sent() && impersonator() === null) { // an admin acting as this user keeps their own cookie
        remember_theme_cookie($theme);
    }
    return true;
}

/** Mirror the theme into the cookie, so the login page shows it after logout. No-op once output has started. */
function remember_theme_cookie(string $theme): void
{
    if (headers_sent() || ($_COOKIE[THEME_COOKIE] ?? null) === $theme) {
        return;
    }
    setcookie(THEME_COOKIE, $theme, [
        'expires' => time() + 365 * 86400,
        'path' => base_path() . '/',
        'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    $_COOKIE[THEME_COOKIE] = $theme;
}
