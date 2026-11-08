<?php
use PHPUnit\Framework\TestCase;

final class ThemesTest extends TestCase
{
    protected function setUp(): void
    {
        db()->exec('DELETE FROM users');
        unset($_COOKIE[THEME_COOKIE]);
    }

    protected function tearDown(): void
    {
        unset($_COOKIE[THEME_COOKIE]);
    }

    private function user(): array
    {
        save_user(null, 'Theme User', '10.0.0.7', 'JBSWY3DPEHPK3PXP', 'user', 5);
        return fetch_user_by_user_ip('10.0.0.7');
    }

    public function testTheRequestedThemesExist(): void
    {
        $this->assertSame(['default', 'dark', 'high-contrast', 'high-contrast-dark', 'slay', 'switzerland', 'terminal', 'brasil', 'atomic-age', 'wtf'], array_keys(THEMES));
        $this->assertTrue(theme_is_dark('dark'));
        $this->assertTrue(theme_is_dark('high-contrast-dark'));
        $this->assertTrue(theme_is_dark('terminal'));
        $this->assertFalse(theme_is_dark('slay'));
        $this->assertFalse(theme_is_dark('wtf'));
    }

    public function testEveryThemeHasStyles(): void
    {
        $css = (string)file_get_contents(__DIR__ . '/../../public/css/themes.css');
        foreach (array_keys(THEMES) as $theme) {
            if ($theme !== 'default') {
                $this->assertStringContainsString('[data-theme="' . $theme . '"] {', $css, $theme);
            }
        }
    }

    public function testUnknownValuesFallBackToDefault(): void
    {
        $this->assertSame('default', theme_or_default('rainbow'));
        $this->assertSame('default', theme_or_default(null));
        $this->assertSame('default', theme_or_default(['dark']));
        $this->assertSame('slay', theme_or_default('slay'));
    }

    public function testUserChoiceIsStoredAndWinsOverTheCookie(): void
    {
        $user = $this->user();
        $this->assertSame('default', current_theme($user));
        $this->assertTrue(set_user_theme($user, 'high-contrast-dark'));
        $user = fetch_user_by_id((int)$user['id']);
        $this->assertSame('high-contrast-dark', $user['theme']);

        $_COOKIE[THEME_COOKIE] = 'slay';
        $this->assertSame('high-contrast-dark', current_theme($user));
        $this->assertSame('slay', current_theme(null), 'login page: cookie');
        $_COOKIE[THEME_COOKIE] = '"><script>';
        $this->assertSame('default', current_theme(null), 'cookie is only a hint – unknown values are ignored');
    }

    public function testUnknownThemeIsRejected(): void
    {
        $user = $this->user();
        $this->assertFalse(set_user_theme($user, 'rainbow'));
        $this->assertSame('default', fetch_user_by_id((int)$user['id'])['theme']);
    }

    public function testHtmlAttributes(): void
    {
        $this->assertSame('data-theme="dark" data-bs-theme="dark"', theme_attributes('dark'));
        $this->assertSame('data-theme="slay" data-bs-theme="light"', theme_attributes('slay'));
        $this->assertSame('data-theme="default" data-bs-theme="light"', theme_attributes('<x>'));
    }

    public function testPaletteOffersEveryTheme(): void
    {
        $commands = array_column(palette_commands($this->user()), null, 'id');
        foreach (THEMES as $key => $theme) {
            $this->assertSame('Theme: ' . $theme['label'], $commands['theme-' . $key]['label']);
            $this->assertSame(['theme' => $key], $commands['theme-' . $key]['body']);
            $this->assertSame('setTheme', $commands['theme-' . $key]['api']);
        }
    }
}
