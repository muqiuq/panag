<?php
use PHPUnit\Framework\TestCase;

/** Status messages: one line, at most 100 characters, valid until the next 03:00 local time. */
final class StatusMessageTest extends TestCase
{
    private string $tz;

    protected function setUp(): void
    {
        $this->tz = date_default_timezone_get();
        date_default_timezone_set('Europe/Zurich');
        db()->exec('DELETE FROM users');
    }

    protected function tearDown(): void
    {
        date_default_timezone_set($this->tz);
    }

    private function user(string $ip = '10.0.0.7', string $name = 'Status User'): array
    {
        save_user(null, $name, $ip, 'JBSWY3DPEHPK3PXP', 'user', 5);
        return fetch_user_by_user_ip($ip);
    }

    private function at(string $local): int
    {
        return (new DateTimeImmutable($local, new DateTimeZone('Europe/Zurich')))->getTimestamp();
    }

    public function testTheDayEndsAtThreeInTheMorning(): void
    {
        $this->assertSame($this->at('2026-11-09 03:00'), status_message_reset_at($this->at('2026-11-08 18:00')));
        $this->assertSame($this->at('2026-11-09 03:00'), status_message_reset_at($this->at('2026-11-09 02:59')), 'after midnight it is still "today"');
        $this->assertSame($this->at('2026-11-10 03:00'), status_message_reset_at($this->at('2026-11-09 03:00')));
        // DST: 2026-03-29 02:00 → 03:00 in Zurich; 2026-10-25 03:00 → 02:00
        $this->assertSame($this->at('2026-03-29 03:00'), status_message_reset_at($this->at('2026-03-28 22:00')));
        $this->assertSame($this->at('2026-10-25 03:00'), status_message_reset_at($this->at('2026-10-24 22:00')));
    }

    public function testMessagesAreOneLineWithoutControlOrBidiCharacters(): void
    {
        $this->assertSame('in the office until 5', normalize_status_message("  in the\noffice \t until\r\n5  "));
        $this->assertSame('evil', normalize_status_message("\u{202E}ev\u{0007}il\u{2066}"));
        $this->assertSame('', normalize_status_message("\n\t "));
        $this->assertSame('Grüezi 👋', normalize_status_message('Grüezi 👋'));
        $this->assertSame('', normalize_status_message("broken \xC3\x28 utf-8"), 'invalid UTF-8 is dropped');
        $this->assertSame(8, status_message_length('Grüezi 👋'));
    }

    public function testLengthLimitCountsCharactersNotBytes(): void
    {
        $user = $this->user();
        $now = $this->at('2026-11-08 09:00');
        $emoji = str_repeat('🚀', STATUS_MESSAGE_MAX);
        $this->assertTrue(set_status_message($user, $emoji, $now)['ok'], '100 emoji are 100 characters');
        $tooLong = set_status_message($user, str_repeat('x', STATUS_MESSAGE_MAX + 1), $now);
        $this->assertFalse($tooLong['ok']);
        $this->assertStringContainsString('101 characters', (string)$tooLong['error']);
        $this->assertSame($emoji, user_status_message(fetch_user_by_id((int)$user['id']), $now), 'the old message stays');
    }

    public function testMessageExpiresAndIsCleared(): void
    {
        $user = $this->user();
        $other = $this->user('10.0.0.8', 'Other User');
        $now = $this->at('2026-11-08 09:00');
        $result = set_status_message($user, 'on call', $now);
        $this->assertSame($this->at('2026-11-09 03:00'), $result['until']);
        set_status_message($other, 'working from home', $now + 60);

        $fresh = fetch_user_by_id((int)$user['id']);
        $this->assertSame('on call', user_status_message($fresh, $now + 3600));
        $this->assertSame(['working from home', 'on call'], array_column(active_status_messages($now + 3600), 'message'), 'newest first');
        $this->assertSame([(int)$other['id'] => 'working from home', (int)$user['id'] => 'on call'], status_messages_by_user($now + 3600));

        $after = $this->at('2026-11-09 03:00');
        $this->assertNull(user_status_message($fresh, $after));
        $this->assertSame([], active_status_messages($after));
        $this->assertNull(fetch_user_by_id((int)$user['id'])['status_message'], 'cleared in the database');
    }

    public function testEmptyTextClears(): void
    {
        $user = $this->user();
        $now = $this->at('2026-11-08 09:00');
        set_status_message($user, 'lunch', $now);
        $result = set_status_message($user, "  \n", $now);
        $this->assertTrue($result['ok']);
        $this->assertNull($result['message']);
        $this->assertSame([], active_status_messages($now));
    }
}
