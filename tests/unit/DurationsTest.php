<?php
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class DurationsTest extends TestCase
{
    public static function inputs(): array
    {
        return [
            ['1:30', 5400], ['0:15', 900], ['14:00', 50400], ['01:30:15', 5415],
            ['90', 5400], ['2h', 7200], ['45m', 2700], ['45min', 2700], ['1h30m', 5400], ['1h 30m', 5400], ['3600s', 3600],
            ['', null], ['abc', null], ['1:75', null], ['-5', null], ['1.5h', null],
        ];
    }

    #[DataProvider('inputs')]
    public function testParseUserInput(string $input, ?int $expected): void
    {
        $this->assertSame($expected, parse_duration_input($input));
    }

    public static function routerValues(): array
    {
        return [
            ['59m58s', 3598], ['1h', 3600], ['1d2h3m4s', 93784], ['1w', 604800], ['01:00:00', 3600],
            ['14:00:00', 50400], ['1d02:00:00', 93600], ['500ms', 0], ['', null], ['soon', null],
        ];
    }

    #[DataProvider('routerValues')]
    public function testParseRouterOsDurations(string $value, ?int $expected): void
    {
        $this->assertSame($expected, parse_routeros_duration($value));
    }

    public function testFormatting(): void
    {
        $this->assertSame('14:00:00', format_routeros_timeout(14 * 3600));
        $this->assertSame('00:15:00', format_routeros_timeout(900));
        $this->assertSame('1 h 30 min', format_duration_human(5400));
        $this->assertSame('15 min', format_duration_human(900));
        $this->assertSame('2 h', format_duration_human(7200));
        $this->assertSame('40 s', format_duration_human(40));
        $this->assertSame('1:05', format_duration_input(3900));
    }

    public function testLimits(): void
    {
        $this->assertSame(14 * 3600, max_grant_duration('default'));
        $this->assertSame(12 * 3600, max_grant_duration('extended'));

        $this->assertNull(validate_grant_duration('default', 15 * 60));
        $this->assertNull(validate_grant_duration('default', 14 * 3600));
        $this->assertNull(validate_grant_duration('extended', 12 * 3600));
        $this->assertNotNull(validate_grant_duration('default', 14 * 60));          // below 15 min
        $this->assertNotNull(validate_grant_duration('default', 14 * 3600 + 60));   // above 14 h
        $this->assertNotNull(validate_grant_duration('extended', 12 * 3600 + 60));  // above 12 h
        $this->assertNotNull(validate_grant_duration('extended', null));

        $this->assertSame(12 * 3600, clamp_grant_duration('extended', 20 * 3600));
        $this->assertSame(15 * 60, clamp_grant_duration('default', 60));
    }

    public function testPresetsRespectLimits(): void
    {
        $this->assertContains(14 * 3600, grant_duration_presets('default'));
        $this->assertNotContains(14 * 3600, grant_duration_presets('extended'));
        $this->assertSame(15 * 60, grant_duration_presets('extended')[0]);
    }
}
