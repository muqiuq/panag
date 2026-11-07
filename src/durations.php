<?php
// Durations of access grants: limits, parsing (user input and RouterOS format) and formatting.

const MIN_GRANT_DURATION = 15 * 60;          // 15 min, for default and extended access
const HARD_MAX_DEFAULT_DURATION = 14 * 3600; // 14 h – MAX_DEFAULT_DURATION may only lower this
const HARD_MAX_EXTENDED_DURATION = 12 * 3600; // 12 h – MAX_EXTENDED_DURATION may only lower this
const GRANT_KINDS = ['default', 'extended'];

/** Upper limit for a grant kind, from config but never above the hard limit or below the minimum. */
function max_grant_duration(string $kind): int
{
    $hard = $kind === 'default' ? HARD_MAX_DEFAULT_DURATION : HARD_MAX_EXTENDED_DURATION;
    $configured = parse_duration_input((string)($kind === 'default' ? MAX_DEFAULT_DURATION : MAX_EXTENDED_DURATION));
    return max(MIN_GRANT_DURATION, min($hard, $configured ?? $hard));
}

/** @return string|null error message, null if valid */
function validate_grant_duration(string $kind, ?int $seconds): ?string
{
    $label = $kind === 'default' ? 'Default access' : 'Extended access';
    if ($seconds === null) {
        return $label . ': invalid duration (use e.g. 1:30, 90m or 2h).';
    }
    if ($seconds < MIN_GRANT_DURATION) {
        return $label . ' must be at least ' . format_duration_human(MIN_GRANT_DURATION) . '.';
    }
    if ($seconds > max_grant_duration($kind)) {
        return $label . ' may be at most ' . format_duration_human(max_grant_duration($kind)) . '.';
    }
    return null;
}

/** Clamp a stored duration to the current limits (limits may have been lowered after it was saved). */
function clamp_grant_duration(string $kind, int $seconds): int
{
    return max(MIN_GRANT_DURATION, min(max_grant_duration($kind), $seconds));
}

/** Preset choices offered in the UI (seconds). */
function grant_duration_presets(string $kind): array
{
    $presets = [15 * 60, 30 * 60, 3600, 2 * 3600, 4 * 3600, 8 * 3600, 12 * 3600, 14 * 3600];
    return array_values(array_filter($presets, fn($s) => $s <= max_grant_duration($kind)));
}

/**
 * Parse a duration typed by a user or configured by an admin.
 * Accepts "1:30" (h:mm), "01:30:00" (h:mm:ss), "2h", "90m", "1h30m", "45" (minutes), "3600s".
 */
function parse_duration_input(string $value): ?int
{
    $value = strtolower(str_replace(' ', '', trim($value)));
    if ($value === '') {
        return null;
    }
    if (preg_match('/^(\d{1,3}):([0-5]\d)$/', $value, $m)) {
        return (int)$m[1] * 3600 + (int)$m[2] * 60;
    }
    if (preg_match('/^(\d{1,3}):([0-5]\d):([0-5]\d)$/', $value, $m)) {
        return (int)$m[1] * 3600 + (int)$m[2] * 60 + (int)$m[3];
    }
    if (preg_match('/^\d{1,5}$/', $value)) {
        return (int)$value * 60;
    }
    if (preg_match('/^(?:(\d{1,3})h)?(?:(\d{1,5})m(?:in)?)?(?:(\d{1,6})s)?$/', $value, $m)) {
        return (int)($m[1] ?? 0) * 3600 + (int)($m[2] ?? 0) * 60 + (int)($m[3] ?? 0);
    }
    return null;
}

/**
 * Parse durations as returned by RouterOS: "1w2d3h4m5s", "59m58s", "01:00:00", "1d02:00:00".
 */
function parse_routeros_duration(string $value): ?int
{
    $value = trim($value);
    if ($value === '') {
        return null;
    }
    if (preg_match('/^(?:(\d+)w)?(?:(\d+)d)?(\d+):(\d{2}):(\d{2})$/', $value, $m)) {
        return (int)$m[1] * 604800 + (int)$m[2] * 86400 + (int)$m[3] * 3600 + (int)$m[4] * 60 + (int)$m[5];
    }
    if (preg_match('/^(?:(\d+)w)?(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?(?:(\d+)ms)?$/', $value, $m)) {
        return (int)($m[1] ?? 0) * 604800 + (int)($m[2] ?? 0) * 86400 + (int)($m[3] ?? 0) * 3600 + (int)($m[4] ?? 0) * 60 + (int)($m[5] ?? 0);
    }
    return null;
}

/** RouterOS "timeout" value, e.g. 14:00:00. */
function format_routeros_timeout(int $seconds): string
{
    $seconds = max(0, $seconds);
    return sprintf('%02d:%02d:%02d', intdiv($seconds, 3600), intdiv($seconds % 3600, 60), $seconds % 60);
}

/** "1 h 30 min", "15 min", "40 s" */
function format_duration_human(int $seconds): string
{
    $seconds = max(0, $seconds);
    if ($seconds < 60) {
        return $seconds . ' s';
    }
    $h = intdiv($seconds, 3600);
    $m = intdiv($seconds % 3600, 60);
    return trim(($h ? $h . ' h ' : '') . ($m ? $m . ' min' : ''));
}

/** Value for the duration input field ("h:mm"). */
function format_duration_input(int $seconds): string
{
    return sprintf('%d:%02d', intdiv($seconds, 3600), intdiv($seconds % 3600, 60));
}
