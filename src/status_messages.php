<?php
// Status messages (PLAN.md, Phase 6): every user can set a short message for the current day ("in the office until
// 3", "on call"). It ends at the next 03:00 local time and is then cleared. All logged-in users see the messages
// of all users (dashboard, status page); admins see them in the users overview.

const STATUS_MESSAGE_MAX = 100;
const STATUS_MESSAGE_RESET_HOUR = 3;

/** End of the "current day" for a message set at $now: the next 03:00 in the app's time zone (DST-safe). */
function status_message_reset_at(int $now): int
{
    $tz = new DateTimeZone(date_default_timezone_get());
    $local = (new DateTimeImmutable('@' . $now))->setTimezone($tz);
    $reset = $local->setTime(STATUS_MESSAGE_RESET_HOUR, 0);
    if ($reset->getTimestamp() <= $now) {
        $reset = $local->modify('+1 day')->setTime(STATUS_MESSAGE_RESET_HOUR, 0);
    }
    return $reset->getTimestamp();
}

/** Length in characters (code points). PCRE only – the image has no mbstring. Invalid UTF-8 counts as -1. */
function status_message_length(string $text): int
{
    $count = preg_match_all('/./su', $text);
    return $count === false ? -1 : $count;
}

/**
 * One line of plain text: control and bidi-override characters removed, whitespace (also line breaks) collapsed.
 * Invalid UTF-8 becomes ''.
 */
function normalize_status_message(string $text): string
{
    if (preg_match('//u', $text) !== 1) {
        return '';
    }
    $text = (string)preg_replace('/[\s\p{Zl}\p{Zp}]+/u', ' ', $text);   // line breaks, tabs → one space
    $text = (string)preg_replace('/[\p{Cc}\x{202A}-\x{202E}\x{2066}-\x{2069}\x{200B}\x{FEFF}]/u', '', $text); // control, bidi, zero-width
    return trim($text);
}

/**
 * Set (or with an empty text: clear) the status message of $user.
 * @return array{ok: bool, error: ?string, message: ?string, until: ?int}
 */
function set_status_message(array $user, string $text, int $now): array
{
    $text = normalize_status_message($text);
    $length = status_message_length($text);
    if ($length > STATUS_MESSAGE_MAX) {
        return ['ok' => false, 'error' => sprintf('The status message is %d characters long – at most %d are allowed.', $length, STATUS_MESSAGE_MAX), 'message' => null, 'until' => null];
    }
    if ($text === '') {
        db()->prepare('UPDATE users SET status_message = NULL, status_message_at = NULL, status_message_until = NULL WHERE id = :id')
            ->execute([':id' => (int)$user['id']]);
        log_event('status_message_cleared', '', (int)$user['id'], $user['username'] ?? null, $user['user_ip'] ?? null);
        return ['ok' => true, 'error' => null, 'message' => null, 'until' => null];
    }
    $until = status_message_reset_at($now);
    db()->prepare('UPDATE users SET status_message = :m, status_message_at = :at, status_message_until = :u WHERE id = :id')
        ->execute([':m' => $text, ':at' => $now, ':u' => $until, ':id' => (int)$user['id']]);
    log_event('status_message_set', $text, (int)$user['id'], $user['username'] ?? null, $user['user_ip'] ?? null);
    return ['ok' => true, 'error' => null, 'message' => $text, 'until' => $until];
}

/** The message of $user if it is still valid at $now. */
function user_status_message(array $user, int $now): ?string
{
    $message = $user['status_message'] ?? null;
    return is_string($message) && $message !== '' && (int)($user['status_message_until'] ?? 0) > $now ? $message : null;
}

/** Clear messages whose day is over. Called before messages are listed; returns the number cleared. */
function expire_status_messages(int $now): int
{
    $stmt = db()->prepare('UPDATE users SET status_message = NULL, status_message_at = NULL, status_message_until = NULL
        WHERE status_message IS NOT NULL AND (status_message_until IS NULL OR status_message_until <= :now)');
    $stmt->execute([':now' => $now]);
    return $stmt->rowCount();
}

/**
 * Valid messages of all users, newest first.
 * @return list<array{id: int, username: string, message: string, at: int, until: int}>
 */
function active_status_messages(int $now): array
{
    expire_status_messages($now);
    $stmt = db()->prepare('SELECT id, username, status_message, status_message_at, status_message_until FROM users
        WHERE status_message IS NOT NULL AND status_message_until > :now ORDER BY status_message_at DESC, username COLLATE NOCASE');
    $stmt->execute([':now' => $now]);
    return array_map(fn($r) => [
        'id' => (int)$r['id'],
        'username' => (string)$r['username'],
        'message' => (string)$r['status_message'],
        'at' => (int)$r['status_message_at'],
        'until' => (int)$r['status_message_until'],
    ], $stmt->fetchAll(PDO::FETCH_ASSOC));
}

/** @return array<int, string> user id => valid message */
function status_messages_by_user(int $now): array
{
    return array_column(active_status_messages($now), 'message', 'id');
}
