<?php
// Known places of a user (countries and network operators). A place counts as known when the user
// confirmed it ("That was me"), an admin added it, or it was learned (allowlisted countries only).
// "pending" = seen in an allowlisted country that was new for the user; learned after 3 days unless
// the user answered "That wasn't me".

const PLACE_PENDING_DAYS = 3;

function place_is_known(int $userId, string $kind, string $value): bool
{
    $stmt = db()->prepare("SELECT 1 FROM user_locations WHERE user_id = :u AND kind = :k AND value = :v AND source != 'pending'");
    $stmt->execute([':u' => $userId, ':k' => $kind, ':v' => $value]);
    return (bool)$stmt->fetchColumn();
}

/** @return list<string> known countries of the user */
function known_countries(int $userId): array
{
    $stmt = db()->prepare("SELECT value FROM user_locations WHERE user_id = :u AND kind = 'country' AND source != 'pending' ORDER BY value");
    $stmt->execute([':u' => $userId]);
    return array_map('strval', $stmt->fetchAll(PDO::FETCH_COLUMN));
}

/** @return list<array{kind: string, value: string, source: string, first_seen: int, last_seen: int}> */
function user_places(int $userId): array
{
    $stmt = db()->prepare('SELECT kind, value, source, first_seen, last_seen FROM user_locations WHERE user_id = :u ORDER BY kind, value');
    $stmt->execute([':u' => $userId]);
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

/**
 * Remember a place. A stronger source replaces a weaker one (pending < learned < confirmed/admin), never the
 * other way round; last_seen is always refreshed.
 */
function place_remember(int $userId, string $kind, string $value, string $source, int $now): void
{
    $rank = ['pending' => 0, 'learned' => 1, 'confirmed' => 2, 'admin' => 2];
    $stmt = db()->prepare('SELECT source FROM user_locations WHERE user_id = :u AND kind = :k AND value = :v');
    $stmt->execute([':u' => $userId, ':k' => $kind, ':v' => $value]);
    $current = $stmt->fetchColumn();
    if ($current === false) {
        db()->prepare('INSERT INTO user_locations (user_id, kind, value, source, first_seen, last_seen) VALUES (:u, :k, :v, :s, :t, :t)')
            ->execute([':u' => $userId, ':k' => $kind, ':v' => $value, ':s' => $source, ':t' => $now]);
        return;
    }
    $newSource = ($rank[$source] ?? 0) > ($rank[(string)$current] ?? 0) ? $source : (string)$current;
    db()->prepare('UPDATE user_locations SET source = :s, last_seen = :t WHERE user_id = :u AND kind = :k AND value = :v')
        ->execute([':u' => $userId, ':k' => $kind, ':v' => $value, ':s' => $newSource, ':t' => $now]);
}

function place_forget(int $userId, string $kind, string $value): void
{
    db()->prepare('DELETE FROM user_locations WHERE user_id = :u AND kind = :k AND value = :v')
        ->execute([':u' => $userId, ':k' => $kind, ':v' => $value]);
}

/** Promote pending places older than PLACE_PENDING_DAYS. @return int promoted */
function places_learn_pending(int $now): int
{
    $stmt = db()->prepare("UPDATE user_locations SET source = 'learned' WHERE source = 'pending' AND first_seen <= :t");
    $stmt->execute([':t' => $now - PLACE_PENDING_DAYS * 86400]);
    return $stmt->rowCount();
}

function place_label(string $kind, string $value): string
{
    return $kind === 'asn' ? 'AS' . $value : $value;
}
