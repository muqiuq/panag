<?php
// Admin: backup and restore (forms on admin/config.php#backup). Users and networks as before, plus a full backup of
// the whole database and its restore. POST only; the result is shown on the config page.
require_once __DIR__ . '/../../src/bootstrap.php';
require_once __DIR__ . '/../../src/backup.php';
require_permission('admin');

ensure_session();
$admin = current_user();
$back = static function (string $type, string $message): never {
    $_SESSION['config_flash'] = ['type' => $type, 'message' => $message];
    header('Location: ' . url_for('admin/config.php') . '#backup');
    exit;
};
$upload = static function (string $field): string {
    if (isset($_FILES[$field]) && is_uploaded_file($_FILES[$field]['tmp_name'])) {
        return (string)file_get_contents($_FILES[$field]['tmp_name']);
    }
    return '';
};
$download = static function (string $filename, string $body): never {
    header('Content-Type: application/json; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Cache-Control: no-store');
    echo $body;
    exit;
};

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: ' . url_for('admin/config.php') . '#backup');
    exit;
}
require_csrf_token($_POST['csrf_token'] ?? null);
$who = ' by ' . $admin['username'];

switch ($_POST['action'] ?? '') {
    case 'export_users':
        require_permission('manage_users');
        log_event('users_exported', 'Users exported' . $who, (int)$admin['id'], $admin['username'], $admin['user_ip']);
        $download('users.json', export_users_json());
        // no break: $download exits
    case 'import_users':
        require_permission('manage_users');
        $json = $upload('users_file');
        if ($json === '') {
            $back('danger', 'No file uploaded.');
        }
        try {
            $result = import_users_json($json);
        } catch (Throwable $e) {
            $back('danger', 'User import failed: ' . $e->getMessage());
        }
        $message = 'Imported ' . (int)$result['imported'] . ' new user(s).';
        if ($result['skipped_existing'] > 0) {
            $message .= ' Skipped ' . (int)$result['skipped_existing'] . ' existing user_ip(s).';
        }
        if ($result['skipped_duplicate'] > 0) {
            $message .= ' Skipped ' . (int)$result['skipped_duplicate'] . ' duplicate user_ip(s) in file.';
        }
        log_event('users_imported', $message . $who, (int)$admin['id'], $admin['username'], $admin['user_ip']);
        $back('success', $message);
        // no break: $back exits
    case 'export_networks':
        require_permission('manage_networks');
        $download('networks.json', export_networks_json());
        // no break
    case 'import_networks':
        require_permission('manage_networks');
        $json = $upload('network_file');
        if ($json === '') {
            $back('danger', 'No file uploaded.');
        }
        $replace = ($_POST['import_mode'] ?? 'replace') !== 'append';
        try {
            $count = import_networks_json($json, $replace);
        } catch (Throwable $e) {
            $back('danger', 'Network import failed: ' . $e->getMessage());
        }
        $message = ($replace ? 'Replaced' : 'Appended') . ' ' . $count . ' network(s).';
        log_event('networks_imported', $message . $who, (int)$admin['id'], $admin['username'], $admin['user_ip']);
        $back('success', $message);
        // no break
    case 'export_full':
        log_event('full_backup_exported', 'Full backup downloaded' . $who, (int)$admin['id'], $admin['username'], $admin['user_ip']);
        $download('panag-backup-' . date('Ymd-Hi') . '.json', export_full_backup_json(db(), time()));
        // no break
    case 'restore_full':
        if (trim((string)($_POST['confirm'] ?? '')) !== 'RESTORE') {
            $back('danger', 'Not restored: type RESTORE to confirm that all current data is replaced.');
        }
        $json = $upload('backup_file');
        if ($json === '') {
            $back('danger', 'No file uploaded.');
        }
        try {
            $result = restore_full_backup(db(), $json, rtrim(DATA_DIR, '/') . '/backups');
        } catch (InvalidArgumentException $e) {
            $back('danger', 'Not restored: ' . $e->getMessage());
        } catch (Throwable $e) {
            error_log('PANAG full restore failed: ' . $e->getMessage());
            $back('danger', 'Restore failed, nothing was changed: ' . $e->getMessage());
        }
        // The restored data has its own users: keep the session only if this admin is still the same admin.
        $same = fetch_user_by_id((int)$admin['id']);
        $stillAdmin = $same && $same['username'] === $admin['username'] && $same['user_ip'] === $admin['user_ip'] && can($same, 'admin');
        log_event('full_backup_restored', sprintf('Full backup restored%s (%d table(s), %d row(s), schema %d; previous data saved as %s)', $who, $result['tables'], $result['rows'], $result['schema_from'], basename($result['safety_copy'])),
            $stillAdmin ? (int)$admin['id'] : null, $admin['username'], $admin['user_ip']);
        if (!$stillAdmin) {
            logout_user();
            header('Location: ' . url_for('login.php'));
            exit;
        }
        $back('success', sprintf('Restored %d row(s) in %d table(s). The previous data was saved as %s.', $result['rows'], $result['tables'], basename($result['safety_copy'])));
        // no break
    default:
        $back('danger', 'Unknown action.');
}
