<?php
// Detection rule settings (PLAN.md, Phase 6), edited on admin/rules.php. Every rule can be switched off and given
// another severity; its thresholds can be changed. Defaults come from the environment (MONITOR_* in config.php) or
// the built-in values below; changes made in the web UI are stored in settings['monitor.rules'] and win.
// A value equal to its default is not stored, so later changes of the environment still apply.

const RULE_SETTINGS_KEY = 'monitor.rules';

/** Rules that cannot be switched off: U1 is the user's own report ("That wasn't me"). */
const RULES_ALWAYS_ON = ['U1'];

/**
 * Parameters of the rules. type: int | duration (seconds) | countries | asns.
 * Either 'env' (default from that config constant) or 'default'.
 */
const RULE_PARAMS = [
    'learning_days' => ['rules' => ['W1', 'W6', 'P3', 'P4'], 'type' => 'int', 'label' => 'Learning phase (days)', 'env' => 'MONITOR_LEARNING_DAYS', 'min' => 0, 'max' => 365],
    'allowed_countries' => ['rules' => ['W2'], 'type' => 'countries', 'label' => 'Allowed countries', 'env' => 'MONITOR_ALLOWED_COUNTRIES'],
    'travel_window' => ['rules' => ['W3'], 'type' => 'duration', 'label' => 'Window', 'env' => 'MONITOR_TRAVEL_WINDOW', 'min' => 60, 'max' => 7 * 86400],
    'hosting_asns' => ['rules' => ['W4'], 'type' => 'asns', 'label' => 'Additional AS numbers', 'env' => 'MONITOR_HOSTING_ASNS'],
    'switch_count' => ['rules' => ['W5'], 'type' => 'int', 'label' => 'Switches', 'default' => 4, 'min' => 2, 'max' => 100],
    'switch_window' => ['rules' => ['W5'], 'type' => 'duration', 'label' => 'Within', 'default' => 1800, 'min' => 300, 'max' => 86400],
    'volume_factor' => ['rules' => ['W6'], 'type' => 'int', 'label' => '× usual daily volume', 'default' => 5, 'min' => 2, 'max' => 100],
    'volume_min_mb' => ['rules' => ['W6'], 'type' => 'int', 'label' => 'At least (MB)', 'default' => 512, 'min' => 1, 'max' => 1048576],
    'failed_logins' => ['rules' => ['P1'], 'type' => 'int', 'label' => 'Failed logins', 'env' => 'MONITOR_FAILED_LOGINS', 'min' => 2, 'max' => 1000],
    'failed_logins_window' => ['rules' => ['P1'], 'type' => 'duration', 'label' => 'Within', 'env' => 'MONITOR_FAILED_LOGINS_WINDOW', 'min' => 60, 'max' => 86400],
    'burst_count' => ['rules' => ['P5'], 'type' => 'int', 'label' => 'Single grants', 'default' => 5, 'min' => 2, 'max' => 100],
    'burst_window' => ['rules' => ['P5'], 'type' => 'duration', 'label' => 'Within', 'default' => 600, 'min' => 60, 'max' => 86400],
    'router_down' => ['rules' => ['M1'], 'type' => 'duration', 'label' => 'Router unreadable for', 'default' => 1800, 'min' => 300, 'max' => 86400],
];

/**
 * Stored settings: ['enabled' => [code => bool], 'severity' => [code => level], 'params' => [name => value]].
 * Cached per request; save_rule_settings() and rule_settings_reload() refresh it.
 * @return array{enabled: array<string, bool>, severity: array<string, string>, params: array<string, mixed>}
 */
function rule_settings(bool $reload = false): array
{
    static $cache = null;
    if ($cache === null || $reload) {
        $raw = monitor_state(RULE_SETTINGS_KEY, []);
        $raw = is_array($raw) ? $raw : [];
        $cache = [
            'enabled' => array_map('boolval', array_intersect_key((array)($raw['enabled'] ?? []), MONITOR_RULES)),
            'severity' => array_filter(array_intersect_key((array)($raw['severity'] ?? []), MONITOR_RULES), fn($s) => is_string($s) && isset(SEVERITIES[$s])),
            'params' => array_intersect_key((array)($raw['params'] ?? []), RULE_PARAMS),
        ];
    }
    return $cache;
}

function rule_settings_reload(): void
{
    rule_settings(true);
}

/** @return mixed default of a parameter (environment or built-in) */
function rule_param_default(string $name)
{
    $def = RULE_PARAMS[$name] ?? throw new InvalidArgumentException('Unknown rule parameter ' . $name);
    return isset($def['env']) ? constant($def['env']) : $def['default'];
}

/** @return mixed effective value */
function rule_param(string $name)
{
    $stored = rule_settings()['params'];
    return array_key_exists($name, $stored) ? $stored[$name] : rule_param_default($name);
}

/** web (changed on admin/rules.php), env or default. */
function rule_param_source(string $name): string
{
    if (array_key_exists($name, rule_settings()['params'])) {
        return 'web';
    }
    $env = RULE_PARAMS[$name]['env'] ?? null;
    if ($env === null) {
        return 'default';
    }
    return ($GLOBALS['PANAG_CONFIG'][$env]['source'] ?? 'default') === 'default' ? 'default' : 'env';
}

function rule_enabled(string $code): bool
{
    return in_array($code, RULES_ALWAYS_ON, true) || (rule_settings()['enabled'][$code] ?? true);
}

/** Severity override of a rule, or null for the rule's own severity. */
function rule_severity(string $code): ?string
{
    return rule_settings()['severity'][$code] ?? null;
}

/**
 * Apply the settings to findings: drop those of disabled rules, set overridden severities.
 * @param list<array<string, mixed>> $findings
 * @return list<array<string, mixed>>
 */
function rules_apply(array $findings): array
{
    $out = [];
    foreach ($findings as $f) {
        $code = (string)($f['rule'] ?? '');
        if (!rule_enabled($code)) {
            continue;
        }
        $f['severity'] = rule_severity($code) ?? $f['severity'];
        $out[] = $f;
    }
    return $out;
}

/** Display form of a parameter value (inputs and texts). */
function rule_param_display(string $name, $value): string
{
    return match (RULE_PARAMS[$name]['type']) {
        'duration' => format_duration_human((int)$value),
        'countries', 'asns' => implode(', ', array_map('strval', (array)$value)),
        default => (string)$value,
    };
}

/**
 * Parse one submitted parameter.
 * @return array{0: mixed, 1: ?string} [value, error]
 */
function rule_param_parse(string $name, string $input): array
{
    $def = RULE_PARAMS[$name];
    $input = trim($input);
    $label = $def['label'] . ' (' . implode(', ', $def['rules']) . ')';
    switch ($def['type']) {
        case 'int':
            if (!preg_match('/^\d+$/', $input) || (int)$input < $def['min'] || (int)$input > $def['max']) {
                return [null, sprintf('%s: a whole number from %d to %d.', $label, $def['min'], $def['max'])];
            }
            return [(int)$input, null];
        case 'duration':
            $seconds = parse_duration_input($input);
            if ($seconds === null || $seconds < $def['min'] || $seconds > $def['max']) {
                return [null, sprintf('%s: a duration from %s to %s (e.g. 15m, 2h, 1:30).', $label, format_duration_human($def['min']), format_duration_human($def['max']))];
            }
            return [$seconds, null];
        case 'countries':
            $items = $input === '' ? [] : preg_split('/[\s,;]+/', strtoupper($input), -1, PREG_SPLIT_NO_EMPTY);
            foreach ($items ?: [] as $code) {
                if (!preg_match('/^[A-Z]{2}$/', $code)) {
                    return [null, sprintf('%s: "%s" is not an ISO country code (two letters, e.g. CH).', $label, $code)];
                }
            }
            return [array_values(array_unique($items ?: [])), null];
        case 'asns':
            $items = $input === '' ? [] : preg_split('/[\s,;]+/', strtoupper($input), -1, PREG_SPLIT_NO_EMPTY);
            $asns = [];
            foreach ($items ?: [] as $asn) {
                $digits = preg_replace('/^AS/', '', $asn);
                if (!ctype_digit((string)$digits) || (int)$digits < 1) {
                    return [null, sprintf('%s: "%s" is not an AS number (e.g. 64512 or AS64512).', $label, $asn)];
                }
                $asns[] = (string)(int)$digits;
            }
            return [array_values(array_unique($asns)), null];
        default:
            return [null, 'Unknown parameter ' . $name];
    }
}

/** Compare a parsed value with the default (lists as sets of strings, numbers as ints). */
function rule_param_equals_default(string $name, $value): bool
{
    $default = rule_param_default($name);
    if (is_array($value) || is_array($default)) {
        $a = array_map('strval', (array)$value);
        $b = array_map('strval', (array)$default);
        sort($a);
        sort($b);
        return $a === $b;
    }
    return (int)$value === (int)$default;
}

/**
 * Save the form of admin/rules.php: enabled[code], severity[code] ('' = rule's own), params[name].
 * Nothing is stored when anything is invalid.
 * @return array{ok: bool, errors: list<string>, changes: list<string>}
 */
function save_rule_settings(array $input, array $admin): array
{
    $errors = [];
    $new = ['enabled' => [], 'severity' => [], 'params' => []];
    foreach (array_keys(MONITOR_RULES) as $code) {
        if (in_array($code, RULES_ALWAYS_ON, true)) {
            continue;
        }
        if (empty($input['enabled'][$code])) {
            $new['enabled'][$code] = false;
        }
        $severity = (string)($input['severity'][$code] ?? '');
        if ($severity !== '') {
            if (!isset(SEVERITIES[$severity])) {
                $errors[] = $code . ': unknown severity "' . $severity . '".';
            } else {
                $new['severity'][$code] = $severity;
            }
        }
    }
    foreach (RULE_PARAMS as $name => $def) {
        if (!isset($input['params'][$name])) {
            continue; // not submitted: keep as it is
        }
        [$value, $error] = rule_param_parse($name, (string)$input['params'][$name]);
        if ($error !== null) {
            $errors[] = $error;
        } elseif (!rule_param_equals_default($name, $value)) {
            $new['params'][$name] = $value;
        }
    }
    foreach (rule_settings()['params'] as $name => $value) {
        if (!isset($input['params'][$name])) {
            $new['params'][$name] = $value;
        }
    }
    if ($errors) {
        return ['ok' => false, 'errors' => $errors, 'changes' => []];
    }

    $old = rule_settings();
    $changes = [];
    foreach (array_keys(MONITOR_RULES) as $code) {
        $was = $old['enabled'][$code] ?? true;
        $now = $new['enabled'][$code] ?? true;
        if ($was !== $now) {
            $changes[] = $code . ($now ? ' on' : ' off');
        }
        if (($old['severity'][$code] ?? null) !== ($new['severity'][$code] ?? null)) {
            $changes[] = $code . ' severity ' . ($new['severity'][$code] ?? 'default');
        }
    }
    foreach (array_keys(RULE_PARAMS) as $name) {
        $before = rule_param($name);
        $after = array_key_exists($name, $new['params']) ? $new['params'][$name] : rule_param_default($name);
        if (rule_param_display($name, $before) !== rule_param_display($name, $after)) {
            $changes[] = $name . ' ' . rule_param_display($name, $after);
        }
    }
    monitor_state_set(RULE_SETTINGS_KEY, $new);
    rule_settings_reload();
    if ($changes) {
        log_event('monitor_rules_changed', implode('; ', $changes) . ' by ' . $admin['username'], (int)$admin['id'], $admin['username'], $admin['user_ip']);
    }
    return ['ok' => true, 'errors' => [], 'changes' => $changes];
}

/** Back to the defaults (environment / built-in) for everything. */
function reset_rule_settings(array $admin): void
{
    monitor_state_set(RULE_SETTINGS_KEY, ['enabled' => [], 'severity' => [], 'params' => []]);
    rule_settings_reload();
    log_event('monitor_rules_changed', 'All detection rules reset to the defaults by ' . $admin['username'], (int)$admin['id'], $admin['username'], $admin['user_ip']);
}
