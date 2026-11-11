<?php
// AI triage of alerts via OpenRouter (GLM). The AI only assesses and explains; it can raise, never lower or
// suppress, an alert. It receives pseudonymised *facts* selected by an allowlist – no names, no IP addresses,
// no network names, no free text. Zero data retention and data_collection=deny are always enforced.

const AI_FACT_ALLOWLIST = [
    'country', 'from_country', 'known_countries', 'asn', 'asn_org', 'asn_type', 'minutes', 'minutes_since_change',
    'local_hour', 'usual_hours', 'network_level', 'user_level', 'network_known', 'count', 'window_minutes',
    'megabytes_today', 'typical_megabytes', 'action', 'role_to',
];

const AI_SCHEMA = [
    'type' => 'object',
    'properties' => [
        'severity' => ['type' => 'string', 'enum' => ['info', 'low', 'medium', 'high', 'critical']],
        'likely_benign' => ['type' => 'boolean'],
        'confidence' => ['type' => 'string', 'enum' => ['low', 'medium', 'high']],
        'signals' => ['type' => 'array', 'items' => ['type' => 'string']],
        'summary_admin' => ['type' => 'string'],
        'summary_user' => ['type' => 'string'],
        'recommended_action' => ['type' => 'string', 'enum' => ['none', 'ask_user', 'revoke_access', 'investigate']],
    ],
    'required' => ['severity', 'likely_benign', 'confidence', 'signals', 'summary_admin', 'summary_user', 'recommended_action'],
    'additionalProperties' => false,
];

const AI_SYSTEM_PROMPT = <<<'PROMPT'
You assess security alerts of PANAG, a gatekeeper that gives administrators time-limited access to network
segments. Users connect via WireGuard VPN, log in to PANAG with a one-time password and then grant themselves
access to networks up to their access level.

You receive one alert as JSON: the subject (a pseudonym), its role and level, a summary of its usual behaviour
(baseline) and the findings of deterministic rules with their facts. Rules: W1 new country for the user,
W2 country outside the allowlist, W3 rapid change to an unknown country, W4 hosting/VPN network,
W5 endpoint switching between two addresses (key on two devices?), W6 unusual data volume, P1 failed logins,
P2 reused one-time password, P3 activity at an unusual hour, P4 network never used before, P5 many grants in a
short time, P6 sensitive admin action, P7 login right after a suspicious location change, P8 setup page attacked.

Assess how likely the activity is legitimate (travel, roaming, new job duties) or an attack (stolen VPN key,
phished one-time password, insider misuse). Combinations matter more than single findings.
- severity: your assessment. It is advisory; the rule severity "rule_severity" stays the minimum.
- summary_admin: at most 400 characters, factual, for the administrator.
- summary_user: at most 300 characters, plain language for the affected user, no jargon, no blame.
- signals: up to 6 short phrases naming what drove your assessment.
Answer only with the JSON object described by the schema.
PROMPT;

/** Stable pseudonym, not reversible without the PANAG database key. */
function ai_pseudonym(int $userId): string
{
    return 'U-' . substr(hash_hmac('sha256', (string)$userId, ai_pseudonym_key()), 0, 8);
}

function ai_pseudonym_key(): string
{
    if ((string)MONITOR_PSEUDONYM_KEY !== '') {
        return (string)MONITOR_PSEUDONYM_KEY;
    }
    return data_dir_secret('monitor.key');
}

/** Keep only allowlisted facts with simple, validated values. */
function ai_clean_facts(array $facts): array
{
    $clean = [];
    foreach (AI_FACT_ALLOWLIST as $key) {
        if (!array_key_exists($key, $facts) || $facts[$key] === null) {
            continue;
        }
        $value = $facts[$key];
        if (in_array($key, ['country', 'from_country'], true)) {
            $value = preg_match('/^([A-Z]{2}|\?\?)$/', (string)$value) ? (string)$value : null;
        } elseif ($key === 'known_countries') {
            $value = array_values(array_filter(array_map('strval', (array)$value), fn($c) => preg_match('/^[A-Z]{2}$/', $c) === 1));
        } elseif (in_array($key, ['asn_org', 'usual_hours', 'action', 'asn_type', 'role_to'], true)) {
            $value = mb_substr_safe((string)$value, 80);
        } elseif ($key === 'network_known') {
            $value = (bool)$value;
        } else {
            $value = is_numeric($value) ? (int)$value : null;
        }
        if ($value !== null) {
            $clean[$key] = $value;
        }
    }
    return $clean;
}

/** The complete payload sent to the AI for an alert. */
function ai_features(array $alert, int $now): array
{
    $user = $alert['user_id'] !== null ? fetch_user_by_id((int)$alert['user_id']) : null;
    $findings = alert_findings($alert);
    $first = $findings ? min(array_column($findings, 'at')) : $now;
    $features = [
        'subject' => $user ? ai_pseudonym((int)$user['id']) : 'system',
        'role' => $user ? (string)$user['role'] : null,
        'level' => $user ? (int)$user['accesslevel'] : null,
        'rule_severity' => (string)$alert['severity'],
        'findings' => array_map(fn($f) => [
            'rule' => (string)$f['rule'],
            'severity' => (string)$f['severity'],
            'minutes_after_first' => (int)round(((int)$f['at'] - $first) / 60),
            'local_hour' => (int)date('G', (int)$f['at']),
            'facts' => ai_clean_facts((array)($f['facts'] ?? [])),
        ], $findings),
    ];
    if ($user) {
        $baseline = baseline_for((int)$user['id']);
        $features['baseline'] = [
            'days' => $baseline && $baseline['first_seen'] ? (int)floor(($now - (int)$baseline['first_seen']) / 86400) : 0,
            'mature' => baseline_mature($baseline, $now),
            'usual_hours' => $baseline ? baseline_usual_hours($baseline) : 'unknown',
            'logins_per_week' => $baseline ? (float)$baseline['logins_per_week'] : 0,
            'grants_per_day' => $baseline ? (float)$baseline['grants_per_day'] : 0,
            'known_countries' => known_countries((int)$user['id']),
        ];
    }
    return $features;
}

function ai_request_body(array $features): array
{
    $body = [
        'model' => (string)OPENROUTER_MODEL,
        'messages' => [
            ['role' => 'system', 'content' => AI_SYSTEM_PROMPT],
            ['role' => 'user', 'content' => json_encode($features, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE)],
        ],
        'response_format' => ['type' => 'json_schema', 'json_schema' => ['name' => 'panag_triage', 'strict' => true, 'schema' => AI_SCHEMA]],
        'max_tokens' => 2048,
        'provider' => [
            'require_parameters' => true,
            'data_collection' => 'deny', // fixed – not configurable
            'zdr' => true,                // fixed – not configurable
            'only' => array_values(array_map('strval', OPENROUTER_PROVIDERS)),
            'allow_fallbacks' => true,
            'max_price' => ['prompt' => (int)OPENROUTER_MAX_PRICE_PROMPT, 'completion' => (int)OPENROUTER_MAX_PRICE_COMPLETION],
        ],
    ];
    if (OPENROUTER_REASONING_EFFORT !== 'off') {
        $body['reasoning'] = ['effort' => (string)OPENROUTER_REASONING_EFFORT];
    }
    return $body;
}

/**
 * POST to OpenRouter. Tests replace the transport via set_ai_transport().
 * @return array{status: int, body: ?array, error: ?string}
 */
function ai_http(array $body): array
{
    if (isset($GLOBALS['PANAG_AI_TRANSPORT'])) {
        return ($GLOBALS['PANAG_AI_TRANSPORT'])($body);
    }
    $headers = ['Content-Type: application/json', 'Authorization: Bearer ' . OPENROUTER_API_KEY, 'X-OpenRouter-Title: ' . APP_NAME];
    if ((string)APP_BASE_URL !== '') {
        $headers[] = 'HTTP-Referer: ' . APP_BASE_URL;
    }
    $result = ['status' => 0, 'body' => null, 'error' => null];
    for ($attempt = 0; $attempt < 2; $attempt++) {
        $ch = curl_init(rtrim((string)OPENROUTER_BASE_URL, '/') . '/chat/completions');
        curl_setopt_array($ch, [CURLOPT_POST => true, CURLOPT_POSTFIELDS => json_encode($body, JSON_INVALID_UTF8_SUBSTITUTE), CURLOPT_HTTPHEADER => $headers,
            CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => (int)MONITOR_AI_TIMEOUT, CURLOPT_CONNECTTIMEOUT => 10]);
        $raw = curl_exec($ch);
        $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $error = curl_error($ch);
        curl_close($ch);
        $decoded = is_string($raw) ? json_decode($raw, true) : null;
        $result = ['status' => $status, 'body' => is_array($decoded) ? $decoded : null, 'error' => $error !== '' ? $error : null];
        if ($status !== 429 && $status < 500 && $status !== 0) {
            break;
        }
    }
    return $result;
}

/** Replace the HTTP transport (tests). @param callable|null $fn fn(array $body): array{status, body, error} */
function set_ai_transport(?callable $fn): void
{
    if ($fn === null) {
        unset($GLOBALS['PANAG_AI_TRANSPORT']);
        return;
    }
    $GLOBALS['PANAG_AI_TRANSPORT'] = $fn;
}

/** Validate the model output against AI_SCHEMA (providers do not all enforce strict mode). */
function ai_validate_result($data): ?array
{
    if (!is_array($data)) {
        return null;
    }
    $p = AI_SCHEMA['properties'];
    foreach (['severity', 'confidence', 'recommended_action'] as $key) {
        if (!isset($data[$key]) || !in_array($data[$key], $p[$key]['enum'], true)) {
            return null;
        }
    }
    if (!isset($data['likely_benign']) || !is_bool($data['likely_benign']) || !isset($data['signals']) || !is_array($data['signals'])
        || !isset($data['summary_admin'], $data['summary_user']) || !is_string($data['summary_admin']) || !is_string($data['summary_user'])) {
        return null;
    }
    return [
        'severity' => $data['severity'],
        'likely_benign' => $data['likely_benign'],
        'confidence' => $data['confidence'],
        'signals' => array_slice(array_map(fn($s) => mb_substr_safe((string)$s, 80), array_filter($data['signals'], 'is_string')), 0, 6),
        'summary_admin' => mb_substr_safe($data['summary_admin'], 400),
        'summary_user' => mb_substr_safe($data['summary_user'], 300),
        'recommended_action' => $data['recommended_action'],
    ];
}

/** Ask the AI. @return array{ok: bool, result: ?array, error: ?string, usage: array, model: ?string, provider: ?string} */
function ai_assess(array $features): array
{
    $resp = ai_http(ai_request_body($features));
    $out = ['ok' => false, 'result' => null, 'error' => null, 'usage' => [], 'model' => null, 'provider' => null];
    $body = $resp['body'];
    if ($resp['status'] !== 200 || !is_array($body) || isset($body['error'])) {
        $out['error'] = 'HTTP ' . $resp['status'] . ': ' . (is_array($body) && isset($body['error']['message']) ? (string)$body['error']['message'] : (string)($resp['error'] ?? 'no response'));
        return $out;
    }
    $out['usage'] = is_array($body['usage'] ?? null) ? $body['usage'] : [];
    $out['model'] = isset($body['model']) ? (string)$body['model'] : null;
    $out['provider'] = isset($body['provider']) ? (string)$body['provider'] : null;
    $choice = $body['choices'][0] ?? null;
    if (($choice['finish_reason'] ?? null) !== 'stop') {
        $out['error'] = 'Unexpected finish_reason: ' . (string)($choice['finish_reason'] ?? 'none');
        return $out;
    }
    $result = ai_validate_result(json_decode((string)($choice['message']['content'] ?? ''), true));
    if ($result === null) {
        $out['error'] = 'Answer does not match the schema';
        return $out;
    }
    $out['ok'] = true;
    $out['result'] = $result;
    return $out;
}

function ai_usage_today(?int $now = null): array
{
    $usage = monitor_state('ai.usage.' . date('Y-m-d', $now ?? time()));
    return is_array($usage) ? $usage + ['calls' => 0, 'failures' => 0, 'prompt_tokens' => 0, 'completion_tokens' => 0] : ['calls' => 0, 'failures' => 0, 'prompt_tokens' => 0, 'completion_tokens' => 0];
}

function ai_record_usage(array $assessment, int $now): void
{
    $usage = ai_usage_today($now);
    $usage['calls']++;
    $usage['failures'] += $assessment['ok'] ? 0 : 1;
    $usage['prompt_tokens'] += (int)($assessment['usage']['prompt_tokens'] ?? 0);
    $usage['completion_tokens'] += (int)($assessment['usage']['completion_tokens'] ?? 0);
    monitor_state_set('ai.usage.' . date('Y-m-d', $now), $usage);
}

/**
 * Triage new/changed alerts (severity >= medium, not yet assessed). Max. 3 calls per cycle and
 * MONITOR_AI_MAX_CALLS_PER_DAY. The result can only raise the alert's severity.
 * @param list<int> $alertIds @return array{assessed: int, failed: int, skipped: ?string}
 */
function monitor_ai_triage(array $alertIds, int $now): array
{
    $stats = ['assessed' => 0, 'failed' => 0, 'skipped' => null];
    if (($problem = ai_config_problem()) !== null) {
        $stats['skipped'] = $problem;
        return $stats;
    }
    foreach ($alertIds as $id) {
        if ($stats['assessed'] + $stats['failed'] >= 3) {
            break;
        }
        if (ai_usage_today($now)['calls'] >= MONITOR_AI_MAX_CALLS_PER_DAY) {
            $stats['skipped'] = 'Daily limit of ' . MONITOR_AI_MAX_CALLS_PER_DAY . ' AI calls reached.';
            break;
        }
        $alert = fetch_alert($id);
        if (!$alert || $alert['ai'] !== null || severity_rank((string)$alert['severity']) < severity_rank('medium')) {
            continue;
        }
        $assessment = ai_assess(ai_features($alert, $now));
        ai_record_usage($assessment, $now);
        if (!$assessment['ok']) {
            $stats['failed']++;
            error_log('PANAG AI triage of alert #' . $id . ' failed: ' . $assessment['error']);
            continue;
        }
        $stats['assessed']++;
        $ai = $assessment['result'] + ['model' => $assessment['model'] ?? OPENROUTER_MODEL, 'provider' => $assessment['provider'], 'at' => $now];
        // Raise only, decided in SQL: the alert may have changed during the call (e.g. "That wasn't me").
        $rank = "CASE severity WHEN 'info' THEN 0 WHEN 'low' THEN 1 WHEN 'medium' THEN 2 WHEN 'high' THEN 3 ELSE 4 END";
        $stmt = db()->prepare("UPDATE alerts SET ai = :ai, severity = CASE WHEN CAST(:r AS INTEGER) > {$rank} THEN :s ELSE severity END WHERE id = :id");
        $stmt->execute([':ai' => json_encode($ai, JSON_INVALID_UTF8_SUBSTITUTE), ':r' => severity_rank((string)$ai['severity']), ':s' => (string)$ai['severity'], ':id' => $id]);
        $after = fetch_alert($id);
        if ($after && $after['notified_at'] !== null && severity_rank((string)$after['severity']) > severity_rank((string)$alert['severity'])) {
            alert_reset_delivery($id); // raised after it was mailed: mail again
        }
    }
    return $stats;
}

/** Synthetic case for the "Test AI" button (no real user data). */
function ai_test_features(): array
{
    return [
        'subject' => 'U-test0000', 'role' => 'user', 'level' => 5, 'rule_severity' => 'high',
        'findings' => [
            ['rule' => 'W2', 'severity' => 'high', 'minutes_after_first' => 0, 'local_hour' => 3,
                'facts' => ['country' => 'US', 'asn' => 14061, 'asn_org' => 'DigitalOcean, LLC', 'asn_type' => 'hosting', 'known_countries' => ['CH']]],
            ['rule' => 'P7', 'severity' => 'high', 'minutes_after_first' => 4, 'local_hour' => 3, 'facts' => ['minutes_since_change' => 4, 'country' => 'US']],
        ],
        'baseline' => ['days' => 120, 'mature' => true, 'usual_hours' => '07-19', 'logins_per_week' => 9, 'grants_per_day' => 1.4, 'known_countries' => ['CH']],
    ];
}
