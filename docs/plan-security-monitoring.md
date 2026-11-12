# PANAG Security Monitoring – Plan (Entwurf)

Stand: 2026-11-07 · umgesetzt bis auf die Geräteprüfung (Phase 0), siehe [Kapitel 18](#18-umsetzungsstand) · eigenständiges Projekt neben [PLAN.md](../PLAN.md) (Modernisierung)

## 1. Ziel

PANAG soll ungewöhnliches Verhalten erkennen und per E-Mail alarmieren:

| # | Anforderung |
|---|-------------|
| A | **WireGuard:** Zugriffe von einem ungewöhnlichen Ort erkennen (GeoIP der Gegenstelle, z. B. neues Land, Hosting-Anbieter, schneller Länderwechsel). |
| B | **PANAG-Aktivität:** abweichende Muster eines Users erkennen (Login-Zeiten, Fehlversuche, OTP-Replay, ungewohnte Netze, Häufungen, sensible Admin-Aktionen). |
| C | **KI-gestützt:** Verdachtsfälle von einem Sprachmodell einordnen und verständlich erklären lassen. |
| D | **Alarm per E-Mail** an Admins und – nach Entscheid – an den betroffenen User. |

**Nicht im Umfang:** Heartbeat von PANAG an ein Drittsystem (folgt später, siehe Kapitel 12). Ebenfalls nicht enthalten: automatische Sperren ohne menschliche Bestätigung und Auswertung von Firewall- oder Verbindungs-Logs des Routers.

## 2. Ausgangslage

**Was PANAG schon hat:**
- `audit_log` mit etwa 25 Ereignistypen, u. a.:
  - Logins: `login_success`, `login_failed`, `login_rate_limited`, `otp_reuse_blocked`
  - Freigaben: `default_access_granted`, `extended_access_granted`, `access_revoked`/`access_extended`, `self_revoke`
  - Admin-Aktionen: `otp_revealed`, `otp_secret_changed`, `user_role_changed`, `user_created`/`user_updated`/`user_deleted`, `impersonate_start`/`impersonate_end`, `network_*`, `default_network_*`
  - Setup: `setup_token_invalid`
- `login_attempts` und die Freigaben als RouterOS-Address-Lists.
- Den Router-Zugang über `RouterClient`. `wireguardPeers()` existiert bereits, ebenso der Mock in `dev/mock-routeros/`.

**Was RouterOS pro WireGuard-Peer liefert:** laut RouterOS-Doku die Read-only-Felder `current-endpoint-address`, `current-endpoint-port` (Quelle des letzten gültig authentifizierten Pakets), `last-handshake`, `rx` und `tx`. Hinzu kommen die konfigurierten Felder `allowed-address`, `public-key`, `comment` und `name`. Ein Peer lässt sich über `allowed-address` (enthält die `user_ip`) einem PANAG-User zuordnen.

**Was fehlt:**
- E-Mail-Adressen der User (Spalte gibt es nicht)
- ein Zeitplan: PANAG läuft heute nur auf Anfrage, ohne Cron
- GeoIP
- Mail-Versand
- eine Alarm-Verwaltung

**Rahmenbedingungen (aus PLAN.md):**
- RouterOS-Container auf dem hEX S, Images für ARM64 und ARMv7
- Image < 50 MB, RAM im Leerlauf < 64 MB
- SQLite auf USB/microSD
- Konfiguration über Env-Variablen, Secrets als `*_FILE`
- strikte CSP
- UI auf Englisch

## 3. Grundsatz: Wer erkennt, wer erklärt

**Erkennen tun Regeln und Statistik, nicht das Sprachmodell.** Die KI ordnet ein und formuliert, sie entscheidet nicht allein.

| Schicht | Aufgabe | Warum so |
|---------|---------|----------|
| 1. Regeln | harte Signale, z. B. Land ausserhalb der Allowlist, OTP-Replay, Fehlversuch-Serie | deterministisch, erklärbar, testbar, ohne Internet |
| 2. Baseline pro User | „ungewöhnlich für *diesen* User“: Uhrzeit, Netze, Länder, Datenvolumen | lernt aus der eigenen Historie, läuft billig in PHP auf dem Router |
| 3. KI-Triage (optional) | Verdachtsfall im Kontext bewerten, Ereignisse bündeln, verständlichen Mailtext schreiben, nächsten Schritt vorschlagen | senkt Fehlalarm-Frust und erklärt in Klartext |

**Daraus folgen feste Regeln für die KI:**
- **Die KI kann keinen Alarm unterdrücken.** Was eine Regel als „hoch“ meldet, wird gemeldet. Die KI darf die Schwere *erhöhen* und *kommentieren*.
- **Ohne KI funktioniert alles.** Ist sie aus oder nicht erreichbar, kommt eine Vorlagen-Mail mit den Regelbefunden.
- **Die KI sieht keine Freitexte.** User-Namen, Netznamen, Peer-Kommentare und Log-Details werden nicht gesendet. Das schützt die Daten und verhindert Prompt-Injection über manipulierte Namen oder Kommentare.

## 4. Architektur

```
 RouterOS /system scheduler (alle 5 min)
        │  /tool fetch  POST http://172.17.0.2:8080/monitor.php  (Token-Header)
        ▼
 ┌──────────────── PANAG-Container ────────────────────────────────────────┐
 │ Monitor-Zyklus (Lock, max. Laufzeit)                                    │
 │  1. Sammeln     audit_log seit Cursor · WireGuard-Peers (1 REST-Call)   │
 │  2. Anreichern  GeoIP/ASN (lokale MMDB) · Peer → User                   │
 │  3. Erkennen    Regeln + Baseline → Kandidaten                          │
 │  4. Bündeln     pro User/Zeitfenster → Alarm (Dedupe, Cooldown)         │
 │  5. Triage      optional GLM über OpenRouter (pseudonym. Merkmale) ─────┼──► openrouter.ai
 │  6. Melden      E-Mail sofort / Digest  ────────────────────────────────┼──► SMTP-Relay
 │  7. Aufräumen   Retention, Baseline-Update, Monitor-Health              │
 └─────────────────────────────────────────────────────────────────────────┘
        ▲                                   ▲
   admin/alerts.php, admin/monitoring.php   profile.php (E-Mail, bekannte Orte)
```

**Auslösung:**
1. **RouterOS:** ein Scheduler ruft alle 5 min `public/monitor.php` auf.
   - Schutz: Token im Header, Vergleich per `hash_equals`. PANAG erzeugt ihn in `DATA_DIR/monitor.token` (oder `MONITOR_TOKEN`); der Scheduler liest die Datei über den Mount.
   - Zusätzlich nur von `MONITOR_ALLOWED_SOURCES` (Default: der Router, `172.17.0.1`).
   - Ein Datei-Lock in `DATA_DIR` verhindert Überlappung.
2. **Docker-Hosts und Dev:** `php bin/monitor.php --loop --interval=300` als eigener Compose-Service, ausserdem `./run.sh monitor` für einen einzelnen Zyklus.

Den Zyklus über einen Prozess *im* PANAG-Container laufen zu lassen, verwerfe ich. Neben Apache bräuchte es dann einen Supervisor, und ein abgestürzter Loop würde von niemandem neu gestartet.

**Ressourcen pro Zyklus:**
- ein REST-Call auf `/interface/wireguard/peers` und wenige SQLite-Schreibzugriffe
- GeoIP-Abfragen nur bei neuer Endpoint-Adresse
- KI-Aufrufe nur für Alarme ab „mittel“, mit Tageslimit

Damit bleibt die Laufzeit innerhalb von `max_execution_time` (Timeouts: KI 20 s, SMTP 10 s, höchstens N Alarme pro Zyklus).

## 5. Erkennung

### 5.1 WireGuard / GeoIP

| ID | Regel | Schwere (Vorschlag) |
|----|-------|---------------------|
| W1 | Endpoint in einem **Land, das für diesen User neu ist** | mittel |
| W2 | Land **ausserhalb der globalen Allowlist** (`MONITOR_ALLOWED_COUNTRIES`) | hoch |
| W3 | **Länderwechsel innerhalb kurzer Zeit**, z. B. CH → US in < 2 h (vereinfachte „Impossible Travel“-Prüfung auf Länderebene) | hoch |
| W4 | Endpoint aus einem **Hosting-, VPN- oder Tor-Netz** (ASN-Liste, optional Tor-Exit-Liste) | mittel |
| W5 | **Endpoint springt** zwischen zwei Adressen hin und her, was auf denselben Schlüssel auf zwei Geräten hindeutet | hoch |
| W6 | **Datenvolumen** (Δrx/Δtx) weit über der Baseline des Peers | mittel |
| W7 | Aktiver **Peer ohne PANAG-User** (`allowed-address` passt zu keinem User) | info (nur Admins) |

**Grenzen:**
- **Polling:** Bei 5 min geht ein Besuch nur verloren, wenn zwischen zwei Abfragen jemand anders verbindet *und* der legitime User sich wieder meldet. `current-endpoint-address` bleibt bis zum nächsten Paket aus anderer Quelle stehen.
- **Ungenauigkeit:** Mobilfunk-Roaming zeigt oft das Heimatland, CGNAT und VPN-Dienste verschleiern den Ort.
- **Auflösung:** Mit Country-Daten ist nur eine Länder-, keine Stadtauflösung möglich.

### 5.2 PANAG-Aktivität

| ID | Regel | Schwere |
|----|-------|---------|
| P1 | ≥ N Fehlversuche in M min (pro User-IP); Rate-Limit erreicht | mittel / hoch |
| P2 | **OTP-Replay blockiert**, d. h. ein Code wurde zweimal benutzt (Hinweis auf Phishing oder abgegriffenen Code) | hoch |
| P3 | Login oder Freigabe zu einer **für den User ungewöhnlichen Zeit** (Baseline) | niedrig |
| P4 | Freigabe eines **Netzes, das der User in 90 Tagen nie genutzt hat**; höher, wenn der Netz-Level nahe am User-Level liegt | mittel |
| P5 | **Viele Einzelfreigaben in kurzer Zeit** (Durchprobieren von Netzen) | mittel |
| P6 | **Sensible Admin-Aktion**: OTP-Reveal oder -Wechsel, Rolle → Admin, Impersonation, User angelegt, Netz-Level geändert | info an alle Admins |
| P7 | **Korrelation:** PANAG-Login kurz nach einem Endpoint-Wechsel in ein neues Land (W1/W3) | Schwere des W-Befunds + 1 |
| P8 | Ungültiger Setup-Token oder Setup-Versuche | hoch |

### 5.3 Baseline pro User

- Rollierend 90 Tage, neu berechnet einmal täglich im Zyklus. Gespeichert wird JSON pro User:
  - Histogramm Wochentag × Stunde (Laplace-geglättet)
  - Netze mit Häufigkeit
  - Länder und ASNs mit „zuletzt gesehen“
  - typische Freigaben pro Tag
  - rx/tx pro Tag
- **Lernphase:** In den ersten 14 Tagen (oder unter 20 Ereignissen) melden nur harte Regeln. Baseline-Befunde werden gesammelt, lösen aber keine Mail aus.
- **Bekannte Orte:** Ein Land gilt als bekannt, wenn ein Admin oder der User es bestätigt hat („Das war ich“). Automatisch gelernt wird es nur innerhalb der Allowlist, nach mehreren Tagen ohne Gegenmeldung.

### 5.4 Bündelung und Lärmschutz

- **Bündelung:** Kandidaten desselben Users innerhalb von 30 min werden zu *einem* Alarm mit Zeitleiste.
- **Dedupe:** gleicher User, gleiche Regel, gleiches Land → 24 h Cooldown.
- **Zustellung nach Schwere:**
  - „hoch“ sofort
  - „mittel“ sofort, aber höchstens eine Mail pro Stunde und Empfänger
  - „niedrig“ und „info“ im Tages-Digest
- **Monitor-Health:** Schlägt das Peer-Polling länger als 30 min fehl, geht eine Mail an die Admins (rate-limitiert).

## 6. GeoIP

- **Daten:** DB-IP „IP to Country Lite“ als MMDB (≈ 8 MB, monatlich aktualisiert, **CC BY 4.0**, Quellenangabe nötig: „IP Geolocation by DB-IP“).
  - Für die ASN-Regel zusätzlich die DB-IP-Lite-ASN-Datenbank; Lizenz und Grösse prüfe ich in Phase 0.
  - Das gleiche Format liest auch MaxMind GeoLite2 (braucht Konto und Lizenzschlüssel).
- **Ablage:** in `/data/geoip/`, nicht im Image. So bleibt das Image klein, und die Daten lassen sich unabhängig vom Release aktualisieren.
  - Monatlicher Download im Zyklus (`GEOIP_AUTO_UPDATE`).
  - Alternativ Upload im Admin-UI für Router ohne Internet-Freigabe.
  - Die Admin-Seite zeigt Version und Datum der Datenbank.
- **Lesen:** MMDB-Reader `maxmind-db/reader`, reines PHP, ohne Extension. Siehe Entscheid zu Runtime-Abhängigkeiten in Kapitel 13.
- **Sonderfälle:**
  - Private Adressen, CGNAT (100.64/10) und Link-Local gelten als „lokal“, ohne Alarm.
  - IPv6 wird unterstützt (MMDB kann beides).
  - Kein Treffer ergibt „unbekannt“, Schwere wie bei einem neuen Land.

## 7. KI-Triage (GLM über OpenRouter)

**Wann:** nur für neue Alarme ab „mittel“, mit Tageslimit (`MONITOR_AI_MAX_CALLS_PER_DAY`, Vorschlag 20). Ist das Limit erreicht, folgt die Vorlagen-Mail.

**Was gesendet wird:** ein pseudonymisierter Merkmalssatz. Feldauswahl per **Allowlist**, nie ein ganzer Log-Eintrag.

```json
{
  "subject": "U-7f3a", "role": "user", "level": 5, "baseline_days": 63,
  "findings": [
    {"rule": "W1", "country": "US", "asn_type": "hosting", "asn_org": "Example Cloud", "known_countries": ["CH", "DE"]},
    {"rule": "P7", "minutes_after_endpoint_change": 4}
  ],
  "timeline": [
    {"t": "-00:04", "event": "wg_endpoint_change", "country": "US"},
    {"t": "00:00", "event": "login_success", "local_hour": 3},
    {"t": "+00:01", "event": "grant_single", "network_level": 5, "network_known": false}
  ],
  "baseline": {"usual_hours": "07-19", "logins_per_week": 9, "grants_per_day": 1.4}
}
```

- **Nicht gesendet** werden Namen, PANAG- und Tunnel-IPs, öffentliche IP-Adressen (nur Land und ASN), Netznamen und alle Freitexte.
- `subject` ist ein HMAC des User-IDs mit einem Secret aus `DATA_DIR`. Es bleibt also über Aufrufe hinweg stabil, ist aber ohne die PANAG-DB nicht auflösbar.
- `asn_org` ist öffentliche Information. Ob es mitgeht, ist in Kapitel 13 offen.

**Was zurückkommt:** JSON nach festem Schema.

```json
{
  "severity": "info|low|medium|high|critical",
  "likely_benign": true,
  "confidence": "low|medium|high",
  "signals": ["new country", "hosting ASN", "login at 03:00"],
  "summary_admin": "≤ 400 Zeichen",
  "summary_user": "≤ 300 Zeichen, Klartext ohne Fachjargon",
  "recommended_action": "none|ask_user|revoke_access|investigate"
}
```

PANAG validiert jede Antwort selbst gegen das Schema; `strict` ist nicht bei jedem Provider garantiert. Massgebend ist danach `severity_final = max(severity_regel, severity_ki)` (siehe Kapitel 3).

**Technik:**
- **Endpoint:** OpenRouter Chat Completions, `POST https://openrouter.ai/api/v1/chat/completions` (OpenAI-kompatibel).
  - Header `Authorization: Bearer <Key>`, optional `HTTP-Referer` und `X-OpenRouter-Title` zur Zuordnung im OpenRouter-Konto.
  - EU-Routing über `https://eu.openrouter.ai/api/v1` braucht einen Business- oder Enterprise-Plan. Laut Modellseite sind für GLM-5.3 nur zwei EU-Provider gelistet (Inceptron, Mistral).
- **Client:** eigener schlanker Client über die schon vorhandene curl-Extension.
  - Kein SDK nötig, also keine Runtime-Abhängigkeit für die KI.
  - Timeout 20 s, ein Retry bei 429 oder 5xx.
- **Modell:** `z-ai/glm-5.3` als Vorschlag, konfigurierbar über `OPENROUTER_MODEL`.
  - Es ist die höchste GLM-Version, die OpenRouter heute listet. Günstigere Varianten wie `z-ai/glm-5.3-flash` vergleiche ich im Eval (Phase 4).
  - Das Modell wird **fest gepinnt**, keine Aliase wie `~z-ai/glm-latest`. Sonst würde das Modell unbemerkt wechseln und die Eval-Ergebnisse gälten nicht mehr.
- **Strukturierte Ausgabe:** `response_format: {type: "json_schema", json_schema: {name, strict: true, schema}}`.
  - Dazu im `provider`-Objekt `require_parameters: true`, damit nur Provider zum Zug kommen, die `response_format` unterstützen. Die Unterstützung ist laut OpenRouter pro Endpoint verschieden.
  - Optional das OpenRouter-Plugin „Response Healing“ gegen kaputtes JSON.
- **Provider-Routing für den Datenschutz:**
  - `data_collection: "deny"`: keine Provider, die Daten speichern oder darauf trainieren.
  - `zdr: true`: nur Zero-Data-Retention-Endpoints.
  - Zusätzlich eine bewusste Auswahl per `only` oder `ignore` (`OPENROUTER_PROVIDERS`). GLM-5.3 wird von etwa 37 Providern angeboten, darunter mehrere mit Sitz in China (Z.ai, Alibaba Cloud, Baidu Qianfan, SiliconFlow). Wohin die Daten gehen dürfen, ist ein Entscheid (Kapitel 13).
  - Dieselben Einstellungen zusätzlich kontoweit in OpenRouter setzen (Privacy-Einstellungen), damit ein Konfigurationsfehler in PANAG sie nicht aushebelt.
- **Kostenschutz:**
  - `provider.max_price` (z. B. Input ≤ 2 $, Output ≤ 6 $ pro Mio. Tokens) sperrt teure Provider.
  - `allow_fallbacks: true` gilt nur innerhalb der erlaubten Provider.
  - Die Preise für GLM-5.3 schwanken je nach Provider stark: Input 0,07–2,80 $, Output 1,40–8,80 $ pro Mio. Tokens; Z.ai selbst 1,40/4,40 $.
  - Bei ~3k Input- und ~0,5k Output-Tokens sind das grob 0,5–1 Rappen pro Aufruf, beim Tageslimit von 20 also höchstens ~20 Rappen pro Tag.
  - Die echten Werte aus `usage` protokolliert PANAG pro Tag.
- **Reasoning:** GLM akzeptiert `reasoning` bzw. `reasoning_effort`. Für die Klassifikation reicht wenig; den Einfluss auf Qualität und Kosten messe ich im Eval. Jeder zusätzliche Parameter verkleinert mit `require_parameters` die Provider-Auswahl.
- **Fehlerpfade:** Fehlerobjekt von OpenRouter, Timeout, `finish_reason` ≠ `stop`, ungültiges JSON oder Schemafehler ergeben das Regel-Ergebnis plus Vorlagen-Mail. PANAG ruft nie den Alarm zurück. Modell und Provider der Antwort werden protokolliert, soweit OpenRouter sie mitliefert.
- **Schlüssel:** `OPENROUTER_API_KEY_FILE` (RouterOS-Mount), wie die übrigen Secrets. Ein eigener Key nur für PANAG, mit Ausgabelimit im OpenRouter-Konto.
- **Lernen aus Rückmeldungen:** Bestätigte Fehlalarme und „Das war ich“-Antworten gehen pseudonymisiert als kurzer Kontext mit („bei diesem Subjekt bisher 3× DE bestätigt“). Ein Modell-Training findet nicht statt.

**Datenschutz:**
- Die Daten gehen an OpenRouter (USA) und von dort an den gewählten Provider, je nach Routing auch an Provider in China. Deshalb gehen nur pseudonymisierte Merkmale raus, ZDR und `data_collection: "deny"` sind Pflicht, und die Provider-Auswahl ist ein bewusster Entscheid.
- Ein Schalter `MONITOR_AI=off` stellt sicher, dass kein Byte das Netz verlässt.

## 8. E-Mail

- **Versand:** SMTP mit STARTTLS/TLS und AUTH über `phpmailer/phpmailer`, kein `mail()` und kein Sendmail im Container.
  - Konfiguration per Env-Variablen (`SMTP_*`, `MAIL_*`, siehe Kapitel 11), einsehbar für Admins auf der Config-Seite.
  - Alternative ohne SMTP-Code in PANAG: RouterOS `/tool/e-mail` über die REST-API nutzt die SMTP-Konfiguration des Routers. Das prüfe ich in Phase 0 (nötige Policies, TLS-Optionen).
- **Empfänger:**
  - Admins mit E-Mail-Adresse, plus `ALERT_ADMIN_EMAILS`.
  - Nach Entscheid zusätzlich der betroffene User („Warst du das?“).
  - Neu sind dafür die Spalten `users.email` und `users.notify_alerts`.
- **Inhalt:**
  - Betreff: Schwere, Kurzbefund, User.
  - Text: was, wann, wo (Land/ASN), warum auffällig (Regeln), KI-Einschätzung falls vorhanden, Link zum Alarm in PANAG (`APP_BASE_URL`, erreichbar nur über VPN).
  - Für User: Links „Das war ich“ / „Das war ich nicht“.
  - Keine Secrets, keine vollständigen Logs.
  - Text-Mail; HTML optional später.
- **Zuverlässigkeit:**
  - Nicht zugestellte Mails bleiben offen (`notified_at IS NULL`) und gehen im nächsten Zyklus erneut raus, höchstens 5 Versuche.
  - Danach erscheint ein Hinweis im Admin-UI.
  - Ein Button „Testmail senden“ steht in `admin/monitoring.php`.

## 9. Datenmodell (Migration 004_monitoring)

| Tabelle / Spalte | Inhalt |
|------------------|--------|
| `users.email`, `users.notify_alerts` | Empfänger und Opt-in |
| `wg_peers` | `public_key` (PK), `user_id`, letzter Endpoint, Land, ASN, `last_handshake_at`, rx, tx, `polled_at` |
| `wg_endpoints` | Historie: Peer, User, IP, Land, ASN, `first_seen`, `last_seen`. **Öffentliche IP nach `MONITOR_IP_RETENTION_DAYS` (Vorschlag 30) entfernt**, Land und ASN bleiben. |
| `user_locations` | bekannte Länder pro User: `source` = `confirmed` / `learned` / `admin`, `first_seen`, `last_seen` |
| `user_baselines` | JSON pro User, `computed_at` |
| `alerts` | `id`, `created_at`, `user_id`, `rules`, `severity`, `dedupe_key`, `summary`, `details_json`, `ai_json`, `status` (`open` / `acknowledged` / `false_positive` / `confirmed` / `resolved`), `status_by`, `status_at`, `notified_at`, `notify_attempts` |
| `alert_events` | Verweise auf `audit_log.id` oder `wg_endpoints.id` (Zeitleiste) |
| `settings` (gibt es schon) | nur Zustand: Cursor `monitor.audit_cursor`, letzter Lauf, GeoIP-Version, KI-Nutzung pro Tag. Einstellungen kommen aus Env-Variablen (Kapitel 11) |

Bestehende Daten bleiben unverändert. Alarme sind Datenschutz-relevant, Vorschlag: Aufbewahrung 12 Monate, dann löschen.

## 10. Oberfläche

- **`admin/alerts.php`:** sortierbare und filterbare Liste (Schwere, Status, User, Regel, Zeitraum). Die Detailansicht zeigt die Zeitleiste, die Regelbefunde und die KI-Einschätzung. Aktionen: Status setzen mit Kommentar, „Land als bekannt bestätigen“, „Alle Freigaben des Users widerrufen“.
- **`admin/monitoring.php`:**
  - Status: letzter Zyklus, Peer-Polling, GeoIP-Datenbank, SMTP, KI-Nutzung heute.
  - Wirksame Einstellungen nur lesend (Allowlist, Schwellen, Lernphase, Transport, Modell), mit Link zur Config-Seite. Geändert wird über Env-Variablen.
  - Aktionen: Testmail, KI-Testaufruf mit Beispieldaten.
  - Quellenangabe DB-IP.
- **`profile.php`:** eigene E-Mail-Adresse, Benachrichtigung an/aus, „Meine bekannten Orte“ (Länder; Entfernen möglich), kurzer Transparenzhinweis, was überwacht wird.
- **Dashboard:** Banner bei offenen Alarmen, die den User betreffen, mit „Das war ich“ / „Das war ich nicht“.
  - „Nicht ich“ widerruft alle aktiven Freigaben des Users und meldet „hoch“ an die Admins (Phase 5).
- **Kommandofeld:** „Go to Alerts“ und „Go to Monitoring“ für Admins.
- **Technik:** alles CSP-konform mit den bestehenden Bausteinen (`table-sort.js`, `Panag.toast`, `data-confirm`).

## 11. Konfiguration

**Grundsatz:** Wie der Rest von PANAG wird auch das Monitoring **ausschliesslich über Env-Variablen** konfiguriert, also RouterOS `/container/envs`, Compose oder `.env`. Secrets gehen alternativ als `*_FILE`.

In der Datenbank liegen nur Daten und Zustand: bekannte Orte, Alarme, Baselines, Cursor. Einstellungen gehören nicht dazu. Damit gibt es eine einzige Quelle der Wahrheit, und ein neu erstellter Container verhält sich gleich wie der alte.

**Einsicht nur für Admins:** `admin/config.php` (Recht `view_config`, nur Admins) zeigt jede Einstellung mit effektivem Wert, Herkunft und Beschreibung. Die Seite gibt es schon für die heutigen Variablen. Folgende Lücken schliesse ich:

| Heute | Neu |
|-------|-----|
| Secrets werden nur nach Namensmuster maskiert (`PASSWORD`, `TOKEN`); ein `OPENROUTER_API_KEY` erschiene im Klartext | Secrets werden bei der Definition explizit markiert und **nie** angezeigt, nur „gesetzt (aus Datei `/…`)“ oder „nicht gesetzt“. Das Namensmuster bleibt als Sicherheitsnetz (`PASSWORD`, `TOKEN`, `SECRET`, `KEY`) |
| Herkunft nur `env` oder `default`; ein Wert aus `*_FILE` ist nicht erkennbar | Herkunft `env`, `env-Datei (Pfad)` oder `Default` |
| Abgeleitete und feste Werte fehlen (`DB_PATH`, `APP_VERSION`, effektive Höchstdauern, `MIN_GRANT_DURATION`), ebenso Container-Variablen ausserhalb von PHP (`APACHE_MAX_WORKERS`, `PHP_DISPLAY_ERRORS`) | eigener Abschnitt „Abgeleitet / fest“, nur lesend |
| eine flache Liste | gruppiert nach Bereich (App, Router, Login, Freigaben, Monitoring, GeoIP, Mail, KI), mit Beschreibung und Default aus einer zentralen Definition; Filter und Sortierung wie bisher |
| ungültige Werte fallen still auf den Default zurück | Warnung beim Start (Log) und auf der Config-Seite. Sicherheitsrelevante Funktionen **schalten sich bei ungültiger Konfiguration ab**, statt auf einen unsicheren Default zu fallen: `SMTP_SECURITY=foo` heisst kein Versand plus Warnung, nicht unverschlüsselt senden |

Status-Prüfungen (Testmail, GeoIP geladen, KI-Testaufruf) bleiben Aktionen in `admin/monitoring.php`. Die Config-Seite zeigt nur Werte und ändert nichts.

**Per Env nicht abschwächbar:** `zdr: true` und `data_collection: "deny"` sind für die KI fest eingebaut. Per Env lassen sich Provider nur weiter einschränken. Das ist dasselbe Prinzip wie bei den Höchstdauern, die man nur senken kann.

**Neue Variablen (Entwurf):**

| Variable | Default | Bemerkung |
|----------|---------|-----------|
| *Monitoring* | | |
| `MONITOR_ENABLED` | `false` | Gesamtschalter |
| `MONITOR_TOKEN[_FILE]` | – | Secret; Header `X-Monitor-Token`; leer = in `DATA_DIR/monitor.token` erzeugt |
| `MONITOR_ALLOWED_SOURCES` | `172.17.0.1` | CIDR-Liste: wer `monitor.php` aufrufen darf |
| `MONITOR_INTERVAL` | `300` | Sekunden, nur für `bin/monitor.php --loop` |
| `MONITOR_ALLOWED_COUNTRIES` | `CH` | ISO-Codes, kommasepariert (Regel W2) |
| `MONITOR_LEARNING_DAYS` | `14` | Lernphase der Baseline |
| `MONITOR_TRAVEL_WINDOW` | `2h` | Fenster für den Länderwechsel (W3) |
| `MONITOR_FAILED_LOGINS`, `MONITOR_FAILED_LOGINS_WINDOW` | `5`, `15m` | Schwelle für P1 |
| `MONITOR_BUNDLE_WINDOW`, `MONITOR_COOLDOWN` | `30m`, `24h` | Bündelung, Dedupe |
| `MONITOR_DIGEST_TIME` | `07:00` | Tages-Digest |
| `MONITOR_NOTIFY_USERS` | `true` | betroffene User mailen (Entscheid 1) |
| `MONITOR_IP_RETENTION_DAYS`, `MONITOR_ALERT_RETENTION_DAYS` | `30`, `365` | Aufbewahrung |
| `APP_BASE_URL` | – | für Links in Mails, z. B. `https://panag.vpn.example` |
| *GeoIP* | | |
| `GEOIP_COUNTRY_DB` | `$DATA_DIR/geoip/country.mmdb` | |
| `GEOIP_ASN_DB` | `$DATA_DIR/geoip/asn.mmdb` | fehlt die Datei, sind die ASN-Regeln aus |
| `GEOIP_AUTO_UPDATE` | `true` | monatlicher Download von DB-IP |
| *Mail* | | |
| `MAIL_TRANSPORT` | `smtp` | `smtp` oder `none` (`routeros` erst, wenn Phase 0 es bestätigt) |
| `SMTP_HOST`, `SMTP_PORT` | –, `587` | |
| `SMTP_SECURITY` | `starttls` | `starttls` oder `tls`; `none` nur mit `APP_ENV=dev` (Mailpit) |
| `SMTP_USERNAME`, `SMTP_PASSWORD[_FILE]` | – | Passwort ist ein Secret |
| `SMTP_TIMEOUT` | `10` | Sekunden |
| `MAIL_FROM`, `MAIL_FROM_NAME` | –, `PANAG` | |
| `ALERT_ADMIN_EMAILS` | – | zusätzlich zu den Admins mit hinterlegter Adresse |
| *KI* | | |
| `MONITOR_AI` | `off` | `off` oder `openrouter` |
| `OPENROUTER_API_KEY[_FILE]` | – | Secret |
| `OPENROUTER_BASE_URL` | `https://openrouter.ai/api/v1` | EU: `https://eu.openrouter.ai/api/v1` |
| `OPENROUTER_MODEL` | `z-ai/glm-5.3` | gepinnt, keine Aliase |
| `OPENROUTER_PROVIDERS` | – | erlaubte Provider (`only`), oder `all` (bzw. `*`) für jeden Provider – Zero Data Retention gilt trotzdem. **Pflicht, wenn die KI aktiv ist:** ohne Wert gibt es keine KI-Aufrufe, sondern eine Warnung |
| `OPENROUTER_MAX_PRICE_PROMPT`, `OPENROUTER_MAX_PRICE_COMPLETION` | `2`, `6` | US-$ pro Mio. Tokens |
| `OPENROUTER_REASONING_EFFORT` | `low` | |
| `MONITOR_AI_MAX_CALLS_PER_DAY`, `MONITOR_AI_TIMEOUT` | `20`, `20` | Aufrufe pro Tag, Sekunden |

**Nicht per Env, weil es Daten sind:** bestätigte Orte pro User (Profil bzw. Admin-UI) und der Alarm-Status. Der Schlüssel für die Pseudonymisierung (HMAC) wird beim ersten Start in `DATA_DIR` erzeugt. Optional lässt er sich per `MONITOR_PSEUDONYM_KEY_FILE` vorgeben; die Config-Seite zeigt nur „vorhanden“.

**Dokumentation:** alle Variablen in `.env.example` und in `docs/deploy-mikrotik.md` (Beispiele für `/container/envs`). Ein Unit-Test prüft, dass jede definierte Variable dort steht und eine Beschreibung hat.

## 12. Ausblick: Heartbeat (nicht im Umfang)

Der Heartbeat an ein Drittsystem folgt später. Der Plan hält ihn nur nicht unnötig auf:
- Der Monitor-Zyklus hat einen Erweiterungspunkt „nach dem Zyklus“.
- Ausgehende HTTP-Aufrufe laufen über einen gemeinsamen Client mit Timeout und Retry.
- Die Egress-Regeln am Router (Kapitel 14) werden dann um ein Ziel ergänzt.

## 13. Offene Entscheide

| # | Frage | Vorschlag |
|---|-------|-----------|
| 1 | Wer wird alarmiert? | Admins immer; der betroffene User zusätzlich bei W1–W5, P2, P7 („Warst du das?“) |
| 2 | Allowlist der Länder | CH + explizit bestätigte Länder pro User; global per `MONITOR_ALLOWED_COUNTRIES` |
| 3 | E-Mail-Weg | eigener SMTP-Relay mit PHPMailer; RouterOS `/tool/e-mail` als Alternative prüfen |
| 4 | Externe KI über OpenRouter | **entschieden:** OpenRouter mit GLM. Nur pseudonymisierte Merkmale, ZDR und `data_collection: "deny"` erzwungen, abschaltbar |
| 5 | GLM-Variante | `z-ai/glm-5.3` gepinnt; `glm-5.3-flash` als günstigere Variante im Eval vergleichen |
| 5a | Erlaubte Provider (wohin dürfen die Daten?) | nur Provider ausserhalb Chinas mit ZDR; wenn der Plan es erlaubt, EU-Routing (`eu.openrouter.ai`, Inceptron/Mistral) |
| 6 | Runtime-Composer-Abhängigkeiten (MMDB-Reader, PHPMailer) | erlauben: `composer install --no-dev` im Image, CI-Grössenbudget bleibt. Das ändert das bisherige Prinzip „Composer nur als Dev-Werkzeug“. Für die KI braucht es kein SDK (eigener curl-Client) |
| 7 | Aufbewahrung | öffentliche Endpoint-IPs 30 Tage, Alarme 12 Monate, Baselines 90 Tage rollierend |
| 8 | Sprache der Mails | Englisch, wie die UI |
| 9 | Automatische Reaktion | keine automatische Sperre; nur „Das war ich nicht“ bzw. Admin-Klick widerruft Freigaben |
| 10 | Hosting-ASN- und Tor-Liste | kleine gepflegte ASN-Liste im Repo plus optional Tor-Exit-Liste (Download im Zyklus) |
| 11 | `asn_org` an die KI | ja (öffentliche Information, hilft bei der Einordnung) |
| 12 | Polling-Intervall | 5 min |

## 14. Betrieb auf dem Router

- **Scheduler:** Die Syntax prüfe ich in Phase 0 gegen RouterOS 7, wie schon in `docs/deploy-mikrotik.md`.

  ```routeros
  /system scheduler add name=panag-monitor interval=5m on-event=":do { /tool fetch \
      url=\"http://172.17.0.2:8080/monitor.php\" http-method=post \
      http-header-field=(\"X-Monitor-Token: \" . [/file/get \"usb1/panag-data/monitor.token\" contents]) \
      output=none } on-error={}"
  ```

- **Egress vom Container**, nur das Nötige: SMTP-Relay (587/465), `openrouter.ai:443` bzw. `eu.openrouter.ai:443` (nur mit KI) und `download.db-ip.com:443` (nur mit Auto-Update). Umsetzung: Address-List mit DNS-Namen plus Forward-Regel.
- **API-User:** Der PANAG-API-User braucht für die Peers nur `read`. Für `/tool/e-mail` kämen zusätzliche Policies dazu, die ich in Phase 0 kläre.
- **Speicher:** GeoIP ≈ 8–16 MB auf USB. SQLite wächst um wenige MB pro Jahr (Retention aktiv).

## 15. Phasen

### Phase 0 – Klärung und Spike (S)
- Am hEX S prüfen:
  - Format von `current-endpoint-address` und `last-handshake` über REST (Sekunden oder `1m12s`; `parse_routeros_duration()` muss beides können).
  - Ausgehende Verbindungen aus dem Container (SMTP, OpenRouter, DB-IP).
  - `/tool/e-mail` über REST.
- Runtime-Abhängigkeiten: Grösse, PHP-Extensions, Lauffähigkeit unter ARMv7.
- OpenRouter: Testaufruf mit `z-ai/glm-5.3`, `response_format` und `require_parameters`, `zdr` und der gewählten Provider-Liste. Prüfen, ob überhaupt ein erlaubter Provider Structured Outputs anbietet.
- Entscheide aus Kapitel 13 treffen.

**Fertig, wenn:** Alle Entscheide in Kapitel 13 getroffen sind und echte Peer-Antworten des Routers als Fixtures vorliegen.

### Phase 1 – Fundament (M)
- Migration 004, E-Mail-Felder im Profil und in `admin/user.php`.
- Config-Seite ausbauen (Kapitel 11): Secrets explizit markiert, Herkunft „env-Datei“, Gruppen und Beschreibungen, abgeleitete und feste Werte, Warnungen bei ungültigen Werten. Neue Variablen in `.env.example`.
- Monitor-Zyklus mit Lock und Cursor, `public/monitor.php`, `bin/monitor.php`, `./run.sh monitor`.
- Mailer und Mailpit im Dev-Compose.
- `alerts`-Tabelle, `admin/alerts.php`, `admin/monitoring.php` (Status, Testmail), Monitor-Health.

**Fertig, wenn:**
- `./run.sh monitor` läuft und ein künstlicher Alarm in der Liste erscheint.
- Die Testmail kommt in Mailpit an.
- `monitor.php` lehnt einen falschen Token und fremde Quell-IPs ab (E2E).
- Mit Dummy-Secrets im Dev-Compose zeigt die Config-Seite „gesetzt“, aber nie einen Secret-Wert. User und Superuser kommen nicht auf die Seite (E2E).

### Phase 2 – WireGuard und GeoIP (M)
- GeoIP-Reader, Datenbank-Verwaltung (Download/Upload, Version, Quellenangabe).
- Peer-Polling, Zuordnung Peer → User, Endpoint-Historie mit Retention.
- Regeln W1–W5 und W7, bekannte Orte, „Das war ich“ (Bestätigen im Dashboard).
- Mock-RouterOS: Endpoints, Handshake und rx/tx über `/_mock/wireguard` setzbar.

**Fertig, wenn:**
- Im E2E-Test löst ein Endpoint-Wechsel auf eine Test-IP ausserhalb der Allowlist innerhalb eines Zyklus einen Alarm und eine Mail aus.
- Ein bekanntes Land löst nichts aus.
- Private und CGNAT-Adressen lösen nichts aus.

### Phase 3 – PANAG-Aktivität (M)
- Baseline-Berechnung, Lernphase, Regeln P1–P8 und W6.
- Bündelung, Dedupe und Cooldown, Zustellung nach Schwere, Tages-Digest.

**Fertig, wenn:**
- Die Unit-Tests mit synthetischen Historien zeigen die erwarteten Befunde.
- Ein OTP-Replay im E2E-Test führt zu einer sofortigen Mail.
- Eine 30-Tage-Demo-Historie ohne Auffälligkeiten erzeugt keine Mail.

### Phase 4 – KI-Triage (M)
- OpenRouter-Client (curl), Pseudonymisierung per Feld-Allowlist, Schema und Prompt, Provider-Routing (ZDR, `data_collection`, Provider-Liste, `max_price`).
- Tageslimit und Nutzungsprotokoll, Fallbacks und Fehlerpfade, Rückmeldungen als Kontext.
- KI-Test im Admin-UI.
- Manuelles Eval-Skript `bin/ai-eval.php` mit gelabelten Beispielfällen, vergleicht GLM-Varianten und Reasoning-Stufen. Es kostet echtes Geld und läuft deshalb nie in der CI.

**Fertig, wenn:**
- Mit `MONITOR_AI=off` verhält sich alles wie in Phase 3.
- Ein Unit-Test belegt, dass kein Request Namen, IPs, Netznamen oder Freitexte enthält.
- Fehlerobjekt, Timeout und ungültiges JSON fallen nachweislich auf die Vorlagen-Mail zurück.
- Jeder Request enthält nachweislich `zdr: true` und `data_collection: "deny"`.
- Ein Regel-„hoch“ wird nie herabgestuft.

### Phase 5 – Rückmeldung und Reaktion (S)
- „Das war ich nicht“ widerruft alle Freigaben des Users und meldet „hoch“ an die Admins.
- Status-Workflow im Admin-UI mit Kommentar.
- Transparenzhinweis im Profil; README und `docs/deploy-mikrotik.md` (Scheduler, Egress, Envs).

**Fertig, wenn:** Der ganze Ablauf vom Alarm über die Mail bis zur Reaktion im E2E-Test durchläuft und die Doku auf dem Gerät nachvollzogen ist.

## 16. Teststrategie

| Ebene | Inhalt |
|-------|--------|
| Unit | Regeln und Baseline mit synthetischen Historien; Bündelung, Dedupe, Cooldown; Pseudonymisierung (keine verbotenen Felder); Schema-Validierung der KI-Antwort; Retention; Konfiguration (jede Variable dokumentiert, ungültige Werte schalten die Funktion ab) |
| Fakes | `FakeGeoIp` (CIDR → Land/ASN), `FakeMailer`, `FakeAiTriage` (Fixtures), `FakeRouterClient` mit Peers |
| Integration | MMDB-Reader gegen eine kleine Test-Datenbank (aus dem MaxMind-DB-Repo, Lizenz prüfen, oder im Dev-Container erzeugt); SMTP gegen Mailpit |
| E2E | Mock-RouterOS ändert Endpoints → Zyklus → Alarm im UI → Mail in Mailpit (Mailpit-API); OTP-Replay; „Das war ich“ / „nicht ich“; Admin-Status-Workflow; Config-Seite zeigt keine Secrets und ist nur für Admins erreichbar; CSP-Test für die neuen Seiten |
| KI-Eval (manuell) | gelabelte Fälle (harmlos/verdächtig); Trefferquote, Fehlalarme und Kosten werden dokumentiert, bevor ein Modell- oder Prompt-Wechsel übernommen wird |

## 17. Risiken

| Risiko | Gegenmassnahme |
|--------|----------------|
| Zu viele Fehlalarme, dann ignoriert man die Mails | Lernphase, bestätigte Orte, Bündelung, Cooldown, Digest für niedrige Schwere, KI-Einordnung |
| GeoIP ungenau (Roaming, CGNAT, VPN-Dienste) | Nur Länderebene, ASN als Zusatzsignal, Bestätigung durch den User statt harter Sperre |
| Prompt-Injection über manipulierte Namen oder Kommentare | Keine Freitexte an die KI; KI kann nicht herabstufen; Schema-Validierung |
| Datenschutz (Überwachung von Mitarbeitenden, Datenweitergabe ins Ausland, GLM-Provider u. a. in China) | Transparenzhinweis, Zweckbindung, Retention, Pseudonymisierung, ZDR und `data_collection: "deny"` pro Request und kontoweit, feste Provider-Liste, KI abschaltbar |
| Ressourcen auf dem hEX S | Ein REST-Call pro Zyklus, GeoIP nur bei Änderung, KI-Tageslimit, Daten auf USB |
| Router-Scheduler fällt aus, Monitoring steht unbemerkt | „Letzter Zyklus“ im Admin-UI und als Banner, wenn älter als 15 min; später der Heartbeat (Kapitel 12) |
| Mail-Versand scheitert | Retry-Queue, Hinweis im Admin-UI, Testmail |
| Kosten der KI | Tageslimit, `max_price`, Ausgabelimit für den OpenRouter-Key, Nutzungsprotokoll |
| Qualität von GLM für diese Aufgabe unbekannt; Provider liefern dasselbe Modell unterschiedlich (Quantisierung, Structured Outputs) | Eval mit gelabelten Fällen vor dem Einschalten, Modell und Provider-Liste gepinnt, Schema-Validierung in PANAG; KI kann ohnehin nur ergänzen, nicht unterdrücken |

## 18. Umsetzungsstand

**Stand 2026-11-07:** Phasen 1–5 sind umgesetzt und grün (Lint inkl. PHPStan Level 5, 137 PHPUnit-, 96 E2E-Tests). Die offenen Entscheide aus Kapitel 13 sind mit dem jeweiligen Vorschlag umgesetzt; ändern lassen sie sich über Env-Variablen.

**Was es gibt:**
- `src/monitor/`: Zyklus (`cycle.php`), Regeln W1–W7, P1–P8 und M1 (`rules.php`), Baseline (`baseline.php`), bekannte Orte (`places.php`), Alarme mit Bündelung, Cooldown und Antworten der User (`alerts.php`), Mails (`mailer.php`, `notify.php`), KI-Triage (`ai.php`), GeoIP (`geoip.php`).
- Auslösung über `public/monitor.php` (Token und Quell-IP) oder `bin/monitor.php [--loop]`; im Dev-Stack `./run.sh monitor`.
- Regelreferenz: Unter der Alert-Liste erklärt die Tabelle *Detection rules* jede Regel (Name, Schwere, Auslöser mit den aktuell konfigurierten Schwellen, ob der User gefragt wird). Die Regelcodes in Liste und Detailansicht verlinken dorthin und zeigen den Namen als Tooltip (`monitor_rule_reference()` in `src/monitor/rules.php`).
- Oberfläche: `admin/alerts.php`, `admin/monitoring.php`, `alert.php` („Warst du das?“), Banner auf dem Dashboard, E-Mail-Adresse und bekannte Orte im Profil, E-Mail im Admin-Tab *Account*, „Alerts“ in der Navigation.
- Konfiguration (Kapitel 11): eine Registry in `src/config.php` mit Gruppe, Beschreibung, Typ und Secret-Kennzeichen; `src/config_checks.php` prüft die Werte (Warnungen beim Start und auf der Config-Seite). Funktionen mit ungültiger Konfiguration schalten sich ab.
- Dev und Test:
  - Mailpit als Mail-Catcher.
  - Der Mock-Router kann Peers verschieben (`/_mock/wireguard`) und bildet OpenRouter nach (`/_ai/v1`).
  - GeoIP-Testdatenbanken für Dokumentations-IP-Bereiche, erzeugt mit `dev/geoip/MmdbWriter.php` und gelesen mit dem echten MaxMind-Reader.
- Runtime-Abhängigkeiten (Entscheid 6): `maxmind-db/reader` und `phpmailer/phpmailer` kommen über eine eigene Build-Stage ins Image (41 MB). Dazu `php84-bcmath`, weil PHP auf arm/v7 32-bit ist und 4-Byte-Werte der MMDB sonst nicht lesbar wären.

**Abweichungen vom Plan:**
- **P7 hängt sich an den zugehörigen Standort-Alarm.** Grund: Wer auf „Warst du das?“ antworten will, muss sich einloggen, und dieser Login löst P7 aus. P7 erzeugt deshalb keinen neuen Alarm und fragt den User nicht erneut. Hat der User den Ort bestätigt, entfällt P7.
- **Gelernte Länder:** Länder innerhalb der Allowlist werden während der Lernphase sofort gelernt. Mit reifer Baseline bleiben sie 3 Tage „pending“ (W1-Alarm) und werden dann gelernt, sofern der User nicht „nicht ich“ geantwortet hat.
- **Keine öffentlichen IPs in Alarmen und Mails:** Alarme werden 365 Tage aufbewahrt, IPs nur 30 Tage. Die IP steht deshalb nur in der Endpoint-Historie und in der Peer-Tabelle von `admin/monitoring.php`.
- **„Hoch“ trotz „Das war ich“:** Ein Alarm wird nach „Das war ich“ auf *acknowledged* gesetzt und nicht geschlossen. Der Admin entscheidet, denn ein Angreifer mit Zugang könnte ebenfalls „Das war ich“ klicken.
- **Nicht umgesetzt:**
  - Tor-Exit-Liste (optional in W4). Die Hosting-ASN-Liste liegt in `src/monitor/hosting_asns.php`, erweiterbar über `MONITOR_HOSTING_ASNS`.
  - Mail über RouterOS `/tool/e-mail` (`MAIL_TRANSPORT=routeros`), bis Phase 0 die REST-Schnittstelle bestätigt.
  - Das manuelle Eval-Skript `bin/ai-eval.php`. Dafür braucht es gelabelte Fälle aus dem Betrieb; bis dahin gibt es den „Test AI“-Button mit einem synthetischen Fall.

**Nach einem unabhängigen Review behoben** (je mit Regressionstest):
- **Ohne Country-Datenbank** wäre jede Verbindung „unbekanntes Land“ gewesen, also W2 für alle. Jetzt sind die Standortregeln dann aus, und die Config-Seite warnt.
- **Erneute Mails:** Ein bereits gemailter Alarm wird erneut gemailt, sobald neue Regeln dazukommen oder der User neu gefragt wird, nicht nur bei höherer Schwere. Auch „Das war ich nicht“ auf einen älteren Alarm geht wieder raus.
- **Keine Frage nach der Antwort:** User, die schon geantwortet haben, werden nicht erneut gefragt. Antworten sind nur möglich, solange der Alarm offen ist und der User gefragt wurde.
- **Bestätigter Vorfall:** Markiert ein Admin einen Vorfall als bestätigt, werden dabei gesehene Länder nicht mehr gelernt.
- **P7 und Polling:** P7 findet auch einen Login, der vor dem nächsten Peer-Polling liegt.
- **KI kann nur erhöhen,** jetzt atomar in SQL. Ändert sich der Alarm während des Aufrufs, kann die KI ihn nicht herabstufen.
- **Peer-Zuordnung:** Peers werden nur über Host-Routen (/32) einem User zugeordnet, nicht über Site-to-Site-Bereiche.
- **32-bit:** Byte-Zähler werden als Float gerechnet; auf 32-bit-PHP blieb W6 sonst bei 2 GiB stehen.
- **UTF-8 ohne mbstring:** Kürzungen sind UTF-8-sicher; die Runtime hat kein mbstring.
- **IP-Retention:** Sie gilt auch für den gespeicherten aktuellen Endpoint und für Peers, die vom Router verschwunden sind.
- **Regeln im Web-UI (2026-11-08, Wunsch des Users):** `admin/rules.php` schaltet Regeln ab, überschreibt die Schwere und ändert Schwellen (`src/monitor/rule_settings.php`, gespeichert in `settings['monitor.rules']`). Die Env-Variablen aus Kapitel 13 (`MONITOR_ALLOWED_COUNTRIES`, `MONITOR_LEARNING_DAYS`, `MONITOR_TRAVEL_WINDOW`, `MONITOR_HOSTING_ASNS`, `MONITOR_FAILED_LOGINS`, `MONITOR_FAILED_LOGINS_WINDOW`) sind nur noch Defaults. Neu einstellbar: W5 (Wechsel/Fenster), W6 (Faktor/Mindest-MB), P5 (Anzahl/Fenster), M1 (Dauer). U1 lässt sich nicht abschalten. Regeländerungen und ein Gesamt-Restore zählen zu P6.

**Offen:**
- **Phase 0 am hEX S:**
  - Format von `current-endpoint-address` und `last-handshake` (der Code akzeptiert Sekunden und `1m12s`).
  - Ausgehende Verbindungen aus dem Container.
  - Scheduler-Syntax.
  - RAM unter Last.
  - Die Peer-Tabelle auf `admin/monitoring.php` zeigt, was RouterOS liefert.
- **OpenRouter:** echter Testaufruf mit der gewählten Provider-Liste (Kapitel 7), insbesondere ob ein erlaubter Provider Structured Outputs anbietet.
- **Heartbeat** (Kapitel 12).

