# PANAG – Modernisierungsplan

Stand: 2026-11-04, überarbeitet nach Rückmeldung · Basis: `main` @ `7f06af4` (V0.1)

## 1. Ziele

| # | Anforderung | Kapitel |
|---|-------------|---------|
| A | Testen ohne MikroTik | 4.1 |
| B | Container-Image, gebaut via GitHub CI | 4.2 |
| C | `run.sh` für lokales Testen; Node/npm/PHP nur in Podman | 4.3 |
| D | Rollen: User / **Superuser** / Admin | 4.4 |
| E | Netzwerk-Zuordnung pro User vereinfachen; Superuser wählen ihre Default-Netze selbst | 4.5 |
| F | Freigabezeiten pro User, selbst konfigurierbar: Default max. 14 h, Sonderfreigabe max. 12 h | 4.6 |
| G | Such-/Kommandofeld: tippen → Auswahl → Pfeiltasten/Maus → Enter/Klick → Freigabe | 4.7 |
| H | Alle Tabellen sortierbar | 4.8 |
| I | Themes pro User: High Contrast, High Contrast Dark, Terminal, Slay, Switzerland, Crazy Colors, Rainbow | 4.9 |

### 1.1 Getroffene Entscheide

| Thema | Entscheid |
|-------|-----------|
| Superuser | Wählt die **eigenen Default-Netze** selbst. Die Sonderfreigabe bleibt für alle wie heute: alle Netze bis zum eigenen Level. |
| Level-Grenze | Gilt auch für Superuser: Wählbar sind nur Netze mit Level ≤ dem eigenen Level. |
| Dauer bei Einzelfreigabe | Wird ein einzelnes Netz freigegeben (Kommandofeld oder Tabelle), gilt **immer die Sonderfreigabe-Dauer** des Users, auch wenn das Netz ein Default-Netz ist. |
| Mindestdauer | 15 min, sowohl für Default als auch für Sonderfreigabe |
| Theme "Slay" | Violett, Gay/Pride-Glam |
| Produktion | RouterOS-Container auf **MikroTik hEX S (E60iUGS)**; Images für ARM64 und ARM32 (`arm/v7`) |
| UI-Sprache | Englisch (bleibt) |

---

## 2. Ist-Analyse

**Stack:** PHP 8 (prozedural, ohne Framework), SQLite via PDO, Bootstrap 5.3 und kjua lokal eingebunden, Vanilla-JS inline in den Seiten, kein Build-Schritt. Etwa 3'300 LOC. Deployment heute: `sync_panag.sh` (rsync auf ein gemountetes Volume, ausgelöst durch VS Code "run on save").

**Was gut ist und bleiben soll:** wenig Abhängigkeiten, CSRF-Token plus Origin-Check, Schutz gegen OTP-Replay, Login-Rate-Limit, Audit-Log, durchgehend Prepared Statements, Backup/Import als JSON.

### 2.1 Probleme (nach Schwere)

| Schwere | Befund | Ort |
|---------|--------|-----|
| 🔴 kritisch | **Kein separater Webroot.** `data/panag.sqlite` (enthält alle OTP-Secrets im Klartext), `data/mock_address_list.json` und `setup-completed.txt` liegen unter dem Document-Root. Es gibt keine `.htaccess`, also ist die DB je nach Webserver per HTTP herunterladbar. | Projektstruktur |
| 🔴 kritisch | **Setup-Flag als Datei im Projekt-Root.** Wird ein Container ohne dieses File neu erstellt, ist `setup.php` wieder offen und jeder Client aus der Login-Whitelist kann sich zum Admin machen. | `config.php:12`, `setup.php` |
| 🟠 hoch | **CI kann nicht funktionieren.** `config/config.php` ist gitignored, also fehlt sie in der CI. Ausserdem stehen `ALLOW_TESTS`/`ALLOW_DEMO_DATA` per Default auf `false`, sodass `create_demo_data.php` mit "Tests are disabled" abbricht. Der Workflow läuft zudem nur manuell. | `.github/workflows/e2e.yml`, `e2e/global-setup.js` |
| 🟠 hoch | **Mock fest im Code verdrahtet.** Jede Router-Funktion enthält `if (is_mock_mikrotik())`. Dadurch wird der HTTP-Client (Auth, TLS-Fingerprint, Fehlerfälle) nie getestet, Timeouts laufen im Mock nie ab, und der Mock funktioniert nur mit `php -S` und Env-Variable. | `lib/functions.php:570ff`, `lib/mock_mikrotik.php` |
| 🟠 hoch | **Client-IP = Benutzeridentität**, ausschliesslich über `REMOTE_ADDR`. Auf dem Router ist das korrekt, solange kein NAT im Spiel ist. Lokal hinter Podman-Port-Forwarding sieht die App aber nur die Gateway-IP, dann funktioniert kein Login. | `login.php:5` |
| 🟠 hoch | **SQLite-Foreign-Keys sind nicht aktiv** (`PRAGMA foreign_keys` fehlt). `ON DELETE CASCADE` greift deshalb nicht, und gelöschte User/Netze hinterlassen verwaiste Zuordnungen. | `lib/functions.php:146` |
| 🟡 mittel | **Keine Migrationen.** Es gibt nur `CREATE TABLE IF NOT EXISTS`, Schemaänderungen sind also heute nicht möglich. | `init_db()` |
| 🟡 mittel | **XSS-Risiko.** `innerHTML` wird mit API- und Router-Daten befüllt (Adressen, Meldungen, Netznamen). | `index.php`, `extendedaccess.php`, `admin/status.php` u. a. |
| 🟡 mittel | **Wiederholte Freigabe verlängert nicht.** Ist ein Eintrag schon vorhanden, wird er übersprungen und der Timeout nicht erneuert. | `functions.php:818` |
| 🟡 mittel | **UX der Sonderfreigabe:** Die Checkboxen sind mit bereits freigegebenen Netzen vorbelegt, Abwählen widerruft aber nichts. Es gibt nur "alles widerrufen", keinen Widerruf pro Eintrag. Restzeit und Ablaufzeitpunkt sind nicht verständlich dargestellt. | `extendedaccess.php` |
| 🟡 mittel | **User-Verwaltung:** Alle User werden auf einer Seite als vollständige Formulare inkl. OTP-Secret im HTML gerendert, dazu pro User Checkboxen für alle Netze. Stammdaten und Netze werden nur gemeinsam gespeichert. Es gibt keine Suche, und man sieht nicht, welche User ein bestimmtes Netz als Default haben. Default-Netze über dem Level des Users lassen sich setzen, werden beim Freigeben aber still übersprungen. | `admin/config_user.php` |
| 🟡 mittel | **Impersonation ohne Rückweg.** `impersonator_id` wird gesetzt, aber nirgends ausgewertet. Die UI zeigt die Impersonation nicht an. | `admin/config_user.php:30` |
| 🟡 mittel | **Config nur als PHP-`const`**, nicht über Env-Variablen steuerbar, also nicht container-tauglich. `config_constants.php` liest `config.php` per Regex aus. | `config/`, `admin/config_constants.php` |
| ⚪ niedrig | Ungültiges HTML: `<form>` direkt in `<tr>` (funktioniert nur zufällig). | `admin/config_networks.php:99` |
| ⚪ niedrig | `login.php` lädt Bootstrap-JS vom CDN, entgegen dem Offline-Anspruch. | `login.php:106` |
| ⚪ niedrig | `isadmin` ist nur 0/1. Rollenprüfungen (`(int)$user['isadmin'] === 1`) sind über ~10 Stellen verstreut. | diverse |
| ⚪ niedrig | Dauern als globale Konstanten (`DEFAULT_TIMEOUT` 1 h, `EXTENDED_TIMEOUT` 15 min). | `config.php:30` |
| ⚪ niedrig | Kein Unit-Test. `test/` enthält Web-Tools, die über `ALLOW_TESTS` erreichbar sind. Doppelte `main.css` (Root und `css/`), `img/.DS_Store` ist eingecheckt. | |

---

## 3. Zielbild

```
panag/
├── public/                 # einziger Webroot
│   ├── index.php  login.php  logout.php  api.php  profile.php  healthz.php
│   ├── admin/  (users.php, user.php, networks.php, matrix.php, logs.php, status.php, config.php)
│   ├── css/  css/themes/*.css   js/ (app.js, palette.js, table-sort.js, …)   img/
├── src/                    # nicht per HTTP erreichbar
│   ├── bootstrap.php  config.php (env-basiert)  db.php  migrations/
│   ├── auth.php  roles.php  access.php  durations.php  themes.php  client_ip.php
│   └── router/ RouterClient.php  RestRouterClient.php
├── bin/                    # CLI: migrate.php, seed-demo.php, create-admin.php, otp.php
├── data/                   # Volume/Mount: panag.sqlite, backups/
├── dev/mock-routeros/      # Fake-RouterOS-REST-API (eigener Container)
├── docker/                 # httpd.conf, php.ini, entrypoint.sh
├── tests/unit/  tests/e2e/
├── Dockerfile  compose.yml  compose.dev.yml  run.sh
└── .github/workflows/ci.yml
```

Prinzipien:
- Leichtgewichtig bleiben: kein Framework, kein JS-Build. Composer und npm nur als Dev-Werkzeuge im Container.
- Konfiguration über Env-Variablen, Secrets optional über `*_FILE`-Variablen, die auf eine Datei zeigen (sinnvoll mit RouterOS-Mounts).
- Die App hat genau einen Router-Zugang (`RouterClient`). Ob dahinter ein echter MikroTik oder der Mock steht, entscheidet allein `MIKROTIK_BASE_URL`.

---

## 4. Umsetzung pro Anforderung

### 4.1 Testen ohne MikroTik

Vorgehen in drei Stufen:

**Stufe 1: Router-Abstraktion (Pflicht)**
- `src/router/RouterClient.php` als Interface: `listAddressEntries(?string $list)`, `addAddressEntry(list, address, comment, timeoutSec)`, `setTimeout(id, sec)`, `removeEntry(id)`, `identity()`, `clock()`, `resource()`, `wireguardPeers()`.
- `RestRouterClient` übernimmt den bestehenden curl-Code aus `mikrotik_request()`, inkl. Fingerprint-Pinning. Filter laufen serverseitig über `?list=…`, statt die ganze Address-List zu laden. Auf dem kleinen Router spart das CPU.
- Sämtliche `is_mock_mikrotik()`-Zweige und `lib/mock_mikrotik.php` werden entfernt.
- Für PHPUnit gibt es `FakeRouterClient` (in-memory).

**Stufe 2: Mock-RouterOS als eigener Container (Pflicht)**
`dev/mock-routeros/` ist eine kleine PHP-App, die den von PANAG genutzten Teil der RouterOS-REST-API nachbildet:

| Endpoint | Verhalten |
|----------|-----------|
| `GET/PUT /rest/ip/firewall/address-list` | Liste (mit `?list=` als Filter) bzw. Eintrag anlegen; `.id` im Format `*1A`, `dynamic=true` |
| `GET/PATCH/DELETE /rest/ip/firewall/address-list/{id}` | Eintrag lesen, Timeout ändern, löschen |
| `GET /rest/system/identity`, `/system/clock`, `/system/resource` | statische bzw. Live-Werte |
| `GET /rest/interface/wireguard/peers` | Seed-Daten aus JSON |
| `POST /_mock/reset`, `GET /_mock/state`, `POST /_mock/fault` | Teststeuerung: zurücksetzen, Zustand prüfen, Fehler einschleusen (500, 401, Timeout, Latenz) |

- **Timeouts laufen echt ab.** Der Mock speichert `expires_at` und liefert die Restzeit im RouterOS-Format (`59m58s`). Abgelaufene Einträge verschwinden.
- Basic-Auth wird geprüft. Optional HTTPS mit selbstsigniertem Zertifikat, um das Fingerprint-Pinning zu testen.
- Damit läuft die App lokal, in E2E-Tests und in der CI exakt wie in Produktion, nur mit `MIKROTIK_BASE_URL=http://mock-routeros:8080/rest`.

**Stufe 3: Echter RouterOS CHR (optional, später)**
Ein nightly oder manueller CI-Job startet RouterOS CHR (Cloud Hosted Router) in QEMU und führt die Integrationstests des `RestRouterClient` dagegen aus. So bemerkt man, wenn der Mock vom echten Verhalten abweicht.

### 4.2 Container für MikroTik und GitHub CI

**Zielplattform:** RouterOS-Container auf einem hEX S (E60iUGS). Daraus folgt:
- Gebaut werden Images für `linux/arm64` und `linux/arm/v7`, zusätzlich `linux/amd64` für CI und lokale Entwicklung (Multi-Arch-Manifest).
- Flash und RAM des Routers sind knapp. Das Image muss klein sein und sparsam laufen. Die genauen Gerätewerte prüfe ich zu Beginn von Phase 0. **Ziel: Image < 50 MB, RAM im Leerlauf < 64 MB.**
- RouterOS-Container kennt kein Compose und ignoriert `HEALTHCHECK`. Die Konfiguration läuft über `/container/envs`, die Daten über `/container/mounts`.

**Image (`Dockerfile`)**
- **Basis Alpine statt `php:8.4-apache-bookworm`**: Debian ist um ein Mehrfaches grösser. Verwendet werden die Alpine-Pakete `apache2` mit `mod_php` (php84) und nur die nötigen Extensions (u. a. `pdo_sqlite`, `curl`, `openssl`, `session`). Es läuft ein einziger Prozess, ein Supervisor ist nicht nötig. Weil fertige Pakete statt kompilierter Builds verwendet werden, bleiben die ARM-Builds unter QEMU schnell.
- Apache wird knapp dimensioniert: `prefork` mit `StartServers 1` und `MaxRequestWorkers` 4–6, PHP mit `memory_limit 64M` und kleinem OPcache.
- `DocumentRoot /var/www/html/public`, Listen auf `8080`, Betrieb als Nicht-Root-User.
- `entrypoint.sh` prüft die Rechte auf `/data`, sichert die DB vor einer Migration nach `data/backups/` (nur die letzten N Sicherungen, wegen des knappen Speichers) und führt dann `bin/migrate.php` aus. Danach startet `httpd -DFOREGROUND`. Logs gehen nach stdout/stderr und landen so mit `logging=yes` im RouterOS-Log.
- `healthz.php` prüft die DB; mit `?deep=1` zusätzlich den Router. RouterOS-Netwatch kann den Endpoint per `http-get` überwachen.
- Produktions-`php.ini` (`expose_php=Off`, Session-Cookies `HttpOnly`, `SameSite=Strict`, `Secure` bei HTTPS).
- Security-Header: CSP, `X-Frame-Options`, `Referrer-Policy`.
- `.dockerignore` hält `e2e/`, `tests/`, `node_modules/`, `docs/`, `dev/` und `.git` aus dem Image heraus.

**Netzwerk auf dem Router**
- Der Container hängt über ein `veth` an einer Container-Bridge (z. B. `172.17.0.0/24`, Router = `172.17.0.1`, wie in der heutigen Config).
- WireGuard-Clients werden **ohne NAT** zum Container geroutet. Dann ist `REMOTE_ADDR` die echte Client-IP. **Bedingung:** keine `masquerade`/`srcnat`-Regel für Verkehr ins Container-Netz. `TRUSTED_PROXIES` bleibt in Produktion leer.
- `MIKROTIK_BASE_URL=https://172.17.0.1/rest`: Die App spricht den Router an, auf dem sie selbst läuft.
- **Härtung:**
  - eigener RouterOS-User für PANAG in einer Gruppe mit minimalen Policies (`read`, `write`, `rest-api`)
  - Service `www-ssl` nur für die Container-IP freigeben
  - HTTPS mit Fingerprint-Pinning
- Daten (`/data`) liegen auf einem externen Speicher (USB/microSD), falls vorhanden, sonst intern. SQLite schreibt wenig (Logins, Audit-Log). WAL-Modus und Pruning bleiben aktiv.

**Auslieferung auf den Router (zwei Wege)**
1. **Pull aus der Registry:** RouterOS lädt `muqiuq/panag:<tag>` von `ghcr.io` (`registry-url`) und wählt die passende Architektur selbst.
2. **Offline:** Die CI hängt an jedes Release `panag-<version>-arm64.tar` und `panag-<version>-armv7.tar` an. Die Datei wird auf den Router hochgeladen und mit `/container add file=…` installiert.

Skizze der RouterOS-Konfiguration. Ausgearbeitet wird sie in Phase 5 im README; die Syntax vorher gegen die aktuelle RouterOS-7-Doku prüfen, weil sich Parameternamen zwischen Versionen geändert haben:

```routeros
/interface/veth add name=veth-panag address=172.17.0.2/24 gateway=172.17.0.1
/interface/bridge add name=br-containers
/ip/address add address=172.17.0.1/24 interface=br-containers
/interface/bridge/port add bridge=br-containers interface=veth-panag
/container/config set registry-url=https://ghcr.io tmpdir=usb1/tmp
/container/envs add name=panag key=MIKROTIK_BASE_URL value=https://172.17.0.1/rest
/container/mounts add name=panag-data src=usb1/panag-data dst=/data
/container add remote-image=muqiuq/panag:latest interface=veth-panag envlist=panag \
    mounts=panag-data root-dir=usb1/panag start-on-boot=yes logging=yes
```

**Konfiguration (Env-Variablen, Auszug)**

| Variable | Default | Bemerkung |
|----------|---------|-----------|
| `APP_ENV` | `production` | `dev` aktiviert den IP-Switcher (4.3) |
| `APP_TIMEZONE` | `Europe/Zurich` | |
| `DATA_DIR` | `/data` | DB, Backups |
| `MIKROTIK_BASE_URL`, `MIKROTIK_USERNAME`, `MIKROTIK_PASSWORD[_FILE]`, `MIKROTIK_CERT_FINGERPRINT` | – | |
| `LOGIN_IP_WHITELIST` | private Netze | kommasepariert, z. B. WireGuard-Netz |
| `TRUSTED_PROXIES` | leer | CIDRs, für die `X-Forwarded-For` ausgewertet wird (nur Dev/CI) |
| `MAX_DEFAULT_DURATION` / `MAX_EXTENDED_DURATION` | `14h` / `12h` | dürfen tiefer, nie höher gesetzt werden |
| `SETUP_TOKEN` | leer | optional zusätzlicher Schutz für die Ersteinrichtung |

- Das Setup-Flag entfällt. **Setup ist nur möglich, solange in der DB kein Admin existiert** (optional zusätzlich mit `SETUP_TOKEN`). Alternativ per CLI: `bin/create-admin.php`.
- `compose.yml` und `compose.dev.yml` dienen nur der lokalen Entwicklung und der CI. Für normale Docker-Hosts bleibt `compose.yml` als Beispiel nutzbar.

**GitHub Actions (`.github/workflows/ci.yml`, ersetzt `e2e.yml`)**

| Job | Trigger | Inhalt |
|-----|---------|--------|
| `lint` | push, PR | `php -l` auf allen Dateien, PHPStan (Level 5), `shellcheck run.sh` |
| `unit` | push, PR | PHPUnit im PHP-Container |
| `e2e` | push, PR | amd64-Image bauen, `docker compose -f compose.yml -f compose.dev.yml up`, Playwright im offiziellen `mcr.microsoft.com/playwright`-Image, `playwright-report` als Artefakt |
| `arm-smoke` | push, PR | Images für `arm64` und `arm/v7` mit QEMU und Buildx bauen. Unter Emulation starten und `/healthz.php` abfragen. Bricht ab, wenn ein Image über 50 MB gross ist. |
| `publish` | `main` und Tags `v*`, benötigt alle oben | Multi-Arch `linux/amd64,linux/arm64,linux/arm/v7` nach `ghcr.io/muqiuq/panag`. Tags per `docker/metadata-action`: `sha-…`, `edge` für main, Semver für Tags, `latest`. GHA-Cache. |
| `release` | Tags `v*` | Pro ARM-Architektur ein Image-Tar als Asset am GitHub-Release; prüft, ob `VERSION` zum Tag passt |
| `chr` (optional) | nightly / manuell | Stufe 3 aus 4.1 |

Ergänzend: Dependabot für Actions und npm, optional ein Trivy-Scan des Images.

### 4.3 `run.sh` – alles in Podman

Auf dem Host werden weder PHP noch Node noch npm benötigt. `run.sh` erkennt `podman` automatisch (Fallback `docker`, überschreibbar mit `CONTAINER_ENGINE=docker`) und startet bei Bedarf die Podman-Machine. Compose läuft über `podman compose`; als Provider dient das bereits installierte `docker-compose`.

```text
./run.sh up            # Images bauen, App + Mock-RouterOS starten → http://localhost:8080 (Demo-Daten)
./run.sh down          # stoppen
./run.sh reset         # Volumes löschen, Demo-Daten neu einspielen
./run.sh logs [svc]    # Logs folgen
./run.sh otp [secret]  # aktuellen TOTP-Code der Demo-User ausgeben (Login ohne Handy)
./run.sh test          # lint + unit + e2e, alles in Containern
./run.sh unit | e2e | lint
./run.sh e2e --update-snapshots
./run.sh report        # Playwright-HTML-Report ausliefern
./run.sh shell [svc]   # Shell im Container
./run.sh npm …         # npm im Node-Container (node_modules in eigenem Volume, nicht auf dem Host)
./run.sh composer …    # Composer im PHP-Container
./run.sh build [arch]  # Produktions-Image bauen: amd64 | arm64 | armv7
./run.sh export <arch> # Image als .tar für den Upload auf den Router (arm64 | armv7)
```

- **Dev-Modus:** Der Quellcode wird per Bind-Mount eingebunden, Änderungen sind also ohne Rebuild sofort sichtbar. Der Mock-Router hat einen eigenen Zustand im Volume.
- **Client-IP lokal:** Aus dem Browser auf dem Host kommen alle Requests mit der Gateway-IP der Podman-VM an. Deshalb gibt es bei `APP_ENV=dev` im Footer einen **IP-Switcher**: einen Cookie, der nur im Dev-Modus ausgewertet wird und beim Start eine laute Warnung ins Log schreibt. Damit kann man sich als `127.0.0.1` (Admin), `10.0.0.2` (User) oder `10.0.0.3` (Superuser) einloggen.
- **E2E:** Playwright läuft im selben Compose-Netz und setzt pro Test `X-Forwarded-For`. In `compose.dev.yml` ist `TRUSTED_PROXIES` auf das Dev-Netz gesetzt. So lassen sich alle drei Rollen getestet abdecken.
- Das lokale `node_modules/` sowie `sync_panag.sh` und der Run-on-save-Task in `.vscode/` werden entfernt.

### 4.4 Rollen: User / Superuser / Admin

`users.isadmin` wird zu `users.role` (`user` | `superuser` | `admin`). Alle Prüfungen laufen zentral über `can(array $user, string $permission): bool` in `src/roles.php`.

| Berechtigung | User | Superuser | Admin |
|--------------|:----:|:---------:|:-----:|
| "Grant default access" (eigene Default-Netze) | ✓ | ✓ | ✓ |
| Sonderfreigabe für alle Netze ≤ eigener Level | ✓ | ✓ | ✓ |
| Eigene Freigaben einzeln verlängern oder widerrufen | ✓ | ✓ | ✓ |
| Eigene Freigabezeiten und eigenes Theme einstellen | ✓ | ✓ | ✓ |
| **Eigene Default-Netze selbst wählen** (nur Netze ≤ eigener Level) | – | ✓ | ✓ |
| Default-Netze anderer User, User und Netze verwalten, Logs, Status, Config, Impersonation | – | – | ✓ |

- Ein Superuser kann weder Rolle noch Access-Level selbst ändern.
- Impersonation bekommt ein Banner ("You are acting as X – back to admin") und einen Rückweg über `impersonator_id`. Start und Ende werden geloggt.

### 4.5 Netzwerk-Zuordnung

**Modell.** Der Kern bleibt wie heute:
- **Default-Netze:** eine explizite Liste pro User (Tabelle `user_to_network`). "Grant default access" gibt alle diese Netze frei.
- **Sonderfreigabe:** Freigebbar sind alle Netze mit `network.accesslevel ≤ user.accesslevel`. Das bleibt unverändert und muss nicht gepflegt werden.
- **Wer die Default-Liste pflegt:** bei Usern der Admin, bei Superusern sie selbst (der Admin weiterhin auch), bei Admins sie selbst.
- **Neu ist eine serverseitige Regel:** Ein Netz lässt sich nur als Default speichern, wenn der Level des Users dafür reicht. Wird der Level eines Users später gesenkt, markiert die Admin-UI die betroffenen Default-Netze als ungültig. Beim Freigeben werden sie wie heute übersprungen, aber mit sichtbarem Hinweis.

**Neu für Admins**
- `admin/users.php`: sortierbare und filterbare Tabelle (Name, IP, Rolle, Level, #Default-Netze, letzter Login, aktive Freigaben, Aktionen). Die heutigen Formular-Kacheln fallen weg, OTP-Secrets stehen nicht mehr im HTML.
- `admin/user.php?id=…` mit Tabs **Account · Default networks · Durations · OTP**. Secret und QR erscheinen erst nach Klick auf "Reveal", das wird geloggt. Jeder Tab speichert für sich.
- **Tab Default networks:**
  - Liste der Netze ≤ Level des Users mit Suchfeld und einem Schalter pro Zeile.
  - Jede Änderung wird sofort per API gespeichert (Toast, Audit-Log-Eintrag).
  - Filter "only selected", Bulk-Aktionen "select all / none".
  - Netze über dem Level sind ausgeblendet; "show all" zeigt sie ausgegraut mit dem nötigen Level im Tooltip.
- `admin/matrix.php`: Matrix User × Netze mit fixierten Kopfzeilen. Ein Klick auf eine Zelle schaltet "Default" ein oder aus. Zellen, für die der Level nicht reicht, sind gesperrt. Filter für User und Netze. Gedacht für den Überblick und für Massenänderungen.
- `admin/networks.php`: Spalte "Default for N users". Ein Klick öffnet einen Dialog mit allen berechtigten Usern und Checkboxen (umgekehrte Sicht), z. B. um ein neues Netz in einem Schritt bei fünf Usern als Default einzutragen. Netze werden im Dialog bearbeitet statt per Inline-Formular in `<tr>`.

**Superuser:** Dieselbe Komponente "Default networks" erscheint auf `profile.php`, beschränkt auf den eigenen User und den eigenen Level. Die API prüft serverseitig `can($user, 'edit_own_default_networks')` und den Level. Für andere User liefert sie 403.

**User:** sehen ihre Default-Netze auf `profile.php` nur lesend, mit dem Hinweis "Managed by your admin".

### 4.6 Freigabezeiten pro User

- Neue Spalten `users.default_duration_sec` und `users.extended_duration_sec`. Startwerte für bestehende und neue User: 1 h bzw. 15 min (die heutigen Konstanten).
- **Grenzen:** Default von 15 min bis 14 h, Sonderfreigabe von 15 min bis 12 h. Die Obergrenzen lassen sich per Env tiefer setzen, nie höher. **Die Validierung erfolgt serverseitig** (HTTP 422 mit Meldung), nicht nur im UI.
- **UI auf `profile.php`:** Preset-Chips 15 min, 30 min, 1 h, 2 h, 4 h, 8 h, 12 h (für Default zusätzlich 14 h) plus Freifeld `h:mm`. Daneben steht live "valid until approx. 22:15".
- **Welche Dauer gilt:**

| Aktion | Dauer |
|--------|-------|
| "Grant default access" | Default-Dauer des Users, für alle Default-Netze |
| Einzelnes Netz freigeben (Kommandofeld oder Tabelle), auch wenn es ein Default-Netz ist | Sonderfreigabe-Dauer des Users |

- **Verlängern statt "Already present":** Ist ein Netz bereits aktiv, setzt eine erneute Freigabe den Timeout neu (`PATCH timeout`). **Eine Verlängerung kürzt nie:** Der neue Timeout ist das Maximum aus Restzeit und neuer Dauer. Eine aktive Default-Freigabe mit 10 h Restzeit wird also durch eine Einzelfreigabe von 15 min nicht verkürzt.
- Der Kommentar am Address-List-Eintrag lautet `PANAG default: <net>` bzw. `PANAG ext: <net>`, damit das UI den Typ anzeigen kann.
- "Active access" zeigt Restzeit, Ablaufzeitpunkt und Typ sowie pro Eintrag die Buttons **Extend** und **Revoke**.
- `src/durations.php` wandelt Sekunden in das RouterOS-Format `HH:MM:SS` um und liest RouterOS-Restzeiten (`1d2h3m4s`) ein. Beides ist per Unit-Test abgedeckt.
- Optional: Dauer direkt im Kommandofeld angeben (`dc 2h` gibt Datacenter für 2 h frei, innerhalb der Grenzen).

### 4.7 Such- und Kommandofeld

Das Feld steht prominent oben auf dem Dashboard und ist automatisch fokussiert. Auf jeder Seite öffnet `/` oder `Ctrl/Cmd+K` es als Overlay.

**Ablauf:**
1. Tippen: Die Trefferliste erscheint und filtert live; noch ist nichts ausgewählt.
2. `Enter` oder `↓` markiert den ersten Treffer.
3. Mit `↑`/`↓` oder per Maus-Hover wählen.
4. `Enter` oder Klick gibt frei; `Esc` schliesst.

Weil die erste Eingabe von `Enter` nur markiert, löst ein versehentliches Enter keine Freigabe aus. Danach erscheint ein Toast ("VPN granted until 16:45"), die Liste der aktiven Freigaben aktualisiert sich, und das Feld leert sich für die nächste Eingabe. Die künstliche Wartezeit von 1 s mit Vollbild-Spinner entfällt.

**Treffer:**
- Alle Netze ≤ Level des Users, gesucht nach Name und Adresse, mit Präfix-Ranking. Default-Netze tragen ein Badge "Default". Freigegeben wird immer mit der Sonderfreigabe-Dauer (siehe 4.6).
- **IP-Suche:** Die Eingabe `10.10.0.5` findet das Netz `10.10.0.0/24`, in dem die Adresse liegt.
- Jeder Treffer zeigt Name, CIDR, Badge und Status ("active, 42 min left"). Enter auf ein aktives Netz verlängert es.
- Befehle: "Grant default access", "Revoke all my access", "Theme: …", "Set durations". Für Admins zusätzlich "Find user …" (springt zu `admin/user.php`) sowie "Go to Logs / Networks / Status".

**Technik:**
- `public/js/palette.js` in Vanilla-JS. Die Daten kommen einmalig über `api.php?f=palette` (Netze, Default-Markierung, Status), das Filtern passiert clientseitig.
- Barrierefrei nach dem WAI-ARIA-Combobox-Pattern (`role=combobox`, `listbox`/`option`, `aria-activedescendant`).
- Ausgaben nur per `textContent`, kein `innerHTML` mit Daten.

`extendedaccess.php` fällt weg. Darunter auf dem Dashboard bleibt als Fallback eine sortierbare Tabelle "All networks" mit einem Grant-Button pro Zeile. Netze über dem Level erscheinen dort wie heute ausgegraut.

### 4.8 Sortierbare Tabellen

- `public/js/table-sort.js` (Vanilla, ~120 LOC) greift für jede `<table data-sortable>`. Ein Klick auf `<th>` sortiert auf- bzw. absteigend, gesetzt wird `aria-sort`, die Bedienung per Tastatur ist möglich.
- Typen: Text (`localeCompare` mit `numeric: true`), Zahl, **IP/CIDR** (numerisch nach Oktetten), Datum und Dauer über `data-sort-value`.
- Die zuletzt gewählte Sortierung wird pro Tabelle in `localStorage` gemerkt. Optional ein Filterfeld pro Tabelle.
- **Audit-Log** ist serverseitig paginiert und wird deshalb serverseitig sortiert (`?sort=created_at&dir=desc`, Spalten per Whitelist). Der Tabellenkopf sieht gleich aus wie bei den anderen Tabellen.
- Betroffene Tabellen: All networks, Active access, Users, Networks, Matrix, Logs, Config, Status (heute eingeloggte User, WireGuard-Peers), Users Overview.

### 4.9 Themes

| Theme | Charakter |
|-------|-----------|
| `default` | heutiges PANAG-Rot |
| `high-contrast` | Schwarz auf Weiss, Kontrast ≥ 7:1 (WCAG AAA), dicke Fokusrahmen, unterstrichene Links, keine Schatten oder Verläufe |
| `high-contrast-dark` | Weiss/Gelb auf Schwarz, sonst wie oben |
| `terminal` | schwarzer Hintergrund, grüne Monospace-Schrift, Überschriften im Prompt-Stil (`$ panag grant`), ASCII-Logo auf dem Login, optional Scanlines |
| `slay` | **Violett als Leitfarbe**, Gay/Pride-Glam: Violett-Verläufe, Pride-Streifen als Akzent (Navbar-Unterkante, Fokusrahmen), Glitzer ✨, runde, fette Buttons. Anders als `rainbow`: violett dominiert, Regenbogen nur als Akzent. |
| `switzerland` | Rot #FF0000 und Weiss, Schweizerkreuz im Logo, Helvetica-artige Schrift, strenges Raster, flach |
| `crazy-colors` | stark gesättigt, pro Karte eine eigene Akzentfarbe, verspielte Schatten |
| `rainbow` | voller Regenbogen-Verlauf in Navbar und Buttons, animierter Hue-Shift |

**Technik:**
- Pro Theme eine Datei `public/css/themes/<name>.css`, gescoped auf `[data-theme="<name>"]`. Sie überschreibt die **Bootstrap-5.3-CSS-Variablen** (`--bs-body-bg`, `--bs-primary`, `--bs-primary-rgb`, `--bs-border-color`, …). Dunkle Themes setzen zusätzlich `data-bs-theme="dark"`.
- Vorarbeit: Hart codierte Klassen und Inline-Styles (`bg-danger` in der Navbar, `bg-light`, `text-dark`, `style="…"`) werden durch semantische Klassen ersetzt (`.app-navbar`, `.stat-tile`, `.card-extended`), damit Themes sie stylen können.
- Gespeichert wird in `users.theme`. `header.php` setzt `data-theme` serverseitig, also ohne Aufflackern. Ein unkritisches Cookie `panag_theme` spiegelt den Wert, damit auch die Login-Seite im gewählten Theme erscheint.
- Die Option **"System (auto)"** wählt `high-contrast`, wenn `prefers-contrast: more` gesetzt ist. Alle Animationen respektieren `prefers-reduced-motion`.
- Auswahl auf `profile.php` mit Vorschaukacheln und Live-Vorschau, ausserdem über das Kommandofeld ("Theme: rainbow").
- Tests: Ein Playwright-Screenshot pro Theme dient als visueller Smoke-Test, `@axe-core/playwright` prüft die Kontraste der beiden HC-Themes.

---

## 5. Datenmodell und Migrationen

- **Migrationssystem:** `src/migrations/NNN_name.php`, Stand über `PRAGMA user_version`. Läuft beim Container-Start (`bin/migrate.php`); vorher wird die DB nach `data/backups/` gesichert (rollierend).
- **Pro Verbindung:** `PRAGMA foreign_keys = ON`, `journal_mode = WAL`, `busy_timeout = 5000`.

| Migration | Inhalt |
|-----------|--------|
| 001_baseline | heutiges Schema, idempotent |
| 002_roles_prefs | `users.role` (aus `isadmin`), `default_duration_sec` (3600), `extended_duration_sec` (900), `theme` (`default`); Tabelle `settings` (key/value) |
| 003_cleanup | verwaiste Zeilen in `user_to_network`/`otp_used` entfernen, `isadmin` entfernen (in SQLite per Neuaufbau der Tabelle) |

- Export/Import nach JSON nimmt die neuen Felder auf (`role`, Dauern, Theme). **Der Import bleibt mit dem alten Format kompatibel** (`isadmin` → `role`).
- Optional: Der User-Export enthält auch die Default-Netze, referenziert über Name und Adresse.
- Ein Unit-Test migriert eine Fixture-DB im heutigen Schema und prüft das Ergebnis.

---

## 6. Phasen

Die Reihenfolge ist so gewählt, dass zuerst die Testbarkeit steht und alles Weitere abgesichert entwickelt werden kann.

### Phase 0 – Fundament (Aufwand L)
1. Aufteilung in `public/` und `src/`, Env-Config, `DATA_DIR`, Setup-Sperre über die DB statt Flag-Datei, Client-IP-Ermittlung mit `TRUSTED_PROXIES`.
2. `RouterClient` mit `RestRouterClient`, Mock-Zweige entfernen, `dev/mock-routeros/`.
3. Alpine-`Dockerfile`, `compose.yml`, `compose.dev.yml`, `run.sh` (inkl. `otp`, `export`, IP-Switcher).
4. `bin/seed-demo.php` statt der Web-Testseiten, `test/` entfernen, bestehende E2E-Tests reparieren, PHPUnit-Grundgerüst.
5. `ci.yml` mit lint, unit, e2e, arm-smoke, publish und release.
6. Testinstallation auf dem hEX S: RAM, Speicher und Client-IP prüfen.

**Stand 2026-11-05 (Branch `phase-0-foundation`):** Punkte 1–5 sind umgesetzt und lokal grün (Lint inkl. PHPStan Level 5, 48 PHPUnit-Tests, 22 E2E-Tests). Offen sind die CI auf GitHub (nicht ausgeführt) und Punkt 6 auf dem Gerät (Anleitung: `docs/deploy-mikrotik.md`).
- Abweichung: arm/v7 lässt sich unter Podman auf Apple Silicon nicht emulieren; dieses Image baut nur die CI. arm64 und amd64 lassen sich lokal bauen.
- Dabei gefundene Bugs: Der CSRF-Origin-Check ignorierte den Port, auf Port 8080 wäre also jeder POST abgelehnt worden. Die alten E2E-Tests konnten nie laufen: Labels ohne `for`, OTP-Replay bei mehrfachem Login, fehlende Config in der CI. Ohne Timeout hätte ein nicht erreichbarer Router Requests unbegrenzt blockiert. Beim Zertifikats-Pinning wurde eine Antwort akzeptiert, wenn sich der Fingerprint nicht auslesen liess.

**Fertig, wenn:**
- `./run.sh up` läuft und der Login mit `./run.sh otp` auf `http://localhost:8080` ohne MikroTik funktioniert.
- `./run.sh test` und die CI auf einem PR grün sind.
- Nach dem Merge liegt ein Multi-Arch-Image auf `ghcr.io/muqiuq/panag`, das kleiner als 50 MB ist.
- Auf dem hEX S klappt der Login mit der echten WireGuard-IP und eine Freigabe landet in der Address-List.

### Phase 1 – Datenmodell und Rollen (Aufwand M)
Migrationssystem, Migrationen 001–003, `can()`, Ersatz aller `isadmin`-Prüfungen, Impersonation-Rückweg, Grundgerüst von `profile.php`.

**Fertig, wenn:** Eine Kopie der Produktions-DB migriert ohne Verlust, und die E2E-Tests für alle drei Rollen sind grün.

**Stand 2026-11-06:** Umgesetzt und grün (59 PHPUnit-, 28 E2E-Tests).
- Migrationen über `PRAGMA user_version`; `bin/migrate.php` läuft beim Container-Start und schreibt vorher ein konsistentes Backup (`VACUUM INTO`, die letzten 5 bleiben). Getestet mit einer Fixture-DB im V0.1-Schema inkl. verwaister Zeilen und mit der bestehenden Dev-DB.
- Rollen `user`/`superuser`/`admin` mit `can()`. Der letzte Admin kann weder gelöscht noch herabgestuft werden, sonst würde sich das Setup wieder öffnen.
- `profile.php`: Superuser und Admins wählen ihre eigenen Default-Netze (der Server erzwingt die Level-Grenze), User sehen sie nur. Die komfortable Oberfläche folgt in Phase 3.
- Impersonation mit Banner und "Back to admin", Start und Ende im Audit-Log.
- Backup-Import akzeptiert weiterhin V0.1-Exporte (`isadmin`).

### Phase 2 – Freigabezeiten und Freigabelogik (Aufwand M)
Dauern pro User inkl. Validierung, Verlängern ohne Kürzen, Widerruf pro Eintrag, Anzeige von Rest- und Ablaufzeit, API-Endpunkte (`grant`, `extend`, `revoke`, `prefs`).

**Stand 2026-11-07:** Umgesetzt und grün (93 PHPUnit-, 38 E2E-Tests).
- `src/durations.php` (Grenzen, Parsen von Eingaben wie `1:30`, `90m`, `2h`, RouterOS-Formate) und `src/access.php` (Freigeben, Verlängern ohne Kürzen, Widerruf und Verlängern einzelner Einträge, Ansicht der aktiven Freigaben).
- Profil: Freigabezeiten mit Preset-Chips, Freifeld und "valid until approx."; ungültige Werte liefern HTTP 422 und bleiben zur Korrektur im Feld.
- Dashboard: aktive Freigaben mit Typ, Restzeit, Ablaufzeit sowie Extend/Revoke pro Eintrag. Das JS liegt neu in `public/js/` und gibt nur über `textContent` aus (Vorarbeit für die CSP).
- API: `grantNetwork`, `extendEntry`, `revokeEntry`, `savePrefs`; `currentAccess` liefert die aufbereitete Ansicht.
- Die globalen `DEFAULT_TIMEOUT`/`EXTENDED_TIMEOUT` entfallen; neu begrenzen `MAX_DEFAULT_DURATION`/`MAX_EXTENDED_DURATION` (nur nach unten).
- Nebenbei: Apache-KeepAlive blockierte mit 5 Workern die Seitenaufrufe (5 s pro Seite) und ist jetzt aus. Einzelne Hosts erkennt PANAG auch ohne `/32`, so wie RouterOS sie anzeigt.

**Fertig, wenn:**
- 14 min, 15 h (Default) und 13 h (Sonderfreigabe) werden mit HTTP 422 abgelehnt.
- Der Mock zeigt den korrekten Timeout.
- Eine Einzelfreigabe kürzt keine längere Default-Freigabe.
- Ein abgelaufener Eintrag verschwindet aus dem UI.

### Phase 3 – Bedienung (Aufwand L)
- Dashboard-Redesign mit Kommandofeld.
- Netz-Zuordnung: User-Liste und User-Detailseite, Superuser-Self-Service, Matrix, Netzwerk-Dialog.
- `table-sort.js` auf allen Tabellen, serverseitige Sortierung im Log.
- Gleichzeitig: Inline-JS in Dateien auslagern, `innerHTML` mit Daten entfernen, CSP aktivieren.

**Fertig, wenn:**
- Der E2E-Test "tippen → Enter → ↓ → Enter → Freigabe" nur mit der Tastatur durchläuft.
- Ein Superuser kann eigene Default-Netze nur bis zum eigenen Level setzen und bekommt für andere User 403.
- Die Sortierung aller Tabellen ist getestet.
- Die CSP erzeugt keine Fehler in der Konsole.

**Stand 2026-11-07 (Phase 3):** Umgesetzt und grün (104 PHPUnit-, 89 E2E-Tests). Alle vier Abnahmekriterien sind als E2E-Test abgedeckt.
- Kommandofeld (`public/js/palette.js`, Daten über `api.php?f=palette`, auf dem Dashboard eingebettet, damit kein zweiter Router-Aufruf nötig ist): Ranking nach Präfix, Wortanfang, Adresse und unscharfem Treffer ab Wortanfang ("dc" → Datacenter); IP-Suche; Dauer-Suffix (`vpn 2h`, serverseitig geprüft, 422 bei Überschreitung); Befehle je Rolle, für Admins "Find user" und "Go to …".
- Netz-Zuordnung: `admin/users.php` (Liste), `admin/user.php` (Tabs, Tab per URL-Hash), `admin/matrix.php`, `admin/networks.php` mit Dialogen. Ein Endpoint `setDefaultNetworks` für alle Oberflächen; die Level-Grenze gilt serverseitig jetzt auch für Admins. Wird der Level gesenkt, bleiben die betroffenen Defaults gespeichert, werden aber als ungültig markiert und lassen sich nur noch entfernen.
- `table-sort.js` auf allen Tabellen, inklusive des Default-Netz-Editors. Das Audit-Log sortiert serverseitig (`audit_log_order()`, Spalten-Whitelist).
- CSP aktiv (`docker/httpd.conf`): kein Inline-JS oder -CSS mehr, kein `innerHTML` mit Daten. Seiten-Skripte laufen über `$pageScripts` im Footer. Daten kommen als `data-*`-Attribute oder als `<script type="application/json">`.
- Alte URLs (`extendedaccess.php`, `admin/config_user.php`, `config_networks.php`, `config_constants.php`) leiten per 301 weiter.
- Abweichungen: Der Befehl "Theme: …" im Kommandofeld folgt mit Phase 4. Der OTP-QR-Code ist ein `<img>`, weil kjua 0.1.1 kein SVG kann; der alte Code erzeugte mit `render: 'svg'` unbemerkt ein Canvas. Die Vorschau-Kachel `.stat-tile` ist schon semantisch, die Navbar (`bg-danger`) noch nicht.
- Ein unabhängiges Review fand keine Rechte- oder Injection-Lücken. Behoben wurden: Hover wählte Treffer auch bei ruhendem Mauszeiger aus (dann hätte schon das erste Enter freigegeben), jetzt erst nach echter Bewegung. Ein Router-Fehler leerte die Liste der aktiven Freigaben, jetzt bleibt sie stehen und das Dashboard zeigt einen Hinweis. Ein fehlgeschlagener Befehl im Kommandofeld löschte die Eingabe. `.d-flex` übersteuerte `[hidden]`. Superuser konnten über 403/404 erkennen, welche User-IDs existieren. Der Netz-Import prüfte die Adressen nicht.
- Nebenbei gefunden: `run.sh` brach mit der macOS-Bash 3.2 ab, weil leere Arrays unter `set -u` als ungesetzt gelten. Der alte Impersonation-Test lief nach dem Session-Wechsel ausgeloggt und prüfte deshalb nichts.

### Phase 4 – Themes (Aufwand M)
Semantische Klassen, 8 Theme-Dateien, Auswahl im Profil und im Kommandofeld, Theme-Cookie für die Login-Seite, Screenshot- und Axe-Tests.

**Fertig, wenn:** Alle Themes auf allen Seiten ohne Darstellungsfehler laufen (Screenshot-Suite) und die HC-Themes axe-clean sind.

**Stand 2026-11-08: umgesetzt mit der vom User gewünschten Auswahl** – `default`, `dark` (neu, „Dark mode“), `high-contrast`, `high-contrast-dark`, `slay`; im zweiten Schritt `switzerland` (Rot #E60000 statt #FF0000, weil weisse Schrift auf #FF0000 nur 4:1 hat; reines Rot nur in der Flagge), `terminal` (Prompt-Überschriften, ASCII-Logo auf dem Login, Scanlines als Overlay ohne Pointer-Events), `brasil`, `atomic-age` (Futura-artige Überschriften, Starbursts, rotierendes Atom) und `wtf` (Comic Sans, Neon pro Karte, schiefe Karten); im dritten Schritt `suse`, `win95` (Fenster mit Bevel-Rahmen, Desktop #008585 statt #008080, damit schwarze Schrift 4.7:1 erreicht), `winxp`, `ubuntu` (Buttons #C34113, weil Weiss auf Ubuntu-Orange nur 3.6:1 hat) und `amiga` (dunkel; Fehler als „Guru Meditation“). Logos der Vorbilder werden bewusst nicht nachgebaut, nur Farben und Formen. Crazy Colors und Rainbow sind nicht gebaut; ein neues Theme braucht einen Eintrag in `THEMES` (`src/themes.php`) und einen Block in `public/css/themes.css`.
- Auswahl im Profil (Kachel pro Theme mit farbiger Vorschau, Live-Vorschau beim Anklicken, „Save theme“) und im Kommandofeld („Theme: Slay“ wechselt sofort, ohne Reload; `api.php?f=setTheme`). Gespeichert in `users.theme`, das Cookie `panag_theme` (HttpOnly, nicht sensibel) spiegelt den Wert für die Login-Seite. Beim Impersonieren bleibt das Cookie des Admins unverändert.
- Abweichungen: **eine** Datei `public/css/themes.css` statt einer pro Theme (weniger Requests auf dem hEX S; die Live-Vorschau braucht alle Themes). Die Vorschau-Kacheln zeigen Farbflächen statt Text, damit die Seite auch in den HC-Themes AAA-konform bleibt. „System (auto)“ ist nicht gebaut. Die Navbar ist jetzt `.app-navbar` mit `data-bs-theme="dark"` statt `navbar-dark bg-danger`.
- Tests: `tests/e2e/themes.spec.js` macht pro Theme Screenshots von 14 Ansichten (Report-Anhänge) und prüft die Kontraste mit `@axe-core/playwright` 4.14.0 – AAA für beide HC-Themes, AA für die übrigen. Text in exakt der Hintergrundfarbe meldet axe nur als „incomplete“ (`equalRatio`), der Test wertet das als Fehler (so fiel ein schwarzes Badge auf Schwarz in High contrast dark auf). Dabei fielen im bisherigen Standard-Look AA-Verstösse auf (Links `#0d6efd` auf dem grauen Seitenhintergrund, graue Outline-Buttons, Code-Farbe, hellrote Navbar-Texte); sie sind mit leicht dunkleren Farben behoben, das PANAG-Rot bleibt.

### Phase 5 – Aufräumen und Doku (Aufwand S)
- README überarbeiten: RouterOS-Installation (Container, veth, Mounts, Envs, API-User, Firewall), Env-Referenz, Update- und Backup-Ablauf.
- Entfernen: `sync_panag.sh`, Run-on-save in `.vscode/`, `main.css` im Root, `img/.DS_Store`.
- Bootstrap auf der Login-Seite lokal einbinden.
- Optional: Stufe 3 (CHR) und Trivy.

### Phase 6 – Wünsche vom 2026-11-08 (Aufwand L)
Vom User nachgeschoben, umgesetzt in dieser Reihenfolge, je ein Commit:

| # | Wunsch | Stand |
|---|--------|-------|
| 1 | Themes SUSE Linux, Windows 95, Windows XP, Ubuntu, Amiga | ✓ (siehe Phase 4) |
| 2 | Paginierung der Alarme | ✓ 50 pro Seite; Sortierung (Zeit, Schwere, User, Status) und Suche (User, Regel, Text) laufen serverseitig wie beim Audit-Log, Statusfilter als gebundener Parameter. Gemeinsames Partial `views/partials/pagination.php` (auch fürs Audit-Log). |
| 3 | Netze als „sensitive“ markieren: nie Default-Netz | offen |
| 4 | Statusmeldung pro User, gültig bis 03:00 | offen |
| 5 | Backups auf die Config-Seite, Gesamt-Backup und -Restore | offen |
| 6 | Erkennungsregeln im Web-UI konfigurierbar | offen |

---

## 7. Teststrategie

| Ebene | Werkzeug | Inhalt |
|-------|----------|--------|
| Unit | PHPUnit | `ip_in_cidr`, TOTP, Dauern (Parsen, Formatieren, Grenzen 15 min / 14 h / 12 h, Verlängern ohne Kürzen), Rechte-Matrix `can()`, Migrationen gegen eine Fixture-DB, Logik der Freigaben gegen `FakeRouterClient` |
| Integration | PHPUnit im Compose-Netz | `RestRouterClient` gegen mock-routeros, inkl. eingeschleuster Fehler (500, 401, Timeout) und TLS-Fingerprint |
| E2E | Playwright (Container) | Login je Rolle (per `X-Forwarded-For`), Default-Freigabe, Kommandofeld per Tastatur und Maus, Verlängern und Widerrufen, Grenzen der Dauern, Default-Netze als Superuser (eigene ✓, fremde 403, über dem Level abgelehnt), Sortierung, Wechsel und Speicherung des Themes, Impersonation |
| Visuell / a11y | Playwright-Screenshots, `@axe-core/playwright` | alle Themes; HC-Themes mit WCAG AAA |
| ARM-Smoke | Buildx + QEMU | `arm64`- und `arm/v7`-Image starten, `/healthz.php` antwortet, Grössenbudget eingehalten |
| Real (optional) | RouterOS CHR | nightly gegen die echte RouterOS-REST-API |

---

## 8. Offene Fragen

Die Antworten zu Superuser, Level-Grenze, Dauern, Theme "Slay", Plattform und Sprache sind in 1.1 eingearbeitet. Offen sind noch:

1. ~~Registry~~ → öffentliches Image `ghcr.io/muqiuq/panag` (bestätigt). Nach dem ersten Push die Sichtbarkeit des Pakets auf GitHub einmalig auf "public" stellen.
2. ~~Speicher am Router~~ → USB/microSD ist vorhanden (bestätigt).
3. ~~Bestehende Instanz~~ → Migrationstest mit einer selbst erzeugten Fixture-DB im alten Schema statt einer Produktionskopie.
4. ~~`status_public.php`~~ → ja, gewollt (bestätigt).

---

## 9. Risiken

| Risiko | Gegenmassnahme |
|--------|----------------|
| RAM oder Flash auf dem hEX S reichen nicht | Alpine-Image, knappes Apache/PHP-Tuning, Grössenbudget in der CI, Testinstallation schon in Phase 0 |
| `srcnat`/`masquerade` verfälscht die Client-IP, dann klappt kein Login | Login-Seite zeigt die erkannte IP (wie heute), Hinweis im README, Prüfung bei der Testinstallation |
| Flash-Verschleiss durch SQLite | Daten auf USB/microSD, WAL-Modus, Pruning von Audit-Log und Login-Versuchen, nur rollierende Backups |
| Migration der Produktions-DB schlägt fehl | automatisches Backup vor jeder Migration, Fixture-Tests, Probelauf mit einer Kopie der Produktions-DB |
| Mock weicht von echtem RouterOS ab | Stufe 3 (CHR) als Vergleich; Mock-Antworten aus echten Responses ableiten |
| ARM-Builds unter QEMU sind langsam | Alpine-Pakete statt Kompilieren, GHA-Build-Cache |
| Themes erhöhen den CSS-Pflegeaufwand | Themes nur über CSS-Variablen und wenige semantische Klassen, Screenshot-Suite in der CI |
| Grösserer Umbau (Phase 0) bricht bestehende Funktionen | bestehende E2E-Tests zuerst reparieren und grün halten, dann umbauen |
