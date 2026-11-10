# PANAG – Übergabe / Stand der Arbeit

Stand: 2026-11-09 · Branch `main` · Version **V2.0** (Tag `v2.0` auf GitHub) · Dient dazu, die Arbeit auf einem anderen Rechner (oder in einer neuen
Claude-Session) nahtlos fortzusetzen. Der Gesamtplan steht in [PLAN.md](PLAN.md); dieses Dokument fasst
zusammen, was entschieden, gebaut und gelernt wurde.

> Neue Claude-Session: „Lies PLAN.md und HANDOFF.md und mach mit Phase 5 weiter.“

---

## 1. Ausgangslage und Ziel

PANAG ist eine kleine PHP/SQLite-Web-App, die per RouterOS-REST-API zeitlich begrenzte Address-List-Einträge
auf einem MikroTik setzt („Freigaben“). User werden über ihre WireGuard-Quell-IP + TOTP identifiziert.
Das Projekt war älter, ohne Tests, ohne Container und nur mit echtem MikroTik testbar.

Gewünscht (vom User):
- Testen ohne MikroTik, Container-Image via GitHub CI, `run.sh` für lokale Tests – alles in Podman
- Freigabezeiten pro User selbst einstellbar: Default max. 14 h, Sonderfreigabe max. 12 h
- Rollen: User / Superuser / Admin
- Einfachere Netzwerk-Zuordnung pro User
- Such-/Kommandofeld für Freigaben (tippen → Enter → Pfeiltasten/Maus → Enter/Klick)
- Alle Tabellen sortierbar
- Themes pro User: gebaut sind Default, Dark mode, High Contrast, High Contrast Dark, Slay, Switzerland, Terminal, Brasil, Atomic age, WTF, SUSE Linux, Windows 95, Windows XP, Ubuntu, Amiga (Auswahl des Users vom 2026-11-08)

## 2. Getroffene Entscheide (vom User bestätigt)

| Thema | Entscheid |
|-------|-----------|
| Superuser | wählt seine **eigenen Default-Netze**; Sonderfreigabe bleibt für alle: alle Netze ≤ eigenem Level |
| Level-Grenze | gilt auch für Superuser |
| Einzelfreigabe (Kommandofeld/Tabelle) | immer **Sonderfreigabe-Dauer**, auch bei Default-Netzen |
| Mindestdauer | 15 min (Default und Sonderfreigabe) |
| Theme „Slay“ | Gay/Pride, **violett** dominant (Regenbogen nur als Akzent; Abgrenzung zu `rainbow`) |
| Produktion | **RouterOS-Container auf MikroTik hEX S (E60iUGS)**; Images für ARM64 (Alpine) und ARM32 (arm/v5, Debian armel) |
| UI-Sprache | Englisch bleibt |
| Registry | öffentliches Image `ghcr.io/muqiuq/panag` |
| Speicher am Router | USB/microSD vorhanden → Image, tmp und `/data` dorthin |
| Migrationstest | ohne Produktions-DB; selbst erzeugte Fixture im V0.1-Schema |
| `status_public.php` | gewollt: jeder eingeloggte User sieht, wer heute eingeloggt war |
| Commits | direkt auf `main`; GitHub Actions testet der User selbst und meldet Fehler |
| Push, Branches, Tags | nur auf ausdrückliche Anweisung des Users (siehe `CLAUDE.md`) |
| Security Monitoring | eigenes Projekt, [docs/plan-security-monitoring.md](docs/plan-security-monitoring.md); KI über **OpenRouter mit GLM** (`z-ai/glm-5.3`), ZDR und `data_collection: deny` fest |
| Konfiguration | **alles über Env-Variablen**, nichts in der DB; Admins sehen jede Einstellung (Secrets nur als „gesetzt“). **Ausnahme seit 2026-11-08 (Wunsch des Users):** die Erkennungsregeln sind im Web-UI einstellbar (`admin/rules.php`, `settings['monitor.rules']`); die `MONITOR_*`-Env-Werte sind deren Defaults, die Config-Seite zeigt Überschreibungen. |
| Runtime-Abhängigkeiten | erlaubt für `maxmind-db/reader` und `phpmailer/phpmailer` (eigene Build-Stage) |

## 3. Was erledigt ist

| Commit | Phase | Inhalt (Kurzfassung) |
|--------|-------|----------------------|
| `ee1e2a4` | 0 – Fundament | `public/` als einziger Webroot, `src/`, `bin/`; Config via Env-Variablen; `RouterClient` + Mock-RouterOS; Alpine-Image (~40 MB); `run.sh`; PHPUnit/PHPStan/Playwright in Containern; GitHub Actions; Setup nur solange kein Admin existiert |
| `48b09b1` | 1 – Datenmodell & Rollen | Migrationen (`PRAGMA user_version`, Backup vor Migration); Rollen + `can()`; letzter Admin geschützt; `profile.php` mit eigenen Default-Netzen (Superuser/Admin); Impersonation mit Rückweg |
| `189b31c` | 2 – Freigabezeiten | Dauern pro User (15 min–14 h / 15 min–12 h, Server-Validierung 422); Verlängern ohne Kürzen; Extend/Revoke pro Eintrag; JS nach `public/js/` (nur `textContent`) |
| „Phase 3: …“ | 3 – Bedienung | Kommandofeld (`/`, Ctrl/Cmd+K, IP-Suche, `vpn 2h`); Admin-Seiten `users`/`user` (Tabs)/`networks`/`matrix`; Default-Netze überall nur ≤ Level (auch Admins); OTP-Secret nur nach „Reveal“ (geloggt); alle Tabellen sortierbar, Log serverseitig; CSP aktiv |

| `064d7be`, „Themes: …“ | 4 – Themes | Default, Dark mode, High contrast, High contrast dark, Slay, Switzerland, Terminal, Brasil, Atomic age, WTF, SUSE Linux, Windows 95, Windows XP, Ubuntu, Amiga; Auswahl im Profil und im Kommandofeld, `users.theme` + Cookie für die Login-Seite; axe-Kontrastprüfung (AAA für HC) und Screenshots pro Theme |
| `311af9f`, `d39d84b` | 4 – Themes | zweiter und dritter Schwung Themes (siehe oben) |
| `70a0057` | 6 – Wünsche | Alarme paginiert (50/Seite), Sortierung und Suche serverseitig |
| `a942879` | 6 – Wünsche | Netze „sensitive“: nie Default-Netz, nur Einzelfreigabe (Migration 005) |
| `e69dc3e` | 6 – Wünsche | Statusmeldung pro User bis 03:00 (Migration 006), sichtbar für alle |
| `56b809e` | 6 – Wünsche | Backups auf der Config-Seite, Gesamt-Backup und -Restore aller Tabellen |
| `fed85c4` | 6 – Wünsche | Erkennungsregeln im Web-UI: an/aus, Schwere, Schwellen (`admin/rules.php`) |
| `dd8fb66` | Security Monitoring | Regeln W1–W7/P1–P8/M1, Alarme mit Bündelung und Cooldown, Mails (SMTP, Digest, „Warst du das?“), GeoIP (DB-IP Lite, MMDB), KI-Triage via OpenRouter, `admin/alerts.php`, `admin/monitoring.php`, Config-Seite mit Herkunft und Secrets; Stand in [docs/plan-security-monitoring.md](docs/plan-security-monitoring.md) Kapitel 18 |

Teststand lokal: Lint grün (php -l, shellcheck, PHPStan Level 5 ohne Baseline), **171 PHPUnit**, **122 E2E**.
GitHub Actions: Workflow geschrieben und mit `actionlint` geprüft, **aber noch nie auf GitHub gelaufen**.

### Unterwegs gefundene und behobene Bugs (wichtig für Produktion)
- CSRF-Origin-Check verglich ohne Port → auf Port 8080 wäre **jeder POST mit 403** abgelehnt worden.
- Kein Router-Timeout → ein nicht erreichbarer Router hätte Requests unbegrenzt blockiert.
- Zertifikats-Pinning akzeptierte Antworten, wenn der Fingerprint nicht lesbar war.
- SQLite-Foreign-Keys waren aus → verwaiste Zuordnungen (Migration 003 räumt auf).
- Apache-KeepAlive blockierte mit 5 Prefork-Workern Seitenaufrufe (~5 s) → `KeepAlive Off`.
- RouterOS zeigt `/32`-Hosts ohne Maske → wurde beim Abgleich normalisiert.
- Die alten E2E-Tests konnten nie laufen (fehlende Config in CI, Labels ohne `for`, OTP-Replay).
- `run.sh` brach mit der macOS-Bash 3.2 ab (leeres Array unter `set -u`), Phase 3 hat das behoben.
- Der QR-Code wurde nie als SVG gerendert: kjua 0.1.1 kennt nur `image`/`canvas` und fiel unbemerkt auf ein Canvas zurück.

## 4. Auf einem neuen Rechner weitermachen

Voraussetzungen: **Podman** (inkl. laufender `podman machine` auf macOS) und ein Compose-Provider für
`podman compose` (hier: `docker-compose` unter `/usr/local/bin`, alternativ `podman-compose`). Alternativ
Docker: `CONTAINER_ENGINE=docker ./run.sh …`. PHP, Node, npm, Composer sind auf dem Host **nicht** nötig.

```sh
git clone git@github.com:muqiuq/panag.git && cd panag
./run.sh up      # baut Image, startet App + Mock-RouterOS mit Demo-Daten → http://localhost:8080
./run.sh otp     # aktueller TOTP-Code (alle Demo-User: Secret JBSWY3DPEHPK3PXP)
./run.sh test    # lint + unit + e2e
./run.sh help
```

- Demo-User (Dev-Banner oben wechselt die simulierte Client-IP): `127.0.0.1` Admin „Local Tester“ (L12),
  `10.0.0.1` Admin, `10.0.0.2` User (L5), `10.0.0.3` Superuser (L8), `10.0.0.9` nur für den Login-Test.
- `vendor/` und `node_modules` werden automatisch im Container erzeugt (node_modules in einem Volume).
- **Nicht im Git:** `config/config.php` (alte Produktions-Config mit Router-Passwort). Wird nicht mehr gelesen;
  die Werte gehören in RouterOS `/container/envs` (siehe `.env.example`). Falls benötigt, manuell übertragen.

## 5. Wichtige Dateien

| Datei | Zweck |
|-------|-------|
| `PLAN.md` | Gesamtplan, Phasen mit Abnahmekriterien und Stand |
| `INSTALL.md` | Installationsanleitung für MikroTik (Container-Paket, WireGuard, veth, Firewall inkl. Regel pro User, API-User, Zertifikat, Envs, erster Admin, Monitoring, Update/Backup, Fehlersuche); `docs/deploy-mikrotik.md` verweist nur noch dorthin |
| `.env.example` | alle Konfigurationsvariablen |
| `run.sh` | alle Entwickler-Befehle |
| `src/config.php` | Env-basierte Konfiguration (`panag_env`, `*_FILE` für Secrets) |
| `src/router/` | `RouterClient` + `RestRouterClient` |
| `src/access.php`, `src/durations.php` | Freigabelogik und Dauern |
| `src/default_networks.php` | Wer darf wessen Default-Netze ändern, Level-Grenze, `change_default_networks()` |
| `src/palette.php`, `public/js/palette.js` | Kommandofeld: Daten (Server) bzw. Ranking, Combobox, Overlay (Browser) |
| `public/js/app.js`, `public/js/table-sort.js` | gemeinsame Helfer (`api`, `el`, `toast`, Event `panag:access`) bzw. sortierbare Tabellen |
| `src/views/partials/` | Default-Netz-Editor, Dauern-Formular, Users-Overview (je Seite wiederverwendet) |
| `src/roles.php` | Rechte-Matrix `can()` |
| `src/config.php`, `src/config_checks.php` | Registry aller Env-Variablen (Gruppe, Beschreibung, Typ, Secret) und Prüfungen; neue Variable = `$cfg(...)` + Eintrag in `.env.example` (Test prüft das) |
| `src/monitor/` | Security Monitoring: `cycle.php` (Ablauf), `rules.php`, `alerts.php`, `notify.php`, `ai.php`, `geoip.php` |
| `dev/geoip/` | MMDB-Writer und GeoIP-Testdatenbanken (Dokumentations-IP-Bereiche → CH, DE, US …) |
| `src/migrations/` | Schema-Migrationen; `bin/migrate.php` läuft beim Container-Start |
| `dev/mock-routeros/router.php` | Mock der RouterOS-REST-API (`/_mock/reset`, `/_mock/state`, `/_mock/fault`) |
| `tests/unit`, `tests/integration`, `tests/e2e` | PHPUnit bzw. Playwright |
| `.github/workflows/ci.yml` | lint, unit, e2e, arm-smoke, publish (GHCR), release (Tarballs) |

## 6. Stolpersteine / Wissen, das nicht im Code steht

- **32-bit ARM: RouterOS-Container können keine Hard-Float-Binaries ausführen.** Auf dem hEX S (E60iUGS) stirbt
  das Alpine-armv7-Image mit `exited with signal 4 (Illegal instruction)`, schon bei `busybox awk`. Deshalb ist
  das 32-bit-Image seit 2026-11-10 Debian armel (`linux/arm/v5`, soft-float), flachgeklopft auf `scratch` ohne
  Perl/apt/gconv, mit denselben Pfaden, User und PHP-Extensions wie Alpine. QEMU in der CI emuliert eine CPU, die
  alles kann – solche Fehler sieht nur echte Hardware.
- **32-bit ARM lässt sich auf Apple Silicon nicht bauen** (kein AArch32; QEMU-binfmt in der Podman-VM hilft nicht).
  Das baut nur die CI. arm64/amd64 gehen lokal (`./run.sh build arm64`, `./run.sh export arm64`). Die
  Debian-Variante läuft aber nativ: `PANAG_RUNTIME_OS=debian ./run.sh e2e` (macht die CI auch).
- `podman build/run --platform X` biegt den lokalen Tag des Basis-Images um → `run.sh` baut nativ immer mit
  expliziter `--platform`; die Cross-Arch-Probe nutzt bewusst `busybox`.
- **TRUSTED_PROXIES** im Dev/E2E nur auf das Compose-Subnetz setzen (Dev `172.30.99.0/24`, E2E `172.30.98.0/24`)
  – sonst gelten Demo-IPs (10.0.0.x) als Proxy und X-Forwarded-For wird ignoriert. In Produktion leer lassen.
- **OTP-Codes sind pro User einmalig** (Replay-Schutz). E2E loggt in `tests/e2e/global-setup.js` einmal pro Rolle
  ein und nutzt die Sessions (`tests/e2e/.auth/`) wieder; neue Login-Tests brauchen einen eigenen User.
- E2E-Tests laufen bewusst mit 1 Worker (geteilter Router-/DB-Zustand); Mock wird pro Test zurückgesetzt.
- Bei `fetch(..., {redirect: 'manual'})` liefert der Browser Status 0 (`opaqueredirect`), nicht 302.
- Podman speichert Images im OCI-Format ohne HEALTHCHECK → `run.sh` baut mit `--format docker`
  (RouterOS braucht ohnehin docker-archive-Tarballs).
- RouterOS-Befehle in `INSTALL.md` sind ungetestet. Container-Syntax nach aktueller MikroTik-Doku (2026-11-09): `/container/envs/add list=…`, `/container/mounts/add list=…`, `/container/add envlist=… mountlists=…` – am Gerät prüfen.
- Nach dem ersten Push nach GHCR: Paket-Sichtbarkeit auf GitHub einmalig auf **public** stellen.
- **macOS-Bash 3.2:** leere Arrays in `run.sh` nur als `${arr[@]+"${arr[@]}"}` expandieren (sonst Abbruch unter `set -u`).
- **CSP** (`docker/httpd.conf`): kein `<script>`-Inhalt, kein `style="…"`, keine `on…`-Attribute. Seiten-JS in
  `public/js/`, eingebunden über `$pageScripts` vor `include view_path('footer')`. Bestätigungen per `data-confirm`.
  Daten an JS als `data-*` oder `<script type="application/json">` mit `JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT`.
  Änderungen an `httpd.conf` brauchen ein neues Image (`./run.sh up` baut es).
- Von JS gerenderte Tabellen rufen danach `PanagTableSort.refresh(table)` auf (Sortierung und Filter bleiben erhalten).
- **E2E:** Impersonation erzeugt eine neue Session-ID, die gespeicherte Session dieser Rolle ist danach ungültig
  (deshalb laufen die nur lesenden Tests in `impersonation.spec.js` zuerst). Specs, die Default-Netze der Demo-User
  ändern, stellen sie mit `setDefaults()` (`tests/e2e/utils/ui.js`) wieder her. `getByLabel` trifft auch
  `aria-label` von Buttons (z. B. die Suche in der Navbar), dann eindeutiger lokalisieren.
- **Zufalls-IPs in E2E-Tests** nur über `testIp()` (`tests/e2e/utils/users.js`, Bereich 10.230–239.x.x). Sonst
  findet z. B. die Palette-Suche „10.10“ die von anderen Specs angelegten User, und Tests scheitern nur im Gesamtlauf.
- **Monitoring im Dev/E2E-Stack:** `compose.dev.yml` schaltet es mit Mailpit (http://127.0.0.1:8025, E2E: 18025),
  den GeoIP-Fixtures (`/geoip`, von `run.sh` gebaut) und der Fake-KI im Mock-Router ein. Ein Zyklus läuft nur auf
  Anstoss (`./run.sh monitor` oder POST `/monitor.php` mit `X-Monitor-Token: e2e-monitor-token`). Die
  `e2e-secret-*`-Werte sind Dummies; ein Test prüft, dass sie nie auf der Config-Seite erscheinen.
- **Monitoring-Tests:** jeder E2E-Test legt eigenen User und Peer an (Dedupe-Schlüssel sind pro User, Cooldown 24 h).
- **Kein mbstring im Image.** `mb_*`-Funktionen gibt es nur im Test-Container – in der App PCRE nutzen
  (`status_message_length()`, `mb_substr_safe()`), sonst Fatal Error erst im E2E.
- **Regel-Einstellungen sind pro Prozess gecacht** (`rule_settings()`); `run_monitor_cycle()` lädt sie neu (für
  `bin/monitor.php --loop`), Unit-Tests, die `settings` leeren, rufen `rule_settings_reload()`.
- **Gesamt-Restore im E2E** ist nur sicher, weil die Specs nacheinander laufen (1 Worker): `backup.spec.js` spielt
  ein eben geladenes Backup wieder ein. Mit mehreren Workern würde das Daten anderer Tests zurücksetzen.
- `.visually-hidden`-Elemente sind absolut positioniert: ohne `position: relative` am Scroll-Container
  (`.table-responsive`) verbreitern sie die ganze Seite auf dem Handy.
  Unit-Tests ersetzen Router, Mailer, GeoIP und KI über `set_router()`, `set_mailer()`, `set_geoip()`,
  `set_ai_transport()`; Zeit wird als `$now` durchgereicht.
- **PHP auf 32-bit ARM ist 32-bit** (`PHP_INT_SIZE` 4): Deshalb ist `php84-bcmath` im Image (MMDB-Werte > 2³¹).

## 7. Offen / nächste Schritte

1. **GitHub Actions** prüfen (User testet; Fehler melden und beheben).
2. **Phase 0, Punkt 6:** Testinstallation auf dem hEX S nach `INSTALL.md` (RAM/Speicher prüfen,
   Login-Seite muss die echte WireGuard-IP zeigen, Freigabe muss in der Address-List landen).
3. ~~Phase 3 – Bedienung~~ erledigt (Stand siehe PLAN.md, Phase 3).
4. ~~Phase 4 – Themes~~ erledigt mit der gewünschten Auswahl (Stand siehe PLAN.md, Phase 4). Crazy Colors und
   Rainbow aus PLAN.md 4.9 nur auf Wunsch.
5. **Phase 5 – Aufräumen/Doku**, optional RouterOS-CHR-Test in der CI und Trivy.
6. **Security Monitoring** ist umgesetzt und committet (`dd8fb66`; Tag `v0.2` am 2026-11-09 nach `v2.0` gepusht – danach den Publish-Job von `v2.0` erneut laufen lassen, damit `latest` wieder V2.0 ist). Offen sind die
   Geräteprüfung am hEX S (Peer-Felder, Egress, Scheduler) und ein echter OpenRouter-Testaufruf mit der
   gewählten Provider-Liste, siehe docs/plan-security-monitoring.md, Kapitel 18.
7. ~~Phase 6 – Wünsche vom 2026-11-08~~ erledigt (Stand siehe PLAN.md, Phase 6) und als **V2.0** getaggt und
   gepusht. Die CI baut daraus Image (`ghcr.io/muqiuq/panag:v2.0`, `latest`) und Release mit den Tarballs
   `panag-v2.0-arm64.tar` / `-armv7.tar`.
8. **arm/v5-Image auf dem hEX S testen** (2026-11-10 lokal committet, nicht gepusht): V2.0s armv7-Image stirbt
   dort mit SIGILL. Nach dem Push gibt es `ghcr.io/muqiuq/panag:edge`; Größe des armel-Images in der CI
   (`arm-smoke`) ablesen und das Budget von 100 MB ggf. enger stellen.
