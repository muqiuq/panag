# PANAG – Übergabe / Stand der Arbeit

Stand: 2026-11-07 · Branch `main` · Dient dazu, die Arbeit auf einem anderen Rechner (oder in einer neuen
Claude-Session) nahtlos fortzusetzen. Der Gesamtplan steht in [PLAN.md](PLAN.md); dieses Dokument fasst
zusammen, was entschieden, gebaut und gelernt wurde.

> Neue Claude-Session: „Lies PLAN.md und HANDOFF.md und mach mit Phase 3 weiter.“

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
- Themes pro User: High Contrast, High Contrast Dark, Terminal, Slay, Switzerland, Crazy Colors, Rainbow

## 2. Getroffene Entscheide (vom User bestätigt)

| Thema | Entscheid |
|-------|-----------|
| Superuser | wählt seine **eigenen Default-Netze**; Sonderfreigabe bleibt für alle: alle Netze ≤ eigenem Level |
| Level-Grenze | gilt auch für Superuser |
| Einzelfreigabe (Kommandofeld/Tabelle) | immer **Sonderfreigabe-Dauer**, auch bei Default-Netzen |
| Mindestdauer | 15 min (Default und Sonderfreigabe) |
| Theme „Slay“ | Gay/Pride, **violett** dominant (Regenbogen nur als Akzent; Abgrenzung zu `rainbow`) |
| Produktion | **RouterOS-Container auf MikroTik hEX S (E60iUGS)**; Images für ARM64 und ARM32 (arm/v7) |
| UI-Sprache | Englisch bleibt |
| Registry | öffentliches Image `ghcr.io/muqiuq/panag` |
| Speicher am Router | USB/microSD vorhanden → Image, tmp und `/data` dorthin |
| Migrationstest | ohne Produktions-DB; selbst erzeugte Fixture im V0.1-Schema |
| `status_public.php` | gewollt: jeder eingeloggte User sieht, wer heute eingeloggt war |
| Commits | direkt auf `main`; GitHub Actions testet der User selbst und meldet Fehler |

## 3. Was erledigt ist

| Commit | Phase | Inhalt (Kurzfassung) |
|--------|-------|----------------------|
| `ee1e2a4` | 0 – Fundament | `public/` als einziger Webroot, `src/`, `bin/`; Config via Env-Variablen; `RouterClient` + Mock-RouterOS; Alpine-Image (~40 MB); `run.sh`; PHPUnit/PHPStan/Playwright in Containern; GitHub Actions; Setup nur solange kein Admin existiert |
| `48b09b1` | 1 – Datenmodell & Rollen | Migrationen (`PRAGMA user_version`, Backup vor Migration); Rollen + `can()`; letzter Admin geschützt; `profile.php` mit eigenen Default-Netzen (Superuser/Admin); Impersonation mit Rückweg |
| `189b31c` | 2 – Freigabezeiten | Dauern pro User (15 min–14 h / 15 min–12 h, Server-Validierung 422); Verlängern ohne Kürzen; Extend/Revoke pro Eintrag; JS nach `public/js/` (nur `textContent`) |

Teststand lokal: Lint grün (php -l, shellcheck, PHPStan Level 5 ohne Baseline), **93 PHPUnit**, **38 E2E**.
GitHub Actions: Workflow geschrieben und mit `actionlint` geprüft, **aber noch nie auf GitHub gelaufen**.

### Unterwegs gefundene und behobene Bugs (wichtig für Produktion)
- CSRF-Origin-Check verglich ohne Port → auf Port 8080 wäre **jeder POST mit 403** abgelehnt worden.
- Kein Router-Timeout → ein nicht erreichbarer Router hätte Requests unbegrenzt blockiert.
- Zertifikats-Pinning akzeptierte Antworten, wenn der Fingerprint nicht lesbar war.
- SQLite-Foreign-Keys waren aus → verwaiste Zuordnungen (Migration 003 räumt auf).
- Apache-KeepAlive blockierte mit 5 Prefork-Workern Seitenaufrufe (~5 s) → `KeepAlive Off`.
- RouterOS zeigt `/32`-Hosts ohne Maske → wurde beim Abgleich normalisiert.
- Die alten E2E-Tests konnten nie laufen (fehlende Config in CI, Labels ohne `for`, OTP-Replay).

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
| `docs/deploy-mikrotik.md` | Installation auf dem hEX S (veth, Firewall, API-User, Zertifikat, Envs, erster Admin) |
| `.env.example` | alle Konfigurationsvariablen |
| `run.sh` | alle Entwickler-Befehle |
| `src/config.php` | Env-basierte Konfiguration (`panag_env`, `*_FILE` für Secrets) |
| `src/router/` | `RouterClient` + `RestRouterClient` |
| `src/access.php`, `src/durations.php` | Freigabelogik und Dauern |
| `src/roles.php` | Rechte-Matrix `can()` |
| `src/migrations/` | Schema-Migrationen; `bin/migrate.php` läuft beim Container-Start |
| `dev/mock-routeros/router.php` | Mock der RouterOS-REST-API (`/_mock/reset`, `/_mock/state`, `/_mock/fault`) |
| `tests/unit`, `tests/integration`, `tests/e2e` | PHPUnit bzw. Playwright |
| `.github/workflows/ci.yml` | lint, unit, e2e, arm-smoke, publish (GHCR), release (Tarballs) |

## 6. Stolpersteine / Wissen, das nicht im Code steht

- **arm/v7 lässt sich auf Apple Silicon nicht bauen** (kein AArch32; QEMU-binfmt in der Podman-VM hilft nicht).
  Das baut nur die CI. arm64/amd64 gehen lokal (`./run.sh build arm64`, `./run.sh export arm64`).
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
- RouterOS-Befehle in `docs/deploy-mikrotik.md` sind eine Skizze – Parameternamen (`envlist`, `mounts`) vor dem
  Einsatz gegen die installierte RouterOS-Version prüfen.
- Nach dem ersten Push nach GHCR: Paket-Sichtbarkeit auf GitHub einmalig auf **public** stellen.

## 7. Offen / nächste Schritte

1. **GitHub Actions** prüfen (User testet; Fehler melden und beheben).
2. **Phase 0, Punkt 6:** Testinstallation auf dem hEX S nach `docs/deploy-mikrotik.md` (RAM/Speicher prüfen,
   Login-Seite muss die echte WireGuard-IP zeigen, Freigabe muss in der Address-List landen).
3. **Phase 3 – Bedienung** (nächste Arbeitsphase, siehe PLAN.md 4.5, 4.7, 4.8):
   - Kommandofeld (`/` bzw. Ctrl/Cmd+K): Treffer live, erstes Enter markiert, zweites Enter/Klick gibt frei
     (immer Sonderfreigabe-Dauer), IP-Suche (Adresse → enthaltendes Netz), WAI-ARIA-Combobox.
     Endpoint `api.php?f=grantNetwork` existiert bereits; für die Trefferliste fehlt noch `f=palette`.
   - Netz-Zuordnung: `admin/users.php` (Tabelle) + `admin/user.php?id=` (Tabs), Matrix, Netzwerk-Dialog,
     serverseitig nur Default-Netze ≤ Level erlauben (für Superuser bereits umgesetzt, für Admins noch nicht).
   - `table-sort.js` für alle Tabellen, Log serverseitig sortiert.
   - CSP aktivieren: Restliches Inline-JS auslagern (`extendedaccess.php`, `admin/status.php`,
     `admin/config_user.php`, `setup.php`) und `innerHTML` mit Daten entfernen (`extendedaccess.php` fällt weg).
   - OTP-Secrets nicht mehr im HTML der User-Liste rendern (erst nach „Reveal“).
4. **Phase 4 – Themes** (PLAN.md 4.9): `users.theme` existiert bereits (Migration 002), Werte noch ungenutzt.
5. **Phase 5 – Aufräumen/Doku**, optional RouterOS-CHR-Test in der CI und Trivy.
