# PANAG - lightweight gatekeeper

This project was built to solve admin access management in a traditional (non-SDN) network. Admins connect to the admin gateway via WireGuard, then use PANAG to grant themselves scoped access to specific segments for a limited time. 
PANAG is a lightweight PHP/SQLite web app that hands out temporary or default access by adding address-list entries on MikroTik RouterOS devices. 

[See Dashboard Screenshot](./docs/screenshots/dashboard.png)

## ⭐ Features
 - OTP login (TOTP) only
 - User management with QR codes for authenticator apps
 - Grant on-demand access to networks; each user chooses own durations (default access 15 min – 14 h, extended access 15 min – 12 h)
 - Keyboard-first search field: type a network name, an IP or a command, Enter selects, Enter grants (`/` or `Ctrl/Cmd+K` on every page; `vpn 2h` grants with a custom duration)
 - Active grants show remaining time and can be extended or revoked individually; re-granting never shortens an active grant
 - User and network management with access levels and roles: user, superuser (chooses own default networks), admin
 - Default networks per user: editor with search and bulk actions, users × networks matrix, reverse view per network – always limited to the user's access level
 - All tables sortable (IP-aware); OTP secrets only shown after an explicit, logged "Reveal"
 - Strict Content-Security-Policy (no inline scripts or styles)
 - Security monitoring: unusual logins, grants and WireGuard locations (GeoIP: country and network operator) are bundled into alerts and mailed to admins – and the affected user ("Was this you?"); optional AI triage via OpenRouter with pseudonymised facts only ([plan](docs/plan-security-monitoring.md), [setup](INSTALL.md#13-security-monitoring-optional))
 - All configuration via environment variables; admins see every effective value (secrets only as "set") on the config page
 - Admins can act as another user (impersonation) and return
 - Local assets (Bootstrap/kjua) for offline-friendly deployments
 - Small container image (~40 MB, Alpine + Apache + PHP 8.4) for `amd64` and `arm64`; 32-bit ARM (`arm/v7`) is
   based on the official `php:8.4-apache-bookworm` image, because Alpine's armv7 build doesn't run in RouterOS
 - Deployable on a [RouterOS](https://mikrotik.com/software) device using the [Container](https://help.mikrotik.com/docs/spaces/ROS/pages/84901929/Container) feature – see [INSTALL.md](INSTALL.md)
 - Fully testable without a MikroTik: a mock RouterOS REST API is included

## 📥 Installation

PANAG runs as a container directly on the MikroTik router that terminates the admins' WireGuard VPN
(RouterOS 7 on an ARM, ARM64 or x86 device, e.g. hEX S 2025). The step-by-step manual is in
**[INSTALL.md](INSTALL.md)**:

1. Install the container package, enable container mode, add a USB stick or microSD card and NTP.
2. Give every admin a WireGuard peer with a fixed `/32` address – that address is the PANAG user IP.
3. Create the container network, the API user and HTTPS for the RouterOS REST API.
4. Start the image (`ghcr.io/muqiuq/panag:v2.0` or the release tarball) with a few environment variables.
5. Add one firewall rule per user: traffic from the user's tunnel IP to the address list
   `Whitelist <user IP>` is allowed – PANAG fills that list with timed entries.
6. Create the first admin, add networks and users, test a grant.

Optional: security monitoring with mail alerts ([INSTALL.md, section 13](INSTALL.md#13-security-monitoring-optional)).

## 🧸 Motivation
 - Let admins grant themselves scoped access to parts of the network without exposing everything.
 - Provide a simple web front-end to hand out timed address-list entries without touching RouterOS manually.
 - Keep dependencies minimal (PHP + SQLite) while still supporting OTP and admin workflows.
 - Define profiles per users for quick access

## 🛠️ Development

Everything runs in containers (Podman, or Docker) – no PHP, Node or npm needed on the host.

```sh
./run.sh up      # app + mock RouterOS with demo data → http://localhost:8080
./run.sh otp     # current login code for the demo users
./run.sh test    # lint (php -l, shellcheck, PHPStan) + PHPUnit + Playwright E2E
./run.sh help    # all commands
```

In development the app runs with `APP_ENV=dev`: a banner lets you choose which client IP PANAG
should assume (users are identified by IP), so you can log in as any demo user.
The mock router (`dev/mock-routeros/`) implements the RouterOS REST endpoints PANAG uses, lets
timeouts expire like RouterOS and supports fault injection (`/_mock/fault`). It also fakes WireGuard
peers (`/_mock/wireguard`, e.g. to move a peer to another country) and the OpenRouter API for the AI
triage. Mails of the dev stack land in Mailpit (http://127.0.0.1:8025); `./run.sh monitor` runs one
security monitor cycle. GeoIP test databases for documentation IP ranges are built from `dev/geoip/`.

Layout: `public/` is the only web root, application code is in `src/`, CLI tools in `bin/`,
the SQLite database lives in `$DATA_DIR` (`/data` in the container).

## ⚙️ Configuration

All settings are environment variables – see [.env.example](.env.example).
Container images are published to `ghcr.io/muqiuq/panag` by GitHub Actions.

## 🚀 Upcoming features
 - Optional email/notification hooks for granted access events
 - WireGuard Configuration Management

## 🚧 Still in development
This project is currently in development and **not yet ready for production use**. If you want to contribute, we welcome issues and pull requests.

## 📦 Credits
- QR code rendering uses [kjua](https://github.com/lrsjng/kjua) by Lars Jung (bundled locally in `js/kjua.min.js`).

## ⚠️ Disclaimer
- Portions of this project were developed using [Vibe Coding](https://de.wikipedia.org/wiki/Vibe_Coding) practices.
- An AI assistant (GPT-5.1-Codex-Max) was used during development; review and validate outputs before production use.

## License
<a rel="license" href="http://creativecommons.org/licenses/by-nc-sa/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by-nc-sa/4.0/88x31.png" /></a><br />This work is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by-nc-sa/4.0/">Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License</a> and [GNU GENERAL PUBLIC LICENSE version 3](https://www.gnu.org/licenses/gpl-3.0.en.html). If there are any contradictions between the two licenses, the Attribution-NonCommercial-ShareAlike 4.0 International license governs. 