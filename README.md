# PANAG - lightweight gatekeeper

This project was built to solve admin access management in a traditional (non-SDN) network. Admins connect to the admin gateway via WireGuard, then use PANAG to grant themselves scoped access to specific segments for a limited time. 
PANAG is a lightweight PHP/SQLite web app that hands out temporary or default access by adding address-list entries on MikroTik RouterOS devices. 

[See Dashboard Screenshot](./docs/screenshots/dashboard.png)

## ⭐ Features
 - OTP login (TOTP) only
 - User management with QR codes for authenticator apps
 - Grant On-demand access to networks 
 - User and network management with access levels and admin role
 - Local assets (Bootstrap/kjua) for offline-friendly deployments
 - Small container image (~40 MB, Alpine + Apache + PHP 8.4) for `amd64`, `arm64` and `arm/v7`
 - Deployable on a [RouterOS](https://mikrotik.com/software) device using the [Container](https://help.mikrotik.com/docs/spaces/ROS/pages/84901929/Container) feature – see [docs/deploy-mikrotik.md](docs/deploy-mikrotik.md)
 - Fully testable without a MikroTik: a mock RouterOS REST API is included

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
timeouts expire like RouterOS and supports fault injection (`/_mock/fault`).

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