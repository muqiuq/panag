# PANAG - lightweight gatekeeper

PANAG is a lightweight PHP/SQLite web app that grants temporary or default network access by adding address-list entries on MikroTik RouterOS devices.

## ⭐ Features
 - OTP login (TOTP) with QR codes for authenticator apps
 - Default and on-demand extended access to MikroTik address lists
 - User and network management with access levels and admin role
 - Local assets (Bootstrap/kjua) for offline-friendly deployments
 - Subdirectory-safe URLs, session lifetime display, and greeting UI

## 🧸 Motivation
 - Let admins grant themselves scoped access to parts of the network without exposing everything.
 - Provide a simple web front-end to hand out timed address-list entries without touching RouterOS manually.
 - Keep dependencies minimal (PHP + SQLite) while still supporting OTP and admin workflows.
 - Make it easy to predefine networks and enforce access levels per user.

## 🚀 Upcoming features
 - Sync status/health checks for MikroTik connectivity across multiple devices
 - Optional email/notification hooks for granted access events
 - More granular audit logging and reporting

## 🚧 Still in development
This project is currently in development and **not yet ready for production use**. If you want to contribute, we welcome issues and pull requests.

## 🔧 Quick start
1) Requirements: PHP 8+, SQLite enabled, MikroTik REST API reachable, web server configured for PHP.
2) Copy the repo to your server (or use the provided `sync_panag.sh` for rsync-based deploys).
3) Configure settings in `define.php` (DB path, MikroTik REST credentials, address list prefix, OTP issuer, session lifetime).
4) Install local assets: run `./fetch_dependencies.sh` (downloads Bootstrap and kjua locally).
5) Initialize/setup: open `/setup.php` in your browser to create the first admin user and seed demo data if desired.
6) Login at `/login.php`, then use the dashboard to grant default access or visit Extended Access for on-demand entries.

## 📦 Credits
- QR code rendering uses [kjua](https://github.com/lrsjng/kjua) by Lars Jung (bundled locally in `js/kjua.min.js`).

## ⚠️ Disclaimer
- Portions of this project were developed using [Vibe Coding](https://de.wikipedia.org/wiki/Vibe_Coding) practices.
- An AI assistant (GPT-5.1-Codex-Max) was used during development; review and validate outputs before production use.


## License
<a rel="license" href="http://creativecommons.org/licenses/by-nc-sa/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by-nc-sa/4.0/88x31.png" /></a><br />This work is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by-nc-sa/4.0/">Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License</a> and [GNU GENERAL PUBLIC LICENSE version 3](https://www.gnu.org/licenses/gpl-3.0.en.html). If there are any contradictions between the two licenses, the Attribution-NonCommercial-ShareAlike 4.0 International license governs. 