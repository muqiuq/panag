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
 - Deployable on a [RouterOS](https://mikrotik.com/software) device using [Container](https://help.mikrotik.com/docs/spaces/ROS/pages/84901929/Container) feature and [php:8.4-apache-bookwor](https://hub.docker.com/_/php/tags)

## 🧸 Motivation
 - Let admins grant themselves scoped access to parts of the network without exposing everything.
 - Provide a simple web front-end to hand out timed address-list entries without touching RouterOS manually.
 - Keep dependencies minimal (PHP + SQLite) while still supporting OTP and admin workflows.
 - Define profiles per users for quick access

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