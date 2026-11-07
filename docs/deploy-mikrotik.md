# Running PANAG as a MikroTik RouterOS container

Target: RouterOS 7.x with the `container` package, e.g. hEX S (E60iUGS). Images exist for
`arm64` and `arm/v7` (plus `amd64` for x86/CHR).

> **Check the syntax against your RouterOS version.** Container parameter names changed between
> 7.x releases (e.g. `envlist`/`mounts`). The commands below show the structure; adjust names if
> RouterOS rejects them (`/container add ?` lists the valid ones).

## Overview

```
WireGuard client 10.8.0.2 ──► router ──(routed, no NAT)──► veth-panag 172.17.0.2:8080  (PANAG)
                                ▲                                  │
                                └──── REST API https://172.17.0.1 ◄┘  (address-list entries)
```

* PANAG identifies users **by source IP**. Traffic from WireGuard clients to the container must be
  routed **without src-NAT/masquerade**, otherwise every user appears as the router's IP.
* PANAG talks to the router it runs on via the REST API (`www-ssl`).

## 1. Prepare the router

```routeros
# Enable container mode (requires confirming on the device: button press or power cycle)
/system/device-mode/update container=yes

# Storage on USB/microSD (ext4 recommended) – image, tmp and data go there
/disk print
```

## 2. Network for the container

```routeros
/interface/veth add name=veth-panag address=172.17.0.2/24 gateway=172.17.0.1
/interface/bridge add name=br-containers
/ip/address add address=172.17.0.1/24 interface=br-containers
/interface/bridge/port add bridge=br-containers interface=veth-panag
```

Firewall (adapt to your rule set; place before any drop rules):

```routeros
# WireGuard clients -> PANAG web UI
/ip/firewall/filter add chain=forward src-address=10.8.0.0/24 dst-address=172.17.0.2 dst-port=8080 protocol=tcp action=accept comment="PANAG UI"
# PANAG -> router REST API
/ip/firewall/filter add chain=input src-address=172.17.0.2 dst-port=443 protocol=tcp action=accept comment="PANAG REST API"
```

Make sure no `srcnat` rule (e.g. a broad `masquerade`) matches traffic towards `172.17.0.0/24`.
The PANAG login page shows the IP it sees – it must be the WireGuard client IP.

## 3. RouterOS API user for PANAG (least privilege)

```routeros
/user/group add name=panag policy=read,write,rest-api
/user add name=panag group=panag address=172.17.0.2/32 password="<long random password>"
```

Enable HTTPS for the REST API with a certificate (self-signed is fine – PANAG pins its fingerprint):

```routeros
/certificate add name=panag-api common-name=172.17.0.1 key-usage=digital-signature,key-encipherment,tls-server
/certificate sign panag-api
/ip/service set www-ssl certificate=panag-api disabled=no
# Optionally restrict www-ssl to PANAG plus your admin networks (don't lock yourself out of WebFig):
# /ip/service set www-ssl address=172.17.0.2/32,<admin-net>
```

Fingerprint: start PANAG with `MIKROTIK_CERT_FINGERPRINT` empty – the admin **Status** page then
shows the router certificate's SHA-256 fingerprint in the error message. Copy it into the env
variable and restart the container.

## 4. Configuration (environment variables)

All settings are documented in [`.env.example`](../.env.example). Minimal set:

```routeros
/container/envs add name=panag key=MIKROTIK_BASE_URL value=https://172.17.0.1/rest
/container/envs add name=panag key=MIKROTIK_USERNAME value=panag
/container/envs add name=panag key=MIKROTIK_PASSWORD value="<password from step 3>"
/container/envs add name=panag key=MIKROTIK_CERT_FINGERPRINT value=""
/container/envs add name=panag key=LOGIN_IP_WHITELIST value=10.8.0.0/24
/container/envs add name=panag key=APP_TIMEZONE value=Europe/Zurich
```

Never set `APP_ENV=dev` or `TRUSTED_PROXIES` on the router.

Instead of the password variable you can mount a file and use
`MIKROTIK_PASSWORD_FILE=/data/secrets/mikrotik_password`.

## 5. Data mount and container

```routeros
/container/mounts add name=panag-data src=usb1/panag-data dst=/data
```

**Option A – pull from GitHub Container Registry**

```routeros
/container/config set registry-url=https://ghcr.io tmpdir=usb1/tmp
/container add remote-image=muqiuq/panag:latest interface=veth-panag envlist=panag \
    mounts=panag-data root-dir=usb1/panag start-on-boot=yes logging=yes
```

**Option B – offline image file**

Download `panag-<version>-armv7.tar` or `panag-<version>-arm64.tar` from the GitHub release
(or build it with `./run.sh export arm64`), upload it to `usb1/`, then:

```routeros
/container add file=usb1/panag-V0.2-arm64.tar interface=veth-panag envlist=panag \
    mounts=panag-data root-dir=usb1/panag start-on-boot=yes logging=yes
```

Start and watch the log:

```routeros
/container start [find interface=veth-panag]
/log print where topics~"container"
```

Expected: `PANAG <version> listening on :8080 (data: /data)`.

## 6. First admin

Either open `http://172.17.0.2:8080/setup.php` from your WireGuard client (only possible while no
admin exists; set `SETUP_TOKEN` to require an extra secret), or use the CLI inside the container:

```routeros
/container shell [find interface=veth-panag]
```
```sh
php bin/create-admin.php --ip=10.8.0.2 --name="Your Name"
# prints the OTP secret and an otpauth:// URL for your authenticator app
```

## 7. Operations

* **Health:** `http://172.17.0.2:8080/healthz.php` (DB) and `?deep=1` (DB + router API).
  RouterOS Netwatch can probe it with an `http-get` check.
* **Memory:** about 30 MB RSS idle. `APACHE_MAX_WORKERS` (default 5) caps parallel requests.
* **Locked out by the login rate limit:** `/container shell …` then `php bin/reset-login-attempts.php`.
* **Update:** stop and remove the container, add it again with the new image/tag. All data lives in
  the `panag-data` mount and is kept. Database migrations run automatically on start; a consistent
  copy is written to `/data/backups/` first (the newest 5 are kept).
* **Backup:** copy `usb1/panag-data/panag.sqlite`, or use *Users → Export* and *Networks → Export*.

## 8. Security monitoring (optional)

PANAG can watch logins, grants and the location of WireGuard connections (GeoIP, country and network
operator) and mail admins – and the affected user – when something looks unusual. Background and rules:
[plan-security-monitoring.md](plan-security-monitoring.md). Everything is configured with environment
variables; admins see the effective values on **Config** (secrets only as "set") and the state on
**Status → Security monitoring**.

**Secrets as files** (on the data mount, readable by the container only):

```routeros
/file add name=usb1/panag-data/secrets/monitor_token contents="<long random token>"
/file add name=usb1/panag-data/secrets/smtp_password contents="<smtp password>"
```

**Environment:**

```routeros
/container/envs add name=panag key=MONITOR_ENABLED value=true
/container/envs add name=panag key=MONITOR_TOKEN_FILE value=/data/secrets/monitor_token
/container/envs add name=panag key=MONITOR_ALLOWED_COUNTRIES value=CH
/container/envs add name=panag key=APP_BASE_URL value=http://172.17.0.2:8080
/container/envs add name=panag key=SMTP_HOST value=smtp.example.com
/container/envs add name=panag key=SMTP_USERNAME value=panag@example.com
/container/envs add name=panag key=SMTP_PASSWORD_FILE value=/data/secrets/smtp_password
/container/envs add name=panag key=MAIL_FROM value=panag@example.com
/container/envs add name=panag key=ALERT_ADMIN_EMAILS value=security@example.com
```

Admins also get alerts at the e-mail address in their profile. Optional AI triage (pseudonymised facts
only, zero data retention enforced): `MONITOR_AI=openrouter`, `OPENROUTER_API_KEY_FILE`, and
`OPENROUTER_PROVIDERS` – the providers allowed to receive the data (required).

**Scheduler** – runs one monitor cycle every 5 minutes. `monitor.php` only accepts the router's
container-bridge address (`MONITOR_ALLOWED_SOURCES`, default `172.17.0.1/32`) and the token:

```routeros
/system scheduler add name=panag-monitor interval=5m on-event=":do { /tool fetch \
    url=\"http://172.17.0.2:8080/monitor.php\" http-method=post \
    http-header-field=\"X-Monitor-Token: <token>\" output=none } on-error={}"
```

**Outgoing connections of the container** – allow only what is needed (SMTP relay; `download.db-ip.com`
for the monthly GeoIP update, unless `GEOIP_AUTO_UPDATE=false`; `openrouter.ai` only with AI). Outgoing
traffic to the internet may be masqueraded as usual – the no-NAT rule above is only about WireGuard
clients reaching PANAG.

```routeros
/ip/firewall/address-list add list=panag-egress address=download.db-ip.com
/ip/firewall/address-list add list=panag-egress address=smtp.example.com
/ip/firewall/address-list add list=panag-egress address=openrouter.ai
/ip/firewall/filter add chain=forward src-address=172.17.0.2 dst-address-list=panag-egress protocol=tcp dst-port=443,465,587 action=accept comment="PANAG egress"
/ip/firewall/filter add chain=forward src-address=172.17.0.2 out-interface-list=WAN action=drop comment="PANAG: no other egress"
```

**GeoIP without internet:** download `dbip-country-lite-YYYY-MM.mmdb.gz` and `dbip-asn-lite-YYYY-MM.mmdb.gz`
from [db-ip.com](https://db-ip.com/db/lite.php) (CC BY 4.0), unpack and upload them on the monitoring page,
or copy them to `usb1/panag-data/geoip/country.mmdb` and `asn.mmdb`.

**Check after setup:**

* *Status → Security monitoring* shows the last cycle (≤ 5 min ago), the WireGuard peers with endpoint,
  country and network, and both GeoIP databases. *Send test mail* must arrive.
* The peers table shows the real public endpoint of your phone/laptop – this confirms that RouterOS
  reports `current-endpoint-address` and `last-handshake` as PANAG expects (planned check of phase 0).
* *Config* lists no configuration problems.

## Migrating from the pre-container layout (V0.1)

* Settings moved from `config/config.php` to environment variables (step 4).
* Copy the old `data/panag.sqlite` into the new data mount. On first start it is migrated
  (admins keep the admin role, everybody else becomes a user; a backup is written beforehand).
  `setup-completed.txt` is no longer used – setup stays disabled because the database contains an admin.
* Old user exports (`isadmin: 0/1`) can still be imported.
