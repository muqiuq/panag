# Installing PANAG on a MikroTik router

This manual installs PANAG as a container on the MikroTik router that also terminates the admins' WireGuard
VPN. At the end, admins connect via WireGuard, log in to PANAG with a one-time password and grant themselves
time-limited access to the networks they need. Everything else stays blocked.

You need basic RouterOS skills (terminal or WebFig) and about an hour.

> **Check the syntax against your RouterOS version.** The container commands follow the current RouterOS 7
> documentation (`/container/envs` and `/container/mounts` with `list=`, `/container/add` with `envlist=` and
> `mountlists=`); older 7.x releases used other names. If RouterOS rejects a parameter, `?` lists the valid
> ones (e.g. `/container/add ?`).

## Contents

1. [How it works](#1-how-it-works)
2. [Requirements](#2-requirements)
3. [Prepare the router](#3-prepare-the-router)
4. [WireGuard for the admins](#4-wireguard-for-the-admins)
5. [Network for the container](#5-network-for-the-container)
6. [Firewall](#6-firewall)
7. [RouterOS API user for PANAG](#7-routeros-api-user-for-panag)
8. [Configuration](#8-configuration)
9. [Install and start the container](#9-install-and-start-the-container)
10. [Certificate fingerprint](#10-certificate-fingerprint)
11. [First admin](#11-first-admin)
12. [First steps and a test](#12-first-steps-and-a-test)
13. [Security monitoring (optional)](#13-security-monitoring-optional)
14. [Operations: update, backup, restore](#14-operations-update-backup-restore)
15. [Troubleshooting](#15-troubleshooting)
16. [Migrating from V0.1](#16-migrating-from-v01)

## 1. How it works

```
admin laptop ──WireGuard──► router ──(routed, no NAT)──► veth-panag 172.17.0.2:8080  (PANAG container)
  10.8.0.2                    │  ▲                                     │
                              │  └──── REST API https://172.17.0.1 ◄───┘  writes address-list entries
                              ▼
               firewall: 10.8.0.2 may reach the networks in the list "Whitelist 10.8.0.2"
```

* **Users are identified by their WireGuard tunnel IP.** Every admin has one WireGuard peer with one fixed
  address (`10.8.0.2/32`). In PANAG, this address is the user's "user IP". The login only asks for the
  one-time password.
* **A grant is an address-list entry with a timeout.** When Jane (10.8.0.2) grants herself the network
  "Datacenter" (`192.168.100.0/24`) for 2 hours, PANAG adds `192.168.100.0/24` to the address list
  `Whitelist 10.8.0.2` with a timeout of 2 hours. RouterOS removes the entry when it expires.
* **One firewall rule per user** lets traffic from 10.8.0.2 through to the addresses in `Whitelist 10.8.0.2`.
  A final rule drops all other traffic from the VPN.
* PANAG runs in a container on the same router and talks to it via the RouterOS REST API.

## 2. Requirements

| What | Details |
|------|---------|
| Router | RouterOS 7.x on an **ARM, ARM64 or x86** CPU, for example the hEX S (2025, E60iUGS). MIPS devices (for example the older hEX S RB760iGS) cannot run containers. Check with `/system/resource/print`: `architecture-name` must be `arm`, `arm64` or `x86_64`. |
| Storage | USB stick or microSD card, formatted as **ext4**, a few hundred MB free. The image (about 40 MB, up to 100 MB on 32-bit ARM), its unpacked files and the database go there, not into the router's flash. |
| Memory | About 30 MB for the container when idle. |
| Clock | Correct time on the router (NTP). One-time passwords only work with the right time. |
| Clients | WireGuard on the admins' devices, an authenticator app (any TOTP app: Aegis, Google Authenticator, 1Password, …). |

**Addresses used in this manual** – replace them with your own:

| Purpose | Example |
|---------|---------|
| WireGuard interface / network | `wg-admin`, `10.8.0.0/24`, router `10.8.0.1` |
| Admin "Jane Doe" | WireGuard address `10.8.0.2` |
| Container bridge / router side | `br-containers`, `172.17.0.1/24` |
| PANAG container | `veth-panag`, `172.17.0.2`, web UI on port `8080` |
| Storage | `usb1` |

## 3. Prepare the router

**Container package.** Download the "Extra packages" for your RouterOS version and architecture from
[mikrotik.com/download](https://mikrotik.com/download), upload `container-<version>-<arch>.npk` to *Files*
and reboot. `/system/package/print` then lists `container`.

**Container mode.** It has to be confirmed on the device itself:

```routeros
/system/device-mode/update container=yes
```

RouterOS then asks you to press the reset button or to cut the power within a few minutes.

**Storage.** Plug in the USB stick or microSD card and format it as ext4 (WebFig: *System → Disks →
Format Drive*). `/disk/print` shows its name, here `usb1`.

**Time.** PANAG takes the time from the router:

```routeros
/system/ntp/client/set enabled=yes servers=pool.ntp.org
/system/clock/set time-zone-name=Europe/Zurich
```

## 4. WireGuard for the admins

Skip this section if your admins already connect via WireGuard. Make sure each admin has **one peer with one
`/32` address**. PANAG and its security monitoring rely on that.

```routeros
/interface/wireguard/add name=wg-admin listen-port=13231
/ip/address/add address=10.8.0.1/24 interface=wg-admin
/ip/firewall/filter/add chain=input protocol=udp dst-port=13231 action=accept comment="WireGuard admins"

# one peer per admin – allowed-address is the admin's PANAG user IP
/interface/wireguard/peers/add interface=wg-admin public-key="<public key of Jane's device>" \
    allowed-address=10.8.0.2/32 comment="Jane Doe"
```

On Jane's device, the tunnel gets the address `10.8.0.2/32`. Its `AllowedIPs` must cover the container
(`172.17.0.2/32`) and the networks PANAG will grant, for example `172.17.0.0/24, 192.168.100.0/24`. Leave
out *Endpoint* routes you don't want through the tunnel.

## 5. Network for the container

```routeros
/interface/veth/add name=veth-panag address=172.17.0.2/24 gateway=172.17.0.1
/interface/bridge/add name=br-containers
/ip/address/add address=172.17.0.1/24 interface=br-containers
/interface/bridge/port/add bridge=br-containers interface=veth-panag
```

## 6. Firewall

Adapt the rules to your rule set. They must come **before** any drop rule that would match the same
traffic. `place-before=` or dragging in WebFig puts them in the right order.

**6.1 Reach PANAG, let PANAG reach the router**

```routeros
# WireGuard admins -> PANAG web UI
/ip/firewall/filter/add chain=forward in-interface=wg-admin dst-address=172.17.0.2 protocol=tcp dst-port=8080 \
    action=accept comment="PANAG UI"
# PANAG -> router REST API
/ip/firewall/filter/add chain=input src-address=172.17.0.2 protocol=tcp dst-port=443 action=accept comment="PANAG REST API"
```

**6.2 No NAT between WireGuard and PANAG.** PANAG must see the admin's tunnel IP. Make sure no `srcnat`
rule (for example a broad `masquerade`) matches traffic from `10.8.0.0/24` to `172.17.0.0/24`. The PANAG
login page shows the IP it sees. It must be the tunnel IP (`10.8.0.2`), not `172.17.0.1`.

**6.3 The access rules.** This is what turns a grant into access:

```routeros
# replies to allowed connections (most rule sets already have this rule at the top)
/ip/firewall/filter/add chain=forward connection-state=established,related action=accept comment="established, related"

# one rule per PANAG user: from the user's tunnel IP to the networks PANAG granted to this user
/ip/firewall/filter/add chain=forward in-interface=wg-admin src-address=10.8.0.2 \
    dst-address-list="Whitelist 10.8.0.2" action=accept comment="PANAG: Jane Doe"

# everything else from the VPN is blocked – this rule comes last
/ip/firewall/filter/add chain=forward in-interface=wg-admin action=drop comment="PANAG: not granted"
```

* The list name is `ADDRESS_LIST_PREFIX` (default `Whitelist `, with a trailing space) followed by the user
  IP. RouterOS creates the list with the first entry; the rule can exist before that.
* **Every new PANAG user needs such a rule.** Without it, the user can grant themselves access in PANAG,
  but the router still blocks the traffic.
* Grants are entries with a timeout. RouterOS does not keep them across a **reboot** – after a restart the
  admins simply grant again.

## 7. RouterOS API user for PANAG

PANAG only needs to read and write address lists (and, for the security monitoring, read the WireGuard
peers):

```routeros
/user/group/add name=panag policy=read,write,rest-api
/user/add name=panag group=panag address=172.17.0.2/32 password="<long random password>"
```

The REST API runs over HTTPS (`www-ssl`). A self-signed certificate is fine – PANAG pins its fingerprint
(section 10):

```routeros
/certificate/add name=panag-api common-name=172.17.0.1 key-usage=digital-signature,key-encipherment,tls-server
/certificate/sign panag-api
/ip/service/set www-ssl certificate=panag-api disabled=no
# optionally restrict www-ssl to PANAG plus your admin network (don't lock yourself out of WebFig):
# /ip/service/set www-ssl address=172.17.0.2/32,10.8.0.0/24
```

## 8. Configuration

PANAG is configured with environment variables. All of them are documented in
[`.env.example`](.env.example); admins see the effective values on PANAG's *Config* page (secrets only as
"set"). The minimal set:

```routeros
/container/envs/add list=panag key=MIKROTIK_BASE_URL value=https://172.17.0.1/rest
/container/envs/add list=panag key=MIKROTIK_USERNAME value=panag
/container/envs/add list=panag key=MIKROTIK_PASSWORD value="<password from section 7>"
/container/envs/add list=panag key=MIKROTIK_CERT_FINGERPRINT value=""
/container/envs/add list=panag key=LOGIN_IP_WHITELIST value=10.8.0.0/24
/container/envs/add list=panag key=WIREGUARD_INTERFACE value=wg-admin
/container/envs/add list=panag key=APP_TIMEZONE value=Europe/Zurich
/container/envs/add list=panag key=APP_BASE_URL value=http://172.17.0.2:8080
```

* `LOGIN_IP_WHITELIST`: only these addresses see the login form – the WireGuard network.
* **Never set `APP_ENV=dev` or `TRUSTED_PROXIES`** on the router. Both would let users pretend to be someone
  else.
* **Secrets as files:** instead of `MIKROTIK_PASSWORD`, put the password into a file on the data mount and set
  `MIKROTIK_PASSWORD_FILE=/data/secrets/mikrotik_password`. Every variable accepts the `_FILE` form.
* PANAG is plain HTTP on port 8080. That is fine as long as it is only reachable through WireGuard, which
  encrypts the traffic – don't expose it to other networks.

## 9. Install and start the container

**Which image?** There is one image per architecture, tagged with the version plus the architecture, for example
`v2.2-arm`. Pick it by `architecture-name` (`/system/resource/print`): `arm` → `-arm` (hEX S E60iUGS),
`arm64` → `-arm64`, `x86_64` → `-amd64`. Up to V2.1 there was one multi-arch tag per version (`v2.1`), from which
RouterOS picked the architecture itself. The `arm` image is Debian armel (soft-float, `linux/arm/v5`): in RouterOS
on the hEX S, every `arm/v7` image stops right away with `exited with signal 4 (Illegal instruction)` – V2.0's and
V2.1's `arm` images too. On a 32-bit ARM router use V2.2 or later.

The database lives on the data mount and survives updates:

```routeros
/container/mounts/add list=panag-data src=usb1/panag-data dst=/data
```

**Option A – pull from the GitHub Container Registry** (the router needs internet access), here V2.2 on a hEX S:

```routeros
/container/config/set registry-url=https://ghcr.io tmpdir=usb1/tmp
/container/add remote-image=muqiuq/panag:v2.2-arm interface=veth-panag envlist=panag \
    mountlists=panag-data root-dir=usb1/panag start-on-boot=yes logging=yes
```

There is no `latest` tag, so an update only happens when you change the tag.

**Option B – image file** (no internet needed): download `panag-<version>-<arch>.tar` from the
[GitHub release](https://github.com/muqiuq/panag/releases), upload it to `usb1/`, then:

```routeros
/container/add file=usb1/panag-v2.2-arm.tar interface=veth-panag envlist=panag \
    mountlists=panag-data root-dir=usb1/panag start-on-boot=yes logging=yes
```

**Start and watch the log:**

```routeros
/container/start [find interface=veth-panag]
/log/print where topics~"container"
```

Expected: `PANAG V2.1 listening on :8080 (data: /data)`. Configuration problems are listed in the log at
start and on PANAG's *Config* page.

## 10. Certificate fingerprint

PANAG only talks to the router's REST API if the certificate's SHA-256 fingerprint matches
`MIKROTIK_CERT_FINGERPRINT`. You get the fingerprint from PANAG itself:

1. With the fingerprint still empty, log in as admin (section 11) and open *Status*. The router check fails
   ("API error"), and the users overview below shows the router certificate as *Peer fingerprint*.
2. Copy it into the variable (colons are optional) and restart the container:

```routeros
/container/envs/set [find list=panag key=MIKROTIK_CERT_FINGERPRINT] value="AB:CD:…"
/container/stop [find interface=veth-panag]
/container/start [find interface=veth-panag]
```

*Status* now shows "API OK". If you renew the router certificate, update the fingerprint.

## 11. First admin

**Variant A – in the browser.** From the first admin's WireGuard device, open
`http://172.17.0.2:8080/setup.php`. It only works while no admin exists. Set `SETUP_TOKEN` beforehand if
the page should also ask for a secret. Scan the QR code with the authenticator app.

**Variant B – on the router:**

```routeros
/container/shell [find interface=veth-panag]
```
```sh
php bin/create-admin.php --ip=10.8.0.2 --name="Jane Doe"
# prints the OTP secret and an otpauth:// URL for the authenticator app
```

Then open `http://172.17.0.2:8080/` from that device and log in with the code from the app. The login page
shows the IP PANAG sees – it must be `10.8.0.2`.

## 12. First steps and a test

1. **Networks** → *Add network*: name, address (`192.168.100.0/24` or a single host) and access level. Users
   need at least this level to grant the network. Mark a network as **sensitive** if it must never be part
   of anyone's default access.
2. **Users** → *Add user*: name, **user IP = the WireGuard address** of that person, role (user, superuser,
   admin) and access level. On the user page, tab *OTP*, *Reveal secret and QR code* shows the QR code for the
   authenticator app (revealing is logged).
3. **Firewall:** add the rule from section 6.3 for every new user.
4. **Default networks** (optional): on the user page or in the *Matrix*. "Grant default access" grants them all
   at once.
5. **Test:** log in as the user, type the network name in the search field and press Enter twice. Then check on
   the router:

```routeros
/ip/firewall/address-list/print where list="Whitelist 10.8.0.2"
```

The entry is there with a timeout, and the user reaches the network. *Revoke my access* removes it again.

## 13. Security monitoring (optional)

PANAG can watch logins, grants and where WireGuard connections come from (country and network operator via
GeoIP) and mail the admins – and the affected user ("Was this you?") – when something looks unusual.
Background: [docs/plan-security-monitoring.md](docs/plan-security-monitoring.md). The rules can be switched
off, given another severity and tuned on *Alerts → Configure rules*; the environment variables below are
their defaults.

**Secrets as files** (on the data mount):

```routeros
/file/add name=usb1/panag-data/secrets/smtp_password contents="<smtp password>"
```

**Environment:**

```routeros
/container/envs/add list=panag key=MONITOR_ENABLED value=true
/container/envs/add list=panag key=MONITOR_ALLOWED_COUNTRIES value=CH
/container/envs/add list=panag key=SMTP_HOST value=smtp.example.com
/container/envs/add list=panag key=SMTP_USERNAME value=panag@example.com
/container/envs/add list=panag key=SMTP_PASSWORD_FILE value=/data/secrets/smtp_password
/container/envs/add list=panag key=MAIL_FROM value=panag@example.com
/container/envs/add list=panag key=ALERT_ADMIN_EMAILS value=security@example.com
```

Admins also get alerts at the e-mail address in their profile. Optional AI triage (only pseudonymised facts,
zero data retention enforced): `MONITOR_AI=openrouter`, `OPENROUTER_API_KEY_FILE` and `OPENROUTER_PROVIDERS`
(the providers allowed to receive the data; required).

**Scheduler** – one monitor cycle every 5 minutes. `monitor.php` only accepts calls from the router's bridge
address (`MONITOR_ALLOWED_SOURCES`, default `172.17.0.1/32`) with the monitor token. PANAG generates the token
on its first start with `MONITOR_ENABLED=true` and writes it to `usb1/panag-data/monitor.token`. The scheduler
reads it from there on every run, so you never copy it:

```routeros
/system/scheduler/add name=panag-monitor interval=5m on-event=":do { /tool fetch \
    url=\"http://172.17.0.2:8080/monitor.php\" http-method=post \
    http-header-field=(\"X-Monitor-Token: \" . [/file/get \"usb1/panag-data/monitor.token\" contents]) \
    output=none } on-error={}"
```

**Outgoing connections of the container** – allow only what is needed: the SMTP relay,
`download.db-ip.com` for the monthly GeoIP update (unless `GEOIP_AUTO_UPDATE=false`) and `openrouter.ai`
only with AI triage. For names to resolve, the container needs a DNS server (for example the router:
`dns=172.17.0.1` on the container and `/ip/dns/set allow-remote-requests=yes`, allowed only from
`172.17.0.2`). Outgoing traffic to the internet may be masqueraded as usual – section 6.2 is only about
WireGuard clients reaching PANAG.

```routeros
/ip/firewall/address-list/add list=panag-egress address=download.db-ip.com
/ip/firewall/address-list/add list=panag-egress address=smtp.example.com
/ip/firewall/address-list/add list=panag-egress address=openrouter.ai
/ip/firewall/filter/add chain=forward src-address=172.17.0.2 dst-address-list=panag-egress protocol=tcp \
    dst-port=443,465,587 action=accept comment="PANAG egress"
/ip/firewall/filter/add chain=forward src-address=172.17.0.2 out-interface-list=WAN action=drop comment="PANAG: no other egress"
```

**GeoIP without internet:** download `dbip-country-lite-YYYY-MM.mmdb.gz` and `dbip-asn-lite-YYYY-MM.mmdb.gz`
from [db-ip.com](https://db-ip.com/db/lite.php) (CC BY 4.0), unpack them and upload them on PANAG's
*Monitoring* page, or copy them to `usb1/panag-data/geoip/country.mmdb` and `asn.mmdb`.

**Check after setup:**

* *Monitoring* shows the last cycle (at most 5 minutes ago), the WireGuard peers with endpoint, country and
  network, and both GeoIP databases. *Send test mail* must arrive.
* The peers table shows the real public address of your laptop or phone. This confirms that RouterOS reports
  the WireGuard fields as PANAG expects.
* *Config* lists no configuration problems.

## 14. Operations: update, backup, restore

* **Health check:** `http://172.17.0.2:8080/healthz.php` (database) and `?deep=1` (database and router API).
  RouterOS Netwatch can probe it with an `http-get` check.
* **Update:** back up first (below). Then stop and remove the container and add it again with the new version
  (`remote-image=muqiuq/panag:<new version>-<arch>` or the new image file). All data lives in the `panag-data` mount
  and is kept. Database migrations run automatically at start; a copy of the database is written to
  `/data/backups/` first (the newest 5 are kept).
* **Backup:** *Config → Backup and restore*. *Download full backup* saves all data in one JSON file: users with
  their OTP secrets, networks, default networks, rule settings, audit log, alerts. Users and networks can also
  be exported on their own. Store the files safely – they contain the OTP secrets. Environment variables and
  the files in `/data` (GeoIP databases, generated keys) are not included; keep your `/container/envs`
  export with the backup.
* **Restore:** *Config → Backup and restore → Restore everything*, then type `RESTORE`. All current data is
  replaced; a copy of the current database is saved to `/data/backups/` first. Backups of older PANAG versions
  are migrated automatically.
* **Locked out by the login rate limit:** `/container/shell [find interface=veth-panag]`, then
  `php bin/reset-login-attempts.php`.

## 15. Troubleshooting

| Symptom | Cause and fix |
|---------|---------------|
| The login page shows `172.17.0.1` instead of the tunnel IP | A `srcnat`/`masquerade` rule hits the traffic – exclude `10.8.0.0/24` → `172.17.0.0/24` (section 6.2). |
| "There is nothing here." instead of the login form | The client IP is not in `LOGIN_IP_WHITELIST`. |
| "Invalid OTP or user not found." with a correct code | The router clock is wrong – the login page shows the server time (section 3) – or the user IP in PANAG doesn't match the WireGuard address shown as *User IP*. |
| *Status*: certificate or API error | Fingerprint missing or outdated (section 10); `www-ssl` disabled; firewall input rule from `172.17.0.2` missing; API user restricted to another address. |
| Grant succeeds, but the network is not reachable | Firewall rule for this user missing or below the drop rule (section 6.3); list name not `Whitelist <user IP>`; the device's `AllowedIPs` don't cover the network. |
| *Monitoring*: "No monitor cycle in the last 15 minutes" | Scheduler missing, `usb1/panag-data/monitor.token` missing (`MONITOR_ENABLED=true` set? container restarted?) or at another path than in the scheduler, or the call doesn't come from `172.17.0.1` (`MONITOR_ALLOWED_SOURCES`). |
| The container does not start | `/log/print where topics~"container"`; wrong image architecture; storage full; container mode not confirmed. |
| The container stops with `exited with signal 4 (Illegal instruction)` | The image's binaries don't run on this CPU. On 32-bit ARM (`architecture-name` `arm`) only the `arm` image from V2.2 on (Debian armel, `arm/v5`) works, not the `arm/v7` images of V2.0 and V2.1 (section 9). |

## 16. Migrating from V0.1

* Settings moved from `config/config.php` to environment variables (section 8).
* Copy the old `data/panag.sqlite` into the new data mount. On the first start it is migrated (admins keep the
  admin role, everybody else becomes a user; a backup is written first). `setup-completed.txt` is no longer
  used – setup stays disabled because the database contains an admin.
* Old user exports (`isadmin: 0/1`) can still be imported.
