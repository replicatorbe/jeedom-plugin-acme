# ACME plugin (Let's Encrypt)

Automatically obtains and renews a **free TLS certificate** for your Jeedom
from Let's Encrypt, ZeroSSL or any ACME-compatible authority, then, if you
wish, installs it in the Jeedom web server to switch to **HTTPS**.

- **DNS-01 validation** through your DNS provider's API (OVHcloud for now): no
  port to open on the router, works for a purely local Jeedom, and allows
  wildcard certificates (`*.mydomain.com`).
- **HTTP-01 validation** for those who already forward public port 80 to Jeedom.
- **Automatic renewal** every day, with **alerts** in the message center and
  through the commands of your choice (mail, Telegram, SMS…) if expiry
  approaches or a renewal fails.
- **Web server installation** (Apache; nginx semi-automatic), with backup,
  configuration test and automatic rollback.
- **No dependency**: no certbot, no acme.sh, no package to install. The plugin
  is written in PHP, using only the extensions Jeedom already requires.

## Contents

1. [Requirements](#requirements)
2. [How it works](#how-it-works)
3. [DNS-01 or HTTP-01?](#dns-01-or-http-01)
4. [Step by step: OVHcloud with DNS-01](#step-by-step-ovhcloud-with-dns-01)
5. [Step by step: HTTP-01](#step-by-step-http-01)
6. [Authorities: Let's Encrypt, staging, ZeroSSL, other](#authorities-lets-encrypt-staging-zerossl-other)
7. [Web server installation](#web-server-installation)
8. [Docker](#docker)
9. [nginx](#nginx)
10. [Renewal and alerts](#renewal-and-alerts)
11. [Commands](#commands)
12. [Clean uninstall](#clean-uninstall)
13. [Troubleshooting](#troubleshooting)
14. [FAQ](#faq)

## Requirements

- **A public domain name** you own, for example `jeedom.mydomain.com`. No
  public authority certifies a private name: `jeedom.local`, `house.lan`,
  `box.home` or an IP address such as `192.168.1.10` are refused, by the
  authority as well as by the plugin.
- With DNS-01, the name **does not need to point to your public address**: it
  may point to Jeedom's local address (`192.168.1.10`) in your public DNS, or
  only in your router's DNS. With HTTP-01, however, it must point to your
  public IP address.
- For DNS-01 validation: a domain whose DNS zone is hosted by a supported
  provider (OVHcloud).
- Jeedom 4.4 or later, PHP 7.4 to 8.4 (official installation, Smart, Luna,
  Atlas, Raspberry Pi, Docker, manual installation).

## How it works

A plugin **device** is **one certificate**. On it you set the domain(s), the
authority, the validation method and, optionally, the web server installation.

1. **Test (staging)**: full trial against the Let's Encrypt test server. No
   rate limits, nothing is installed. Do this first.
2. **Get the certificate**: the real request. Depending on the method, the
   plugin creates a DNS record or a file, the authority checks it, issues the
   certificate, and the plugin removes what it created.
3. **Install in the web server**: the button of that name, or the
   "Automatically install" box ticked *before* getting the certificate (it is
   then installed as soon as it is issued, and after each renewal). The web
   server is gracefully reloaded.
4. **Check** that `https://<your name>` opens without a browser warning.
5. **Only then**, enable **Redirect HTTP to HTTPS**, and install again.
6. Every day, the plugin checks the expiry date and renews when needed.

> **From the local network, the name must resolve to Jeedom's local IP
> address**, otherwise the browser will not find Jeedom by that name. Three
> options:
> - a **local DNS** answering the local address for that name (router DNS,
>   Pi-hole, AdGuard Home…);
> - a **public A record** pointing to the private address
>   (`jeedom.mydomain.com → 192.168.1.10`): harmless, that address is only
>   reachable at home; DNS-01 only;
> - the router's **NAT loopback** (*hairpin NAT*), if the name points to your
>   public address and the router can send connections coming from inside back
>   to Jeedom.

An issuance can take several minutes (waiting for DNS propagation). It
therefore runs **as a background task**: the page shows the current step and
the last log lines, and you can leave it without interrupting anything.

Keys and certificates are stored in the plugin's `data/` folder (folders
`0700`, files `0600`, web access denied). The ACME account is created once per
authority, then reused.

## DNS-01 or HTTP-01?

To prove that you control the domain, the authority offers two challenges.

| | DNS-01 (recommended) | HTTP-01 |
|---|---|---|
| What the plugin does | creates a TXT record `_acme-challenge.<domain>` through the DNS provider's API | puts a file in `/.well-known/acme-challenge/` |
| Port to open on the router | **none** | **public port 80 → Jeedom:80**, mandatory |
| Purely local Jeedom | yes | no |
| Wildcard certificate `*.domain` | yes | no |
| What you need | API keys from the DNS provider | the name points to your public IP, port 80 forwarded |

### The HTTP-01 trap: port 80, and nothing else

The authority **always connects to port 80** of the public address of the
name. It follows HTTP redirects, but **only to ports 80 and 443**.

```
                        Internet                           Local network
 Let's Encrypt ──http://jeedom.mydomain.com:80──▶ Router ──────────▶ Jeedom:80    ✔ works
                                                 (NAT 80 → 192.168.1.10:80)

 Let's Encrypt ──http://jeedom.mydomain.com:80──▶ Router    nothing on port 80  ✘ fails
                                                 (NAT 9002 → 192.168.1.10:80)
```

A router forward "public port **9002** → Jeedom:80", very common for remote
access to Jeedom, **is not enough**: the authority will never come to port
9002. You need "public port **80** → Jeedom:80". If public port 80 is already
taken (another server, a router that reserves it), or if you do not want to
open anything: use **DNS-01**.

## Step by step: OVHcloud with DNS-01

### 1. Create an API token with restricted rights

1. On the device page, choose **Method: DNS-01**, **DNS provider:
   OVHcloud**, then the **API endpoint**:
   - **OVHcloud Europe** (`ovh-eu`) for a European OVH account: the usual
     case in France and Belgium;
   - `ovh-ca` / `ovh-us` for Canadian and US accounts;
   - `kimsufi-*` and `soyoustart-*` for those brands.
2. Click **Create an OVH token**. The OVHcloud token creation page opens,
   pre-filled with only the required rights:
   - `GET /domain/zone`
   - `GET /domain/zone/*`
   - `POST /domain/zone/*`
   - `DELETE /domain/zone/*`
3. Log in with the OVH account that manages the domain, name the application
   (for example "Jeedom ACME"), and choose an **unlimited validity**:
   otherwise automatic renewals will stop when the token expires.
4. To restrict it further, replace `*` with your zone name:
   `/domain/zone/mydomain.com/*` (and keep `GET /domain/zone`, used to find
   the zone).
5. OVHcloud shows three values: **Application Key**, **Application Secret**
   and **Consumer Key**. The Application Secret is shown only once.

### 2. Fill in the device

1. Copy the three keys into the matching fields.
2. Click **Test DNS access**: the plugin checks the keys and rights with
   OVHcloud and summarises what it sees, without changing anything in the
   zone. The fields are used as typed: no need to save first.
3. Enter the **domain(s)**, for example `jeedom.mydomain.com`.
4. **Save**, then **Test (staging)**. Follow the progress in the "Current
   task" panel: TXT record creation, waiting for propagation on OVH's DNS
   servers, validation, removal.
5. If the test succeeds: **Get the certificate**.
6. **Install in the web server** (or tick automatic installation before step
   5), check `https://jeedom.mydomain.com`, and only then enable the HTTP →
   HTTPS redirect (see [Web server installation](#web-server-installation)).

The **propagation wait** (**300 s by default**, 30 to 3600 s on the device)
bounds the time spent waiting for the TXT record on all authoritative servers
of the zone. The plugin queries them directly; if outgoing port 53 is blocked,
it falls back to DNS-over-HTTPS (Cloudflare, Google).

If the record is still not visible everywhere when that delay runs out, the
plugin **stops with an error without asking the authority to validate**: the
record is removed and **no Let's Encrypt attempt is used up** (failed
validations are limited per hour). Increase the delay and try again.

## Step by step: HTTP-01

1. On the router: forward **public port 80** to **Jeedom, port 80** (see
   [the HTTP-01 trap](#the-http-01-trap-port-80-and-nothing-else)).
2. In the public DNS: the name must point to your **public IP address**.
3. On the device page: **Method: HTTP-01**. An empty **web root** is fine for
   a standard installation (Jeedom root).
4. Save, **Test (staging)**, then **Get the certificate**.
5. **Install in the web server**, check `https://<your name>`, and only then
   enable the redirect. From home, the name points here to your public
   address: you need the router's NAT loopback or a local DNS (see
   [How it works](#how-it-works)).

Before contacting the authority, the plugin checks that it can read the
challenge file itself. If it cannot through the public address, your router
probably does not do "NAT loopback": this is not blocking, the authority comes
from outside.

## Authorities: Let's Encrypt, staging, ZeroSSL, other

- **Let's Encrypt**: the default. 90-day certificates (shorter in the future:
  the plugin adapts, see renewal). The e-mail address is optional.
- **Let's Encrypt staging**: the test server. Its certificates **are not
  trusted by any browser**. Chosen as the authority, it checks the setup end to
  end; the plugin refuses to install such a certificate in the web server. The
  **Test (staging)** button does the same on demand, whatever the chosen
  authority, without touching the real certificate.
- **ZeroSSL**: requires an **e-mail address** (on the device or in the plugin
  configuration) and an External Account Binding (EAB). Leave the EAB fields
  **empty**: the plugin obtains the credentials from ZeroSSL using the e-mail
  address, then stores them in the device. You can also enter the ones from
  your ZeroSSL dashboard (*Developer → EAB Credentials*).
- **Other ACME authority**: enter the directory URL (`https://…/directory`)
  and, if required, the EAB credentials it provides.

## Web server installation

Tick **Automatically install in the Jeedom web server**: after each issuance
or renewal, the plugin

1. copies the certificate and key to `/etc/ssl/jeedom-acme/` (key `0600`): the
   web server never depends on the plugin folder;
2. backs up the existing configuration;
3. writes the HTTPS configuration (files marked "managed by the Jeedom acme
   plugin") and enables the SSL module if needed;
4. **tests the configuration** (`apachectl -t` / `nginx -t`);
5. reloads the server **gracefully**: no connection is dropped.

If the test fails, **everything is restored** and the error is shown: a
working server keeps working. The **Install in the web server** and
**Uninstall from the web server** buttons do the same on demand.

Options:

- **HTTPS port**: 443 by default.
- **Public HTTPS port**: fill it in if your router publishes Jeedom on another
  port than the local HTTPS port, for instance **public port 9003 →
  Jeedom:443** to avoid exposing the heavily scanned 443. The redirect then
  points to `https://<your name>:9003`. Empty: same as the HTTPS port.

  Example with Home Assistant on the same router: public port 9000 → HA:8123,
  9002 → Jeedom:80 (HTTP), 9003 → Jeedom:443 (HTTPS). Both certificates carry
  the same name without interfering: a certificate is tied to the name, not the
  port.
- **Redirect HTTP to HTTPS**: every `http://` visit goes to `https://`, except
  `/.well-known/acme-challenge/` (needed for HTTP-01). **Enable it only after
  checking `https://` access.**

The recommended order:

1. install (**Install in the web server** button, or automatic installation
   ticked before **Get the certificate**);
2. open `https://<your name>` and check there is no warning;
3. **only then**, tick **Redirect HTTP to HTTPS**, save and install again.

> Always keep a way to reach Jeedom over `http://` through its local IP address
> until HTTPS has been checked. The certified name must resolve to Jeedom's
> local IP address from your browser: local DNS (router, Pi-hole…), public A
> record to the private address, or the router's NAT loopback (see
> [How it works](#how-it-works)); failing that, the computer's `hosts` file.
> Otherwise the browser will not find Jeedom, or will report a name mismatch.

The web server has **a single HTTPS configuration** for the whole of Jeedom:
only one certificate can be installed at a time, and **Uninstall from the web
server** removes Jeedom's HTTPS whichever device it is run from.

The **Analyse the system** button, in the plugin configuration, tells whether
automatic installation is possible and why.

### Compatibility

| Platform | Issuance (DNS-01 / HTTP-01) | Automatic HTTPS installation |
|---|---|---|
| Debian / Raspberry Pi OS / Ubuntu + Apache (official Jeedom installation, Smart, Luna, Atlas) | yes | yes |
| Docker (official Jeedom image, Apache) | yes | yes (no systemd: `apachectl -k graceful`), provided port 443 is published |
| RHEL / Fedora / Alma / Rocky + Apache | yes | yes if `mod_ssl` is installed |
| Alpine + Apache | yes | yes if `apache2-ssl` is installed |
| nginx | yes | semi-automatic: configuration file generated, include to be added by hand |
| Other / no root rights | yes | no: the PEM files can be downloaded and used elsewhere (reverse proxy, NAS…) |

Installation uses `sudo` (the `www-data` account of a Jeedom installation has
it without password).

### Using the certificate elsewhere

The **Download fullchain** and **Download the key** buttons give the PEM files
(administrators only; each key download is recorded in the log). They suit a
reverse proxy (nginx, HAProxy, Traefik), a NAS, a router… Remember to copy
them again after each renewal.

## Docker

- Issuance works without any particular setting.
- For automatic installation, the container must **publish the HTTPS port**:
  `-p 443:443` (or the chosen port) in `docker run`, or `ports: ["443:443"]`
  in `docker-compose.yml`. Otherwise Apache listens for HTTPS inside the
  container but nobody can reach it.
- Without systemd, reloading uses `apachectl -k graceful`.
- The Apache configuration lives in the container: if it is recreated from the
  image, run **Install in the web server** again (the certificate itself is
  kept in the plugin folder if it is on a volume).

## nginx

The plugin generates the HTTPS configuration file and copies the certificates,
but **does not include** that file in your nginx configuration: every nginx
setup is organised differently. The path of the generated snippet and the
steps to follow are shown in the task log: add `include <snippet>;` in a
`server { listen 443 ssl; server_name <domain>; … }` block serving Jeedom, then
test with `nginx -t` and reload with `systemctl reload nginx`. If the snippet
is already included, the plugin simply reloads nginx. Before "Uninstall from
the web server", remove that `include`.

> **Mandatory: deny web access to `plugins/acme/data/`.** nginx ignores
> `.htaccess` files: without an explicit rule, the private keys stored in
> `data/` could be downloaded by anyone. The generated snippet contains the
> rule; but **every** `server` block serving Jeedom, including the port 80
> one, must carry it:
>
> ```nginx
> location ^~ /plugins/acme/data/ { deny all; }
> ```
>
> Then check that `http://<jeedom>/plugins/acme/data/` answers `403`.

## Renewal and alerts

- **Every day**, the plugin updates the commands of each enabled device and
  checks the expiry date.
- Renewal happens at the **last third of the certificate lifetime** (30 days
  before the end for a 90-day certificate), or **N days before expiry** if you
  fill in "Renew". A change of the domain list or of the authority also
  triggers a new issuance.
- Renewal runs as a background task, with a **random delay** (one minute to
  one hour, shifted by ten minutes per certificate) so as not to hit the
  authority at a fixed time.
- If automatic installation is enabled, the new certificate is reinstalled in
  the web server.
- On failure, the error is kept in the "Last error" command and the status
  becomes `error`.
- If the certificate expires in fewer than **14 days** ("Alert before expiry",
  in the plugin configuration) without having been renewed, whatever the
  reason, an alert is sent **every day** until it is renewed: a message in the
  Jeedom message center, and the actions of the Notifications tab.

> **Let's Encrypt no longer sends expiry e-mails since 2025.** The plugin warns
> you instead: set up at least one action in the Notifications tab.

### Notifications (mail, Telegram, SMS…)

The device's **Notifications** tab lists the actions to run, like a scenario
action block:

1. **Add an action**, then pick a command with the
   <i class="fas fa-list-alt"></i> button (for instance the send command of
   your Mail, Telegram or SMS plugin, or of the mobile app), or a block with the
   <i class="fas fa-tasks"></i> button (start a scenario, set a variable…).
2. Fill in the options (title, message…) or leave them empty: the plugin then
   writes a clear title and message.
3. Tick the **events** that trigger the action:

   | Event | When | Ticked by default |
   |---|---|---|
   | Expiry approaching | every day, below the alert threshold, until the certificate is renewed | yes |
   | Issuance or renewal failed | on every failure (not for staging tests) | yes |
   | Web server installation failed | on every failure | yes |
   | Certificate issued or renewed | on every success | no |

4. **Save**, then **Test notifications**: every saved action runs with a test
   message, whatever events are ticked, and the result of each one is shown.

Tags available in the options: `#equipement#` (device), `#domaines#`
(domains), `#jours#` (days left), `#expiration#`, `#evenement#` (event),
`#message#` (details: error, date…). Example message:
`#evenement# for #domaines#: #message#`.

A failed notification (deleted command, mail service down) is written to the
`acme` log.

## Commands

| Command | Type | Content |
|---|---|---|
| Status | info | `none` (no certificate), `valid`, `renew_soon` (renewal due), `expired`, `error` (last issuance or renewal failed) |
| Expiry | info | expiry date, `YYYY-MM-DD HH:MM` |
| Days left | numeric info | days until expiry, historized |
| Issuer | info | intermediate authority that signed the certificate |
| Last renewal | info | date of the last successful issuance |
| Last error | info | last error message, empty when all is well |
| Renew | action | forces an immediate renewal (background task) |
| Install in the web server | action | reinstalls the current certificate in the web server |

Example scenario: trigger `#[Home][Certificate][Days left]# < 10`, action:
phone notification.

## Clean uninstall

Disabling or removing the plugin **does not remove** the HTTPS configuration
from the web server: removing it without warning might cut the very access you
are browsing through. Apache then keeps serving the last installed certificate
(copied to `/etc/ssl/jeedom-acme/`)… until it expires, without any renewal.

To remove everything cleanly:

1. If the HTTP → HTTPS redirect is active, reopen Jeedom over `http://`
   through its local IP address (the redirect goes away with the
   configuration).
2. On the certificate page: **Uninstall from the web server**. The
   configuration added by the plugin is removed, the server tested and
   reloaded.
3. Delete the device (its keys are erased), then the plugin.

## Troubleshooting

- **The task fails**: read the "Current task" panel, then the full **acme**
  log (Analysis → Logs), in *Debug* mode for details (level set in the plugin
  configuration). Secrets never appear in clear text.
- **Saving the device does nothing**, or a page stays blank: look at
  `/var/www/html/log/http.error` before anything else.
- **Let's Encrypt rate limits**: 5 identical certificates (same names) per
  week, and a limited number of failed validations per hour. Do your trials
  with **Test (staging)**, which is not subject to these limits, and use
  "Renew now" sparingly. When a limit is hit, the error says so, with the time
  it ends.
- **DNS-01: "TXT record never visible"**: the plugin stopped before contacting
  the authority, no attempt was lost. Increase the propagation wait (300 s by
  default); check
  that the zone is really served by OVH's DNS servers (and not by other servers
  declared at the registry); check that no CNAME record hides
  `_acme-challenge`.
- **DNS-01: "403" or "This call has not been granted"**: the token lacks the
  `GET/POST/DELETE /domain/zone/*` rights, or it has expired. Create a new one.
- **HTTP-01: "Connection refused" / "Timeout during connect"**: public port 80
  does not reach Jeedom. Check the router forward (80 → 80, not 9002 → 80) and
  the router firewall.
- **HTTP-01: "404"**: another server answers on port 80, or the web root is
  wrong.
- **"Installation in the web server failed"** while the certificate is valid:
  issuance succeeded, only installation failed. Fix the cause, then **Install
  in the web server**; no need to request a new certificate.
- **Installation refused**: the message includes the script output
  (`apachectl -t` failing, SSL module missing, `sudo` unavailable…). **Analyse
  the system** in the plugin configuration summarises what is missing.
- **The browser reports a wrong name**: you reach Jeedom through an IP address
  or a name other than the certificate's.
- **`https://<name>` does not answer from home**: the name does not resolve to
  Jeedom's local address. See the network reminder in
  [How it works](#how-it-works) (local DNS, A record to the private address or
  NAT loopback).

## FAQ

**Can I certify `jeedom.local`?**
No. No public authority certifies a private name. Use a subdomain of a domain
you own; with DNS-01 it may point to a local address.

**Do I need to open a port?**
With DNS-01, none. With HTTP-01, public port 80 to Jeedom:80, and only that one.

**My remote access uses port 9002: will HTTP-01 work?**
No: the authority only connects to port 80. Use DNS-01.

**Can I get a `*.mydomain.com` certificate?**
Yes, with DNS-01. Also add `mydomain.com` to the list if you want to cover the
bare name: a wildcard does not cover it.

**Several certificates?**
Yes: one device per certificate. Only one can be installed in the Jeedom web
server; the others are used by downloading them.

**Where are the keys?**
In `plugins/acme/data/` (web access denied, `0700`/`0600` rights) and, for the
installed certificate, in `/etc/ssl/jeedom-acme/`. The ACME account key can
never be downloaded.

**Does the plugin use certbot or acme.sh?**
No. The ACME protocol is implemented in PHP, without dependencies.

**What if Jeedom is off on renewal day?**
Nothing serious: renewal starts 30 days before expiry and is retried every day.
