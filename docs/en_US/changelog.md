# Changelog

## 0.1

First release.

- One device per certificate: one or more domains, the first one being the
  main name; wildcard certificates (`*.domain`) with DNS-01.
- Authorities: Let's Encrypt, Let's Encrypt staging, ZeroSSL (EAB credentials
  obtained automatically from the e-mail address), or any ACME authority
  through its directory URL, with EAB if required.
- DNS-01 validation through the OVHcloud API (all OVH, Kimsufi and So you Start
  endpoints), with a link to create a token with restricted rights and a button
  to test access placed right after the endpoint choice; propagation checked
  directly against the authoritative DNS servers, DNS-over-HTTPS fallback.
  Configurable propagation delay (300 s by default): when it runs out, the
  plugin stops without contacting the authority, so no Let's Encrypt attempt
  is used up.
- HTTP-01 validation in the Jeedom web root.
- "Test (staging)" button: full issuance against the Let's Encrypt test server,
  without rate limits and without installing anything.
- Issuance as a background task, with the current step and the last log lines
  shown on the device page; tracking survives short outages (retry every 5 s,
  gives up after 10 failures).
- Issuance failures and web server installation failures shown separately.
- Web server installation (Apache; nginx semi-automatic): backup, configuration
  test, graceful reload and automatic rollback; optional HTTP → HTTPS redirect;
  system compatibility check from the plugin configuration. With nginx, web
  access to `plugins/acme/data/` is denied by the generated snippet
  (`location ^~ /plugins/acme/data/ { deny all; }`), to be carried over to
  every `server` block serving Jeedom.
- Daily automatic renewal at the last third of the lifetime (or N days before
  expiry), spread over time; daily alert in the message center if expiry
  approaches without renewal.
- Public HTTPS port (e.g. 9003 → Jeedom:443): target of the HTTP → HTTPS
  redirect when the router publishes Jeedom on another port.
- Notifications tab: actions of your choice (mail, Telegram, SMS, scenario…)
  triggered by approaching expiry, an issuance failure, an installation failure
  or a successful renewal, with tags (#domaines#, #jours#, #message#…) and a
  "Test notifications" button.
- Commands: status, expiry, days left (historized), next renewal, issuer,
  last renewal, certificate served, last error; Renew and Install in the web
  server actions.
- Check of the certificate actually served by the web server (local TLS probe
  with SNI, serial number comparison): every day, after each installation and
  on each save; on mismatch or unreachable server, warning, message,
  notification and new installation.
- Health page: one line per certificate (state, days left, next renewal, last
  error, certificate served), the Jeedom daily task and sudo rights.
- Download of the PEM files (fullchain, key, certificate, chain), for
  administrators only.
- Guided path on the page: test, issuance, installation, `https://` check,
  then redirect; reminder about name resolution from the local network (local
  DNS, A record to the private address, NAT loopback).
- English user interface, DNS provider fields included.
- No dependency: plain PHP (openssl, curl, json extensions).
