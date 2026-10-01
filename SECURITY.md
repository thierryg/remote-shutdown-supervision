<!--
=============================================================================
Remote Shutdown - LAN parental control and machine management (master/agent)
=============================================================================
File    : SECURITY.md
Purpose : Threat model, security controls and vulnerability reporting
Author  : Thierry Gayet <thierry.gayet@labworks.fr>
Project : remote-shutdown (version: VERSION)
Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
=============================================================================
-->
# Security

## Reporting a vulnerability

Write to **Thierry Gayet <thierry.gayet@labworks.fr>** with the affected version, the steps to
reproduce and the impact. Please do not open a public issue before a fix is available.

## Threat model

| Asset | Threat | Control |
|---|---|---|
| Admin console | password guessing | bcrypt (cost 12), 5 failures per IP / 5 min, constant-time answer for unknown users |
| Admin session | theft, CSRF, XSS | JWT in `HttpOnly; Secure; SameSite=Strict` cookie, 30 min idle / 12 h absolute, token version (logout and password change revoke every token), `X-RSD` anti-CSRF header, strict CSP (no inline code), no `innerHTML` with data |
| Default account | `admin`/`admin` left in place | the API refuses everything but the password change until it is changed |
| Agent channel | eavesdropping, impersonation | TLS 1.2+, client certificate mandatory, identity = CN chosen by the master, serial checked on every connection |
| Fake master | MITM at enrollment | CA fingerprint pinned out of band (copied from the console); afterwards chain + serverAuth EKU verification |
| Discovery | spoofed answers | answer used as an address hint only; trust comes from TLS |
| Enrollment token | interception, reuse | 128-bit random, stored as SHA-256, limited uses and lifetime, shown once, masked in the audit log, erased from agent config / registry after use |
| Stolen agent certificate | replay on another machine | delete the machine in the console (immediate revocation); certificates live 365 days |
| CA private key | master compromise | 0600 in a 0700 directory owned by the unprivileged service account; offline creation possible (`scripts/rsd-gen-certs.sh`) |
| Master process | exploitation | unprivileged account, systemd sandbox (`ProtectSystem=strict`, no capabilities, syscall filter, private /tmp) |
| Audit log | tampering | SHA-256 hash chain verified by the console and `rsd-master verify-audit` |
| Master host (Ansible) | network exposure, brute force | nftables default drop (SSH from admin networks, master ports from the LAN only), key-only modern sshd, fail2ban on SSH and on the master JSON log (login failures, invalid enrollment tokens), kernel and sudo hardening, automatic security updates, no core dumps |
| Backups | theft of the CA key | archives 0600 in a 0700 directory; copy them off the host encrypted |
| Metrics | information disclosure | `/metrics` disabled unless a bearer token file exists; constant-time comparison; no secret in the metrics |
| Crawlers | indexing of the console | `robots.txt` Disallow, `X-Robots-Tag: noindex`, `<meta name="robots">` |
| Agent input | malicious master messages, oversized frames | 64 KiB line limit, at most 3 concurrent popups, AppleScript texts passed as arguments, zenity `--no-markup`, notify-send markup escaped |

## Known limits

* The agent runs as root / SYSTEM (needed to power off and to reach the user sessions); a user
  with administrator rights on a machine can stop or remove it. Parental control therefore
  assumes the supervised accounts are standard (non-admin) accounts.
* Uptime restarts at boot and after sleep, as documented: a reboot resets the counter.
* Windows machines cannot answer chat messages (a service cannot open an input dialog in a user
  session without a helper process).
* The browser warns about the private CA until it is imported (`/ca.crt`).

## Hardening checklist

- [ ] Deploy with Ansible (`deploy/ansible`): firewall, SSH, fail2ban and the vault password come with it.
- [ ] Change the `admin` password at first login (enforced) and keep it unique.
- [ ] Import the CA in the admin browsers; never accept a certificate warning afterwards.
- [ ] Restrict 8443/8444/50000 to the LAN (firewall); never publish them on the Internet.
- [ ] Use short token validity and the exact number of machines.
- [ ] Back up `/var/lib/rsd-master` encrypted (it holds the CA key).
- [ ] Delete in the console every machine that is retired or reinstalled.
- [ ] Review the audit log (`Audit` tab, `rsd-master verify-audit`).
