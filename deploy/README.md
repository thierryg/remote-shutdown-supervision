<!--
=============================================================================
Remote Shutdown - LAN parental control and machine management (master/agent)
=============================================================================
File    : deploy/README.md
Purpose : Map of the deployment artifacts (Ansible IaC of the master, MOTD) and deployment methods
Author  : Thierry Gayet <thierry.gayet@labworks.fr>
Project : remote-shutdown (version: VERSION)
Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
=============================================================================
-->
# `deploy/` — deployment of the master

This directory holds what turns a Debian / Ubuntu / Linux Mint machine into a hardened
Remote Shutdown master: the Ansible infrastructure as code and the SSH login dashboard.
What the packages install (systemd units, default configuration) lives in `packaging/`;
the containers live in `docker/`. The agents are deployed with their packages (`.deb`, `.msi`,
`.pkg`), see [INSTALL.md](../INSTALL.md).

## 1. Deployment methods of the master

| Method | Location | Use |
|---|---|---|
| **Ansible (recommended)** | [`deploy/ansible/`](ansible/README.md) | complete, hardened, verified deployment: preflight and postflight checks, `.deb` built and installed, admin password from the vault, nftables, SSH hardening, fail2ban, backups, MOTD, metrics |
| Debian package | `apt install ./rsd-master_<v>_all.deb` | manual installation on the machine itself (no hardening, firewall or MOTD) |
| Docker (host) | `docker/docker-compose.yml` | master in a container with host networking (LAN discovery, real client addresses) |
| Docker (local test) | `docker/rsd-start.sh`, `rsd-status.sh`, `rsd-stop.sh`, `rsd-clean.sh` | try it on a workstation: master + 2 simulated agents, `https://localhost:8443` |

```bash
cd deploy/ansible
cp inventory/hosts.example.yml inventory/hosts.yml && $EDITOR inventory/hosts.yml
cp group_vars/all/vault.example.yml group_vars/all/vault.yml && $EDITOR group_vars/all/vault.yml
ansible-vault encrypt group_vars/all/vault.yml
./rsd-deploy.sh deploy -J            # -K as well if sudo asks for a password
```

## 2. Contents

```
deploy/
├── README.md                    this file
├── motd/
│   ├── issue.net                →  /etc/issue.net, /etc/issue   legal banner shown BEFORE the SSH login
│   ├── rsd-motd                 →  /usr/local/bin/rsd-motd      dashboard: service, agents UP, audit, backups, firewall, bans
│   └── 10-rsd-master            →  /etc/update-motd.d/          pam_motd hook (5 s cap, never blocks a login)
└── ansible/                     infrastructure as code of the master (see ansible/README.md)
    ├── rsd-deploy.sh            wrapper: deps, ping, preflight, check, deploy, postflight, lint
    ├── site.yml                 playbook: preflight → base → hardening → firewall → ssh → master → fail2ban → monitoring → motd → postflight
    ├── group_vars/all/          main.yml (every tunable), vault.example.yml (secrets template)
    ├── inventory/               hosts.example.yml (hosts.yml is not versioned)
    ├── roles/                   one role per step
    ├── artifacts/<host>/        rsd-ca.crt fetched from the master (not versioned)
    └── tests/                   systemd container target + end-to-end/idempotence test
```

## 3. Paths on the master

| Path | Content | Owner / mode |
|---|---|---|
| `/usr/lib/rsd-master`, `/usr/bin/rsd-master` | code and launcher (`.deb`) | root |
| `/etc/rsd-master/master.ini` | settings (rendered by Ansible) | root:rsd-master 0640 |
| `/etc/rsd-master/metrics.token` | Prometheus bearer token (optional) | root:rsd-master 0640 |
| `/var/lib/rsd-master/rsd-master.db` | database (agents, tokens, settings, chat, audit) | rsd-master 0600 |
| `/var/lib/rsd-master/pki/` | CA and server key pairs | rsd-master 0700 / keys 0600 |
| `/var/lib/rsd-master/backups/` | daily archives (14 kept) — **contain the CA key** | rsd-master 0700 / 0600 |
| `/etc/nftables.conf`, `/etc/fail2ban/jail.d/rsd.local` | firewall and bans | root |
| `/etc/ssh/sshd_config.d/01-rsd-hardening.conf` | sshd hardening | root 0600 |
