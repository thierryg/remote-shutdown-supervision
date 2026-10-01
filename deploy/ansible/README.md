<!--
=============================================================================
Remote Shutdown - LAN parental control and machine management (master/agent)
=============================================================================
File    : deploy/ansible/README.md
Purpose : Ansible deployment of the master: prerequisites, variables, roles, checks, tests
Author  : Thierry Gayet <thierry.gayet@labworks.fr>
Project : remote-shutdown (version: VERSION)
Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
=============================================================================
-->
# Ansible deployment of the master

Deploys and hardens the Remote Shutdown master on **Ubuntu Server 26.04 LTS or Debian 13** (reference
platforms), and on Ubuntu 22.04/24.04, Debian 12 or Linux Mint 21+
from any Linux or macOS controller. The playbook is idempotent: a second run changes nothing.

## 1. Prerequisites

| Side | Needs |
|---|---|
| Controller | bash ≥ 4.4, [uv](https://docs.astral.sh/uv/) (or ansible-core ≥ 2.16), `dpkg-deb` when `dist/` has no package, SSH key |
| Target | systemd, an administrator account accepting the key (`ssh-copy-id`) and allowed to sudo, Internet or an apt mirror |

`rsd-deploy.sh` runs ansible-core from the PATH, or through `uvx` when it is missing or too old,
and installs the collections (`ansible.posix`, `community.general`) into `./collections`.

## 2. Quick start

```bash
cd deploy/ansible
cp inventory/hosts.example.yml inventory/hosts.yml           # address, user, certificate names
cp group_vars/all/vault.example.yml group_vars/all/vault.yml # rsd_admin_password, rsd_metrics_token
ansible-vault encrypt group_vars/all/vault.yml
./rsd-deploy.sh ping
./rsd-deploy.sh preflight -J      # checks only, changes nothing
./rsd-deploy.sh deploy -J
```

The CA certificate is copied to `artifacts/<host>/rsd-ca.crt` (import it in the browsers).
Set `rsd_create_token: true` to receive an enrollment token and the agent commands at the end.

## 3. Commands of `rsd-deploy.sh`

| Command | Effect |
|---|---|
| `deps` | install the collections |
| `ping` | SSH + sudo check |
| `preflight` | blocking checks only (OS, resources, secrets, SSH lockout, ports) |
| `check` | dry run (`--check --diff`) |
| `deploy` | full deployment, postflight included |
| `postflight` | post-deployment checks only (any time) |
| `lint` | syntax check, ansible-lint (production profile), yamllint |

Options: `-i FILE`, `-l HOSTS`, `-t TAGS`, `-e VAR=VAL`, `-K` (sudo password), `-J` (vault password), `-v`.

## 4. Roles

| Role | Does |
|---|---|
| `preflight` | Ansible version, source tree, distribution and release, systemd, RAM, disk, admin password policy, metrics token, root, **SSH lockout protections** (key present, AllowUsers, controller inside `rsd_admin_networks`), master ports free, Docker detection, clock |
| `base` | apt update/upgrade, tools, mDNS, host name, time zone, timesyncd |
| `hardening` | sysctl (not in containers; IP forwarding kept when Docker is present), no core dumps, persistent bounded journal, unattended security upgrades, sudo hardening, legacy clients removed |
| `firewall` | nftables, default drop: SSH from admin networks (rate-limited), 8443/8444/tcp and 50000/udp from the LAN, node_exporter from the monitoring server; ufw removed; Docker tables untouched |
| `ssh` | banner, keys, key-only login, modern algorithms filtered against the local OpenSSH, rollback if `sshd -t` fails |
| `master` | `.deb` built on the controller when missing, installed with its distribution dependencies; `master.ini`; metrics token; admin password set only when it differs (`rsd-master check-password`); backup timer; CA fetched; optional token |
| `fail2ban` | jails `sshd`, `rsd-master` (console login failures and invalid enrollment tokens, read from the JSON journal), `recidive`; nftables bans |
| `monitoring` | optional `prometheus-node-exporter`; prints the Prometheus scrape job of `/metrics` |
| `motd` | `rsd-motd` dashboard at SSH login |
| `postflight` | services active and enabled, version, ports (incl. UDP discovery), TLS 1.2/1.3 accepted and 1.1 refused, certificate chained to the CA, security headers, robots, **mTLS refuses a client without certificate**, admin/admin refused and the vault password works, audit chain intact, backup taken and private, nftables table, fail2ban jails |

Tags: `preflight base hardening firewall ssh master fail2ban monitoring motd postflight`
(e.g. `./rsd-deploy.sh deploy -t master,postflight`).

## 5. Main variables

Every tunable is documented in [`group_vars/all/main.yml`](group_vars/all/main.yml).

| Variable | Default | Meaning |
|---|---|---|
| `rsd_lan_networks` | private ranges | clients allowed on 8443/8444/50000 |
| `rsd_admin_networks` | `rsd_lan_networks` | SSH sources |
| `rsd_tls_extra_names` | `[]` | extra names/IPs in the server certificate |
| `rsd_web_port` / `rsd_agent_port` / `rsd_discovery_port` | 8443 / 8444 / 50000 | master ports |
| `rsd_admin_password` (vault) | — | web admin password, required unless `rsd_allow_default_admin` |
| `rsd_metrics_token` (vault) | `""` | enables `GET /metrics` with this bearer token |
| `rsd_backup_timer` | true | daily backup, 14 archives |
| `rsd_harden`, `rsd_firewall`, `rsd_harden_ssh`, `rsd_fail2ban`, `rsd_motd` | true | switch a role off |
| `rsd_create_token` | false | create an enrollment token and print the agent commands |

## 6. Tests

```bash
tests/rsd-container-test.sh                       # Ubuntu 26.04 LTS systemd container, deploy twice
tests/rsd-container-test.sh --image debian:13     # also ubuntu:24.04, debian:12, ubuntu:22.04
tests/rsd-container-test.sh --keep                # keep the container to inspect it over SSH
```

The second run must report `changed=1` (only the requested enrollment token). The CI runs the
test on Ubuntu 26.04, Debian 13, Ubuntu 24.04 and Debian 12.
