<!--
=============================================================================
Remote Shutdown - LAN parental control and machine management (master/agent)
=============================================================================
File    : INSTALL.md
Purpose : Installation, configuration, operations, upgrade, removal and troubleshooting guide
Author  : Thierry Gayet <thierry.gayet@labworks.fr>
Project : remote-shutdown (version: VERSION)
Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
=============================================================================
-->
# Installation and operations

## 1. Supported platforms

| Component | Platforms | Package |
|---|---|---|
| Master | **Ubuntu Server 26.04 LTS and Debian 13 (reference)**, Ubuntu 22.04/24.04, Debian 12, Linux Mint 21+ (amd64, arm64, any arch with Python 3.10+) | `rsd-master_<v>_all.deb` |
| Master | Fedora, openSUSE Leap / Tumbleweed | `rsd-master-<v>-1.noarch.rpm` |
| Agent | Ubuntu 26.04/24.04/22.04, Debian 13/12, Mint (amd64, arm64, armhf) | `rsd-agent_<v>_<arch>.deb` |
| Agent | Fedora, RHEL / Rocky / AlmaLinux 9+, openSUSE (x86_64, aarch64, armv7hl) | `rsd-agent-<v>-1.<arch>.rpm` |
| Agent | Windows 10 / 11 without installer (amd64, arm64) | `rsd-agent-<v>-windows-<arch>.exe` |
| Agent | Windows 10 / 11 (x64) | `rsd-agent-<v>-x64.msi` |
| Agent | macOS 12+ (Intel and Apple silicon, universal binary) | `rsd-agent-<v>.pkg` |

The master uses the Python packages of the distribution (`python3-fastapi`, `python3-uvicorn`,
`python3-cryptography`, `python3-bcrypt`, `python3-jwt`); apt installs them automatically.
The agent is a **static standalone binary**: every package embeds it, and the computers need
neither Go nor any library (Go is only needed on the machine that builds the packages, see
`make deps`). On Linux, `zenity` (or `kdialog`, or `libnotify-bin`) is recommended for the popups.

The agent dialogs follow the **language** of the user logged in on each computer (12 languages,
English otherwise) and its **light / dark theme** on Linux and macOS. Windows draws its system
message boxes in the classic light style whatever the theme. Free text typed in the console is
shown as typed.

RHEL / Rocky / AlmaLinux do not ship FastAPI: run the master on Ubuntu, Debian, Mint, Fedora or
openSUSE (any agent works with any master).

## 2. Network

| Port | Direction | Purpose |
|---|---|---|
| 8443/tcp | browser → master, agent → master | Web console, REST API, enrollment |
| 8444/tcp | agent → master | Agent connection (mutual TLS) |
| 50000/udp | agent broadcast → master | Discovery (optional) |

Only the master needs inbound rules: the agents always open the connections. With `ufw`:

```bash
sudo ufw allow 8443,8444/tcp
sudo ufw allow 50000/udp
```

Never expose these ports on the Internet; use a VPN to administer from outside.

## 3. Master

### 3.1 Install

Three ways, from the most to the least complete:

* **Ansible** (hardened host, checks before and after): see [deploy/ansible/README.md](deploy/ansible/README.md).
  The web administrator password then comes from the vault: the console never runs with `admin`/`admin`.
* **Debian package**, below.
* **Docker** with host networking: `docker compose -f docker/docker-compose.yml up -d --build`
  (data in the `rsd-master_data` volume, optional `/etc/rsd-master/master.ini`).

```bash
sudo apt install ./rsd-master_<version>_all.deb
systemctl status rsd-master
```

The package creates the `rsd-master` system account, the data directory `/var/lib/rsd-master`
(database, CA, session key) and starts the service. At first start the master creates its
certificate authority and a server certificate covering its host names and LAN addresses.

### 3.2 First login

Open `https://<master-ip>:8443/`. The browser warns about an unknown authority until you import
the CA: download it from **Enrollment → Download the CA certificate** (or `/ca.crt`) and
import it as a trusted authority. Sign in with `admin` / `admin`: the console forces a new
password (10 characters minimum) before anything else.

Lost password:

```bash
sudo rsd-master reset-password --user admin
```

### 3.3 Configuration

`/etc/rsd-master/master.ini` holds the restart-required settings (ports, certificate names,
session lifetime, keepalive timeout, log format). Every key can also be set by environment,
`RSD__SECTION__KEY` (e.g. `RSD__SERVER__WEB_PORT=9443` in a systemd drop-in). Apply with
`sudo systemctl restart rsd-master`.

Runtime parameters are edited in the console (**Settings**):

| Parameter | Meaning |
|---|---|
| Default maximum uptime (days / hours / minutes) | Limit for the machines set to "default setting"; 0 = unlimited |
| Warning before the limit | Popup shown this many minutes before the limit |
| Shutdown countdown | Seconds between the shutdown order and the power-off |

Per machine (**Machines → Edit**): name, and maximum uptime = default setting, custom value,
or **unlimited** (override). Uptime counts from the boot or from the last resume from sleep.

### 3.4 Command line

```bash
sudo rsd-master info                    # version, ports, CA fingerprint, enrollment example
sudo rsd-master create-token --uses 3   # enrollment token for 3 machines (printed once)
sudo rsd-master verify-audit            # integrity of the audit hash chain
sudo rsd-master status                  # agents UP (last keepalive), tokens, audit chain (--json)
sudo rsd-master backup                  # archive now (also run daily by rsd-master-backup.timer)
sudo rsd-master reset-password          # new admin password (closes every session)
journalctl -u rsd-master -o cat | jq .  # structured logs
```

Run as root, the CLI switches to the `rsd-master` account by itself, so the files it creates
stay readable by the service.

### 3.5 Backup

`rsd-master-backup.timer` archives the database (consistent online snapshot), the PKI and the
session key every day at 03:30 into `/var/lib/rsd-master/backups` (14 archives, mode 0600).
The archives contain the CA private key: copy them off the host **encrypted**. To restore,
stop the service, extract an archive into `/var/lib/rsd-master` (owner `rsd-master`) and start
it again; every agent keeps working (they trust the CA, not the host name).

### 3.6 Monitoring

Write a token (16+ characters) to `/etc/rsd-master/metrics.token` (root:rsd-master 0640), set
`metrics_token_file` in `master.ini` (or `rsd_metrics_token` with Ansible) and restart: then
`GET https://<master>:8443/metrics` with `Authorization: Bearer <token>` returns `rsd_info`,
`rsd_agents_total`, `rsd_agents_up`, `rsd_agent_up`, `rsd_agent_uptime_seconds`,
`rsd_agent_limit_seconds`, `rsd_enroll_tokens_active` and `rsd_audit_chain_ok`.

## 4. Agents

Create a token in **Enrollment** (validity and number of machines are yours to choose). The
console prints the exact commands with the token, the CA fingerprint and the master address.

### 4.1 Linux (Debian, Ubuntu, Mint)

```bash
sudo apt install ./rsd-agent_<version>_amd64.deb
sudo rsd-agent enroll --token <TOKEN> --fingerprint <FINGERPRINT> --master <MASTER-IP>
rsd-agent status
```

The service `rsd-agent` starts at boot; it connects within a minute of the enrollment.
Configuration: `/etc/rsd-agent/agent.json`; credentials: `/var/lib/rsd-agent` (0700).
Unattended installs can put `enroll_token`, `ca_fingerprint` and `master` in `agent.json`:
the service enrolls by itself and erases the token.

### 4.2 Linux (Fedora, RHEL, Rocky, AlmaLinux, openSUSE)

```bash
sudo dnf install ./rsd-agent-<version>-1.x86_64.rpm        # openSUSE: sudo zypper install ./...
sudo rsd-agent enroll --token <TOKEN> --fingerprint <FINGERPRINT> --master <MASTER-IP>
```

Same layout as the `.deb` (service `rsd-agent`, `/etc/rsd-agent/agent.json`,
`/var/lib/rsd-agent`). The master RPM (Fedora, openSUSE) is installed the same way; open its
ports with `firewall-cmd --permanent --add-port=8443/tcp --add-port=8444/tcp --add-port=50000/udp`.

### 4.3 Windows

From an elevated prompt (or a deployment tool):

```bat
msiexec /i rsd-agent-<version>-x64.msi /qn MASTER=<MASTER-IP> ENROLL_TOKEN=<TOKEN> CA_FINGERPRINT=<FINGERPRINT>
```

The MSI installs `C:\Program Files\rsd-agent\rsd-agent.exe`, registers the automatic service
**Remote Shutdown Agent** (LocalSystem) and writes the properties to `HKLM\SOFTWARE\rsd-agent`;
the service enrolls and deletes the token value. Credentials: `C:\ProgramData\rsd-agent\state`
(ACL: SYSTEM and Administrators only); log: `C:\ProgramData\rsd-agent\agent.log`. Manual
enrollment: `"C:\Program Files\rsd-agent\rsd-agent.exe" enroll --token ... --fingerprint ...`.
Popups use `WTSSendMessage` (all editions, Home included); chat replies are not available.

Without the MSI, the standalone `rsd-agent-<version>-windows-amd64.exe` (or `-arm64`) is the same
binary: copy it to `C:\Program Files\rsd-agent\rsd-agent.exe`, then from an elevated prompt:

```bat
"C:\Program Files\rsd-agent\rsd-agent.exe" enroll --token <TOKEN> --fingerprint <FINGERPRINT> --master <MASTER-IP>
sc.exe create rsd-agent binPath= "\"C:\Program Files\rsd-agent\rsd-agent.exe\" run" start= auto
sc.exe start rsd-agent
```

### 4.4 macOS

```bash
sudo installer -pkg rsd-agent-<version>.pkg -target /
sudo /usr/local/bin/rsd-agent enroll --token <TOKEN> --fingerprint <FINGERPRINT> --master <MASTER-IP>
```

The launchd daemon `com.labworks.rsd-agent` runs at boot. Configuration and credentials:
`/Library/Application Support/rsd-agent`; log: `/Library/Logs/rsd-agent.log`. Dialogs are shown
in the session of the user logged in on the console. Remove with `sudo rsd-agent-uninstall`.

### 4.5 Containers

The agent image `docker/Dockerfile.agent` is a **simulation** (dry-run power off, no desktop):
it serves the local test only. Real machines use the packages.

## 5. Upgrade

Install the newer package over the old one (`apt install ./...deb`, `msiexec /i ...msi`,
`installer -pkg ...`). Configuration, database, CA and agent credentials are kept. Agents
renew their certificate automatically 30 days before expiry.

## 6. Removal

| Platform | Remove | Remove everything (data, keys) |
|---|---|---|
| Debian / Ubuntu / Mint | `sudo apt remove rsd-master` / `rsd-agent` | `sudo apt purge rsd-master` / `rsd-agent` |
| Windows | Settings → Apps → Remote Shutdown Agent, or `msiexec /x rsd-agent-<v>-x64.msi` | delete `C:\ProgramData\rsd-agent` |
| macOS | `sudo rsd-agent-uninstall` | (included) |

Delete the machine in the console as well: its certificate is then refused.

## 7. Troubleshooting

| Symptom | Check | Fix |
|---|---|---|
| Agent stays DOWN | `rsd-agent status`; agent log | Open 8444/tcp on the master; check `--master` or the discovery port |
| `the master CA does not match the pinned fingerprint` | `sudo rsd-master info` | Copy the fingerprint again from the console (no typo, right master) |
| `master answered 403 error.invalid_token` | Enrollment tab | Token expired or used up: create a new one |
| `the master refused this agent` in the agent log | Machines tab | The machine was deleted: `sudo rsd-agent enroll --force ...` with a new token |
| No popup on Linux | `rsd-agent test-popup` as root | Install `zenity`; a graphical session must be open |
| No popup on macOS | `/Library/Logs/rsd-agent.log` | A user must be logged in on the console |
| Browser certificate warning | — | Import the CA (`/ca.crt`) as a trusted authority |
| Console says "too many attempts" | — | Wait 5 minutes (5 failed logins per IP) |
