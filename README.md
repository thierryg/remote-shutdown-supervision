<!--
=============================================================================
Remote Shutdown - LAN parental control and machine management (master/agent)
=============================================================================
File    : README.md
Purpose : Project overview, features, quick start and repository map
Author  : Thierry Gayet <thierry.gayet@labworks.fr>
Project : remote-shutdown (version: VERSION)
Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
=============================================================================
-->
# Remote Shutdown

LAN parental control and machine management with a **master / agent** architecture: a Linux
master serves a secure web console; a small agent on every Linux, Windows or macOS machine
reports its state and executes the orders (shutdown with countdown, popup message, chat).

```
             HTTPS 8443 (browser)                    discovery UDP 50000 (bootstrap)
  admin ───────────────────────────►  ┌──────────────────────────┐ ◄──────────────┐
                                      │ rsd-master (Linux)       │                │
                                      │ FastAPI · SQLite · CA    │                │
                                      └──────────────────────────┘                │
                                         ▲  mutual TLS, TCP 8444, JSON lines      │
                 ┌───────────────────────┼───────────────────────┐                │
            ┌────┴─────┐            ┌────┴─────┐            ┌────┴─────┐          │
            │ rsd-agent│            │ rsd-agent│            │ rsd-agent│ ─────────┘
            │  Linux   │            │ Windows  │            │  macOS   │
            └──────────┘            └──────────┘            └──────────┘
```

## Features

| Area | What you get |
|---|---|
| Discovery | Agents find the master by UDP broadcast (or use a configured address) |
| Supervision | UP / DOWN per machine (keepalive every 10 s, DOWN after 35 s), uptime, IP and MAC of every interface, OS, agent version |
| Commands | Shut down one machine or all, with countdown, message and optional force; cancel; popup message; chat (reply from Linux and macOS) |
| Parental control | Maximum uptime in days / hours / minutes, global default + per-machine override (custom or **unlimited**), warning popup before the limit |
| Security | HTTPS everywhere, mutual TLS for agents, automatic PKI enrollment with one-time tokens and CA pinning, bcrypt passwords, short JWT sessions, anti-CSRF, strict CSP, rate limiting, hash-chained audit log |
| Packages | `.deb` for Debian / Ubuntu / Linux Mint, `.rpm` for Fedora / RHEL / Rocky / openSUSE, `.msi` and standalone `.exe` for Windows, `.pkg` for macOS; the agent is a **static standalone binary** (no Go, no library needed on the computers) |
| Agent dialogs | Shown in the **language of the computer** (12 languages) and its **light / dark theme** (Linux, macOS) |
| Deployment | Ansible IaC of the master (hardening, nftables, SSH, fail2ban, backups, MOTD, pre/postflight checks), Docker images and a one-command local test with simulated agents |
| Operations | Daily backups (systemd timer), SSH login dashboard, `rsd-master status`, Prometheus `/metrics` (bearer token), structured JSON logs |
| Console | Framework-free web UI in 12 languages (English, French, Spanish, Dutch, German, Italian, Russian, Chinese, Indonesian, Korean, Japanese, Thai), light and dark themes |

## Quick start

1. **Master** (reference platforms **Ubuntu Server 26.04 LTS** and **Debian 13**; also Ubuntu 22.04/24.04, Debian 12, Linux Mint 21+):
   ```bash
   sudo apt install ./rsd-master_<version>_all.deb
   sudo ufw allow 8443,8444/tcp && sudo ufw allow 50000/udp     # if ufw is enabled
   ```
   Open `https://<master-ip>:8443/`, sign in with `admin` / `admin`, choose a new password.
2. **Enrollment tab**: create a token. The console shows the exact command for each OS,
   including the token, the CA fingerprint and the master address.
3. **Agent** on each machine, then the command copied from the console:
   - Linux (Debian/Ubuntu/Mint): `sudo apt install ./rsd-agent_<version>_amd64.deb` then `sudo rsd-agent enroll ...`
   - Linux (Fedora/RHEL/Rocky/openSUSE): `sudo dnf install ./rsd-agent-<version>-1.x86_64.rpm` (or `zypper install`) then `sudo rsd-agent enroll ...`
   - Windows (elevated): `msiexec /i rsd-agent-<version>-x64.msi /qn MASTER=... ENROLL_TOKEN=... CA_FINGERPRINT=...`
   - macOS: `sudo installer -pkg rsd-agent-<version>.pkg -target /` then `sudo /usr/local/bin/rsd-agent enroll ...`
4. The machine appears **UP** in the **Machines** tab within seconds.

See [INSTALL.md](INSTALL.md) for the details, firewall notes, upgrades and removal.

**Hardened master with Ansible** (recommended for a permanent installation):

```bash
cd deploy/ansible && cp inventory/hosts.example.yml inventory/hosts.yml
cp group_vars/all/vault.example.yml group_vars/all/vault.yml && ansible-vault encrypt group_vars/all/vault.yml
./rsd-deploy.sh deploy -J
```

**Try it in Docker** (master + two simulated agents, nothing else installed):

```bash
docker/rsd-start.sh        # https://localhost:8443/  (admin / admin)
docker/rsd-status.sh       # docker/rsd-stop.sh, docker/rsd-clean.sh
```

## Documentation

| Document | Content |
|---|---|
| [INSTALL.md](INSTALL.md) | Installation, configuration, operations, troubleshooting |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Components, data flows, PKI, policy engine, design decisions |
| [docs/PROTOCOL.md](docs/PROTOCOL.md) | Discovery, enrollment and agent protocol reference (all messages) |
| [deploy/README.md](deploy/README.md) | Deployment methods of the master, paths on the host |
| [deploy/ansible/README.md](deploy/ansible/README.md) | Ansible IaC: roles, variables, checks, tests |
| [SECURITY.md](SECURITY.md) | Threat model, security controls, reporting a vulnerability |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development environment, conventions, building the packages |
| [CHANGELOG.md](CHANGELOG.md) | Release history |
| [AGENTS.md](AGENTS.md) | Standing rules for AI coding agents |

## Repository map

```
master/rsd_master/   Python master (FastAPI console + API, mTLS hub, PKI, policy, CLI)
agent/               Go agent (one source tree for Linux, Windows and macOS)
packaging/           systemd units, Debian control files, WiX (MSI) source, launchd + pkg files
deploy/              Ansible IaC of the master (deploy/ansible) and SSH login dashboard (deploy/motd)
docker/              master and agent images, Compose files, local test scripts (rsd-start/status/stop/clean)
scripts/             build, test and maintenance scripts (rsd-*.sh, rsd-bump-version.py)
tests/               pytest suite of the master and of the repository rules
docs/                architecture and protocol references
VERSION              single source of the version
```

## Building

The version of every package comes from the single `VERSION` file.

```bash
make deps              # build tools: Go (latest stable), dpkg-deb, rpmbuild, wixl/msitools
make build             # dist/: .deb, .rpm, .msi, .exe (+ .pkg on macOS) and SHA256SUMS
make linux             # .deb + .rpm      (make linux-deb / make linux-rpm)
make win-msi           # Windows installer     make exe: standalone Windows agent
make macosx-pkg        # macOS installer (on macOS; the CI builds it on a macOS runner)
make venv check        # lint, SAST, ShellCheck, go vet, go test, pytest
make test-distro       # master suite inside Ubuntu 26.04/24.04/22.04 and Debian 13/12
make test-deb test-rpm # install and exercise the packages in Docker
make deploy-lint deploy-test   # Ansible lint, playbook twice against a systemd container
make ui-check          # real-browser check of the console (Playwright + Chrome)
make audit             # pip-audit + govulncheck
```

## License

[BSD Zero Clause License](LICENSE) (0BSD). Third-party components keep their own licenses, see
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
