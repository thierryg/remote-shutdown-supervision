<!--
=============================================================================
Remote Shutdown - LAN parental control and machine management (master/agent)
=============================================================================
File    : CHANGELOG.md
Purpose : Release history (Keep a Changelog 1.1.0, Semantic Versioning 2.0.0)
Author  : Thierry Gayet <thierry.gayet@labworks.fr>
Project : remote-shutdown (version: VERSION)
Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
=============================================================================
-->
# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

The version has a single source, `VERSION`. Bump it with `make bump PART=patch|minor|major`
(`scripts/rsd-bump-version.py`): this moves the `[Unreleased]` section below under a dated
heading. Never edit the version anywhere else.

## [Unreleased]

## [0.3.0] - 2026-10-01

### Added
- **Agent dialogs in the language of the computer** (12 locales, the same as the console,
  embedded in the binary: `agent/i18n/*.json`): the master sends a message key and its
  parameters (`key`, `params`) with an English fallback text; the agent renders it in the
  language of each desktop user: AccountsService / `~/.pam_environment` / system locale on
  Linux (also passed as `LANG`/`LANGUAGE` to zenity and kdialog, whose own buttons follow),
  `AppleLanguages` of the console user on macOS, `PreferredUILanguages` / `LocaleName` of the
  session user's profile on Windows. Free text typed by the administrator is shown as is.
- **Light / dark theme followed**: Linux dialogs get the user's color scheme (libadwaita and
  GTK 3 dark variant), macOS dialogs follow the appearance natively. Windows message boxes are
  drawn by Windows in the classic light style (system limitation, documented).
- **RPM packages** (`scripts/rsd-build-rpm.sh`, `packaging/rpm/*.spec`): agent for Fedora,
  RHEL / Rocky / AlmaLinux and openSUSE (x86_64, aarch64, armv7hl), master (noarch, python3dist
  requirements) for Fedora and openSUSE. Integration test `scripts/rsd-test-rpm.sh`
  (`make test-rpm`): Fedora 44, Rocky Linux 10, openSUSE Leap 16.
- **Standalone Windows executables** `rsd-agent-<v>-windows-{amd64,arm64}.exe` (`make exe`).
- **Makefile packaging targets**: `make deps` (`scripts/rsd-install-deps.sh`: dpkg-deb,
  rpmbuild, wixl/msitools and the latest stable Go from go.dev, SHA-256 checked; Debian /
  Ubuntu / Mint, Fedora / RHEL, openSUSE, macOS), `make build` (every package of this OS +
  `dist/SHA256SUMS`), `make linux`, `make linux-deb`, `make linux-rpm`, `make macosx-pkg`,
  `make win-msi`, `make exe` (the former `deb`, `rpm`, `msi`, `pkg`, `packages` remain aliases).
- The console Enrollment tab also shows the RPM installation command.

### Changed
- The CI builds with `make deps` + `make build`, tests the RPMs (Fedora and openSUSE masters)
  and publishes the `.rpm` and `.exe` too; Go is the latest stable release everywhere (CI and
  agent image), as govulncheck found standard library vulnerabilities in Go 1.26.0.
- Docker test networks share one subnet fallback (`ensure_docker_network` in `rsd-common.sh`).

### Fixed
- The agent no longer rewrites `agent.json` after an enrollment when the file holds no token:
  the packaged configuration stays pristine (no `.rpmsave`, no dpkg conffile prompt).
- Package targets always rebuild the agent first: a package can no longer embed a stale binary.
- `rsd-container-test.sh --work DIR` creates DIR when it does not exist.

## [0.2.1] - 2026-10-01

### Added
- **Reference platforms Ubuntu Server 26.04 LTS and Debian 13** (Python 3.14 / 3.13, FastAPI
  0.118 / 0.115, cryptography 46 / 43): `scripts/rsd-test-distro.sh` (`make test-distro`) runs
  the master suite inside each distribution on its own apt packages; the `.deb` test, the
  Ansible container test (now Ubuntu 26.04 by default) and the CI matrices cover them; the
  master Docker image is based on Ubuntu 26.04.
- CI job `test-distro` (Ubuntu 26.04/24.04/22.04, Debian 13/12).

### Fixed
- **TLS refused on Python 3.13+** (Debian 13, Ubuntu 26.04): the strict X.509 profile enabled
  by default requires the Authority Key Identifier. Server and agent certificates now carry SKI
  and AKI; an existing server certificate without AKI is re-issued at start; the agent hub keeps
  accepting the agent certificates of the first releases (chain, validity, clientAuth and the
  recorded serial are still checked).
- CI: runners `windows-2025` / `macos-15`, `test-oldest` on Ubuntu 24.04 (Python 3.10 by uv),
  `fail-fast: false` on the matrices, release checksum glob made safe (actionlint/ShellCheck).

## [0.2.0] - 2026-10-01

### Added
- **Ansible IaC of the master** (`deploy/ansible/`, wrapper `rsd-deploy.sh`): preflight (Ansible,
  distribution Debian 12+ / Ubuntu 22.04+ / Mint 21+, resources, vault password policy, SSH
  lockout protections, ports, Docker detection), base system, hardening (sysctl, no core dumps,
  persistent journal, unattended security upgrades, sudo), nftables firewall (SSH from the admin
  networks, 8443/8444/tcp and 50000/udp from the LAN), sshd hardening with rollback, master role
  (`.deb` built on the controller, `master.ini`, admin password from the vault, metrics token,
  backup timer, CA fetched to `artifacts/`, optional enrollment token), fail2ban (SSH, console
  logins and invalid enrollment tokens from the JSON journal, recidive), optional node_exporter,
  MOTD, postflight checks (services, ports, TLS 1.2/1.3 only, certificate chain, security
  headers, mTLS refusal, default login refused, audit chain, backup, firewall, fail2ban filter).
  End-to-end test `tests/rsd-container-test.sh` (systemd container over SSH, run twice:
  idempotence) passing on Ubuntu 24.04 and Debian 12.
- **Docker** (`docker/`): master image on the distribution Python packages (read-only root, no
  capability, health check), simulated agent image (`RSD_DRY_RUN=1`), host Compose file, and a
  local test (`rsd-start.sh`, `rsd-status.sh`, `rsd-stop.sh`, `rsd-clean.sh`) with two agents
  that discover the master by broadcast and enroll unattended.
- **CLI:** `rsd-master status [--json]`, `rsd-master backup [--dir] [--keep]` (SQLite online
  snapshot + PKI + session key, 0600, rotation), `rsd-master check-password`, and
  `reset-password --password-stdin` for automation.
- **Daily backup timer** `rsd-master-backup.{service,timer}` in the `.deb` (sandboxed, no network).
- **Prometheus metrics** `GET /metrics` (bearer token file `security.metrics_token_file`).
- **SSH dashboard** `deploy/motd/rsd-motd` (service, agents UP, audit chain, backups, firewall
  drops, fail2ban bans) and pre-login banner.
- **Agent dry run** (`dry_run` / `RSD_DRY_RUN`): the power-off is logged, not executed.
- **Anti-indexing:** `robots.txt`, `X-Robots-Tag`, `<meta name="robots">`.
- **Resource accounting** (CPU, memory, I/O, IP, memory caps) in the master and agent units.
- **DevSecOps:** `make audit` (pip-audit, govulncheck), Dependabot, CI jobs `ansible-lint`,
  `sca`, `ansible-deploy` (Ubuntu 24.04, Debian 12), `docker` (stack test + Trivy image scan);
  real-browser check `make ui-check` (Playwright + Chrome).

### Changed
- The shutdown countdown reports "nothing pending" after a failed or simulated power-off.

## [0.1.0] - 2026-10-01

### Added
- **Master** (Python, FastAPI): HTTPS web console and REST API, mutual-TLS agent hub (JSON lines
  over TCP 8444), UDP discovery responder, uptime-limit policy engine, SQLite storage with a
  SHA-256 hash-chained audit log, `rsd-master` CLI (`serve`, `info`, `create-token`,
  `reset-password`, `verify-audit`), structured JSON logs, sandboxed systemd unit.
- **Local PKI**: ECDSA P-384 CA and server certificate created at first start (re-issued when a
  LAN address is missing or before expiry); automatic agent enrollment with one-time tokens and
  CA fingerprint pinning; agent certificate renewal over the mTLS link; revocation by deletion.
- **Web console**: machines (UP/DOWN, uptime, IP/MAC per interface, OS), shutdown of one or all
  machines with countdown/message/force, cancel, popup message, chat, per-machine settings
  (name, maximum uptime inherit/custom/unlimited), enrollment with ready-to-paste commands for
  Linux/macOS/Windows, settings (default limit in days/hours/minutes, warning, countdown), audit
  view; 12 locales; light/dark themes; strict CSP; forced change of the default password.
- **Agent** (Go, static binary): enrollment, discovery, persistent mTLS connection with backoff,
  DECLARE/UPDATE/KEEPALIVE, cancellable shutdown countdown, popups and chat dialogs in the user
  sessions (zenity/kdialog/notify-send, osascript, WTSSendMessage), uptime since boot or resume,
  systemd / launchd / Windows service integration, registry settings on Windows.
- **Packages**: `.deb` for Debian 12+ / Ubuntu 22.04+ / Linux Mint 21+ (master `all`, agent
  amd64/arm64/armhf), `.msi` for Windows x64 (wixl), universal `.pkg` for macOS 12+
  (pkgbuild/productbuild, optional signing and notarization).
- **Tooling**: `scripts/rsd-*.sh` (build, Docker package test, openssl PKI example), Makefile,
  pytest and Go test suites (oldest and newest dependency sets), ruff, bandit, ShellCheck,
  gitleaks, pre-commit, GitHub Actions CI and release pipeline.
