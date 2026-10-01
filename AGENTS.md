<!--
=============================================================================
Remote Shutdown - LAN parental control and machine management (master/agent)
=============================================================================
File    : AGENTS.md
Purpose : Project memory and standing rules for AI coding agents (Claude, Gemini, Codex, Copilot...)
Author  : Thierry Gayet <thierry.gayet@labworks.fr>
Project : remote-shutdown (version: VERSION)
Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
=============================================================================
-->
# AGENTS.md — project memory for AI agents

This is the canonical instruction file for every AI coding agent working on this repository.
`CLAUDE.md` and `GEMINI.md` point here. Read it fully before any change. The rules below are
**standing orders** from the project owner (inherited from the Jarvis project conventions):
apply them without being asked again.

## 1. What Remote Shutdown is

A LAN parental-control and machine-management system with a master/agent architecture.

| Part | How |
|---|---|
| Master | Python 3.10+ (FastAPI, uvicorn), Linux, systemd service `rsd-master`, unprivileged account |
| Web console | HTTPS 8443, framework-free SPA, 12 locales, bcrypt + short JWT session cookie |
| Agent hub | TCP 8444, **JSON lines over mutual TLS** (stdlib only on both sides) |
| Discovery | UDP 50000 broadcast, bootstrap only (never trusted alone) |
| PKI | Local CA (ECDSA P-384) built by the master; agents enroll with a one-time token + pinned CA fingerprint |
| Agent | Go static binary `rsd-agent` (Linux, Windows, macOS): systemd / Windows service / launchd |
| Policy | Uptime limit per machine (inherit / custom / unlimited), warning popup, shutdown countdown |
| Storage | SQLite WAL in `/var/lib/rsd-master`, SHA-256 hash-chained audit log |
| Packages | `.deb` (Debian, Ubuntu, Mint), `.msi` (Windows, wixl), `.pkg` (macOS, pkgbuild) |
| Deployment | Ansible IaC of the master (`deploy/ansible`), Docker images + local test (`docker/`) |
| Operations | daily backup timer, `rsd-master status`, SSH MOTD (`deploy/motd`), Prometheus `/metrics` |

Design decisions that must not be undone without the owner's approval:
- The agent → master connection is **agent-initiated**: machines need no inbound port.
- The agent identity is the **certificate CN chosen by the master**, never a field of a message.
- Agents verify the master by **chain + serverAuth EKU**, not by host name (DHCP-proof).
- WebSocket was dropped for the hub: `python3-websockets` 9.1 of Ubuntu 22.04 is broken on
  Python 3.10. JSON lines over TLS have the same semantics with no dependency.
- The master runs on the **distribution's Python packages** (FastAPI ≥ 0.63, cryptography ≥ 3.4,
  pydantic 1 or 2): never use an API newer than those (see `requirements-oldest.txt`).
- **Reference platforms: Ubuntu Server 26.04 LTS and Debian 13** (latest LTS / stable, Python
  3.14 / 3.13). Everything must pass there first: `make test-distro`, `make test-deb`,
  `make deploy-test` (26.04 by default, `IMAGE=debian:13`), Docker image on 26.04.
- Issued certificates follow the strict X.509 profile (SKI + AKI) enforced by Python 3.13+.

## 2. Layout

| Path | Content |
|---|---|
| `master/rsd_master/` | `config` (INI + env), `db` (SQLite, audit), `pki`, `auth`, `hub` (mTLS), `discovery`, `policy`, `web` (FastAPI), `server`, `cli` |
| `master/rsd_master/static/` | `index.html`, `app.js`, `style.css`, `favicon.svg`, `i18n/*.json` |
| `agent/` | Go agent: `main`, `config`, `pki`, `enroll`, `discovery`, `agent` (protocol), `shutdown`, `sysinfo`, `logging`, `i18n` (+ `i18n/*.json`, 12 locales), `platform_{unix,linux,darwin,windows}.go` |
| `packaging/` | systemd units (master, agent, backup timer), default configs, Debian control/maintainer scripts, RPM specs, WiX source, launchd plist + pkg scripts |
| `deploy/ansible/` | playbook `site.yml`, roles (preflight, base, hardening, firewall, ssh, master, fail2ban, monitoring, motd, postflight), `rsd-deploy.sh`, container test `tests/rsd-container-test.sh` |
| `deploy/motd/` | `issue.net`, `rsd-motd` dashboard, `10-rsd-master` pam_motd hook |
| `docker/` | `Dockerfile.master`, `Dockerfile.agent`, `docker-compose.yml` (host), `docker-compose.local.yml` + `rsd-start/status/stop/clean.sh`, `rsd-docker-common.sh` |
| `scripts/` | `rsd-build-agent.sh`, `rsd-build-deb.sh`, `rsd-build-msi.sh`, `rsd-build-pkg.sh`, `rsd-test-deb.sh`, `rsd-gen-certs.sh`, `rsd-bump-version.py`, `lib/rsd-common.sh` |
| `tests/` | pytest suite (master, CLI, repository rules), `browser/ui_check.py` (Playwright); Go tests live in `agent/*_test.go` |
| `docs/` | `ARCHITECTURE.md`, `PROTOCOL.md` |
| `VERSION` | **single source of the version** |
| `backup/` | historical analysis by the owner (kept as is, outside the rules below) |

## 3. Standing rules (mandatory)

### Language and style
- **Code in US English:** file, function, class and variable names, and **all comments and
  docstrings** (Python, Go, bash, Makefile, HTML, JS, CSS, YAML, XML).
- **Every Markdown file is written in technical US English** (except `backup/`).
- **Header** at the top of every source file: project banner, `File`, `Purpose`,
  `Author : Thierry Gayet <thierry.gayet@labworks.fr>`, `Project : remote-shutdown (version: VERSION)`,
  `Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD`. JSON files cannot carry one.
  In XML/HTML comments the separator line is made of `=` (`--` is illegal in an XML comment).
- **Document every module, class, function and method** (Google-style docstrings, Go doc comments, JSDoc).
- **Match the surrounding code:** comment density, naming and idioms.

### Bash scripts
- **Naming:** `rsd-XXXX.sh` everywhere (`scripts/`, `docker/`, `deploy/ansible/`; Python helpers
  `rsd-XXXX.py`), libraries `scripts/lib/rsd-common.sh` and `docker/rsd-docker-common.sh`.
  Installed commands keep their names (`rsd-master`, `rsd-agent`, `rsd-agent-uninstall`, `rsd-motd`,
  update-motd hook `10-rsd-master`).
- **Structure:** source `lib/rsd-common.sh` (strict mode, ERR/EXIT traps, colors), documented
  functions, `main "$@"` at the end; `--help` prints the header block.
- **Output:** `log_info/ok/warn/error/step`, honors `NO_COLOR`; errors through `die MSG CODE`.
- **Exit codes** (documented in each header): 0 OK, 1 runtime, 2 usage, 3 privileges,
  4 prerequisites, 5 configuration, 6 network, 7 state, 8 warnings. Unknown option → 2.
- **Quality:** idempotent, `make shellcheck` clean. Maintainer scripts are POSIX `sh`.

### Versioning
- The version lives only in `VERSION` (SemVer). Python reads it (`rsd_master.__version__`), Go
  receives it with `-ldflags -X main.version`, packages read it in the build scripts.
- Bump it with every delivered batch: `make bump PART=patch|minor|major`, then fill in the
  `CHANGELOG.md` entry (Keep a Changelog).

### Documentation is always regenerated
- Every change updates **all** affected docs: `README.md`, `INSTALL.md`, `docs/ARCHITECTURE.md`,
  `docs/PROTOCOL.md`, `SECURITY.md`, `CHANGELOG.md`, `CONTRIBUTING.md` and this file.
- A change is not done while a doc is stale.

### Agent dialogs
- Every text shown on a computer is localized: a key in **all** `agent/i18n/*.json` (en-US is
  the reference; `TestEveryLocaleHasTheReferenceKeys` enforces it). Texts generated by the
  master travel as `key` + `params` with an English fallback; free admin text stays as typed.
- Dialogs follow the user's language and light/dark theme (Linux env, macOS native); Windows
  message boxes stay classic (documented limitation).
- The agent is and stays a **static standalone binary** (no cgo, assets embedded).

### Web console
- Locales: en-US (reference) plus fr, es, nl, de, it, ru, zh, id, ko, ja, th. Every new string
  gets a key in **all** `static/i18n/*.json` files (`tests/test_repo.py` enforces it).
- CSP-safe: no inline script or style, no `innerHTML` with data (build nodes with `h()`).
- State-changing requests carry `X-RSD: 1`; background polling carries `X-RSD-Background: 1`.

### Security (never break)
- Never commit keys, certificates, tokens, databases or `session.key` (see `.gitignore`).
- Enrollment tokens are stored hashed (SHA-256), shown once, masked (`***`) in the audit log.
- Every administrative action is audited (hash chain, diffs for value changes).
- Default web account `admin` / `admin` must be changed at first login (enforced by the API).
- The master runs unprivileged and sandboxed (systemd unit); the agent runs as root/SYSTEM only
  because powering off and opening popups in user sessions require it.
- Never expose the master ports on the Internet (LAN or VPN only).
- Git: commit or push only when the owner asks.

### Ansible and Docker
- Ansible variables are global and prefixed `rsd_` (`group_vars/all/main.yml` documents each one);
  secrets only in `group_vars/all/vault.yml` (ansible-vault), tasks handling them use `no_log`.
- Every role stays idempotent: `make deploy-test` fails when the second run changes anything
  but the requested enrollment token. ansible-lint runs with the **production** profile.
- No fact cache (`gathering = implicit`). Container-incompatible tasks check `rsd_in_container`.
- Docker images use the same distribution packages as the `.deb`; containers drop every
  capability; the agent image is a simulation (`RSD_DRY_RUN=1`).

### Validation before saying "done"
Run `make check` (ruff, gofmt, bandit, ShellCheck, go vet on 3 OSes, go test -race, pytest),
`make test-oldest` (Ubuntu 22.04 package versions), `make test-distro` (every distribution on its
own packages), `make audit`, and depending on the change:
`make ui-check` (console), `make packages` + `make test-deb` (packaging), `make deploy-lint` +
`make deploy-test` (Ansible), `make docker-start docker-status docker-clean` (Docker).
Report real results, failures included.

## 4. Useful commands

```bash
make venv check                 # development environment and full local CI
make venv-oldest test-oldest    # tests against the Ubuntu 22.04 / Mint 21 Python packages
make run-master                 # development master on https://localhost:8443 (admin/admin)
make deps                       # build tools: Go (latest stable), dpkg-deb, rpmbuild, wixl/msitools
make build                      # every package of this OS + dist/SHA256SUMS (.pkg on macOS only)
make linux | linux-deb | linux-rpm | win-msi | exe | macosx-pkg
make test-rpm                   # RPMs in Docker: Fedora 44, Rocky Linux 10, openSUSE Leap 16
make test-distro                # master suite inside Ubuntu 26.04/24.04/22.04, Debian 13/12 (apt packages only)
make test-deb                   # install the .deb in Docker: Ubuntu 26.04/24.04/22.04, Debian 13/12, Mint 22
make deploy-lint deploy-test    # Ansible: lint, then deploy twice into a systemd container
make docker-start               # local Docker test: master + 2 simulated agents
make ui-check audit             # browser check; pip-audit + govulncheck
make version / make bump PART=minor
```
