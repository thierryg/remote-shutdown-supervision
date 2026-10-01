<!--
=============================================================================
Remote Shutdown - LAN parental control and machine management (master/agent)
=============================================================================
File    : docs/ARCHITECTURE.md
Purpose : Components, data flows, PKI, policy engine, packaging and design decisions
Author  : Thierry Gayet <thierry.gayet@labworks.fr>
Project : remote-shutdown (version: VERSION)
Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
=============================================================================
-->
# Architecture

## 1. Components

```
                          ┌───────────────────────── rsd-master (one asyncio loop) ─────────────────────────┐
 browser ── HTTPS 8443 ──►│ uvicorn + FastAPI (web.py)   static SPA · REST API · /api/enroll · /ca.crt         │
                          │        │ await hub.send()                                                        │
 agents ── mTLS 8444 ────►│ AgentHub (hub.py)            JSON lines · identity = cert CN · live registry     │
 agents ── UDP 50000 ────►│ DiscoveryProtocol            DISCOVER → MASTER                                   │
                          │ PolicyEngine (policy.py)     every 15 s: warn / shut down on uptime limit        │
                          │ PKI (pki.py)                 CA P-384 · server cert · signs agent CSRs           │
                          │ Database (db.py)             SQLite WAL: users, agents, tokens, settings, chat,  │
                          │                              audit (SHA-256 chain)                               │
                          └──────────────────────────────────────────────────────────────────────────────────┘
```

Running everything in one event loop keeps the registry of live connections in memory without
locks: a REST handler awaits `AgentHub.send()` directly. SQLite calls are short and synchronous;
bcrypt runs in the thread pool.

| Module | Responsibility |
|---|---|
| `config.py` | INI file + `RSD__SECTION__KEY` environment, restart-required settings |
| `logs.py` | one JSON object per line (journald), `extra=` fields preserved |
| `db.py` | schema, data access, audit hash chain (`verify_audit`) |
| `pki.py` | CA creation, server certificate (re-issued when an address is missing or expiry < 30 days), CSR signing |
| `auth.py` | bcrypt, JWT sessions (idle + absolute lifetime, token version), rate limiter |
| `hub.py` | TLS server callback, peer identity, message dispatch, keepalive monitor, renewal |
| `discovery.py` | UDP responder with per-source rate limit |
| `policy.py` | effective limit, warning and shutdown once per boot |
| `web.py` | security middleware (session, CSRF, headers, `X-Robots-Tag`), routes, static files, `robots.txt`, Prometheus `/metrics` (bearer token) |
| `server.py` | context construction (default admin), startup and shutdown of every component, hourly server-certificate check |
| `cli.py` | `serve`, `info`, `status`, `create-token`, `reset-password` (`--password-stdin`), `check-password`, `backup`, `verify-audit`, `version`; drops to the service account when run as root |

Agent (Go, standard library + `golang.org/x/sys`):

| File | Responsibility |
|---|---|
| `main.go` | command line, exit codes |
| `config.go` | JSON file, `RSD_*` environment, Windows registry, `state.json` |
| `pki.go` | key/CSR, credentials storage, CA pinning, chain verification |
| `enroll.go`, `discovery.go` | enrollment over HTTPS, UDP discovery |
| `agent.go` | connection loop, backoff, protocol, popups (bounded), renewal |
| `shutdown.go` | cancellable countdown independent of the connection |
| `sysinfo.go` | interfaces, uptime since boot or resume (suspend detection) |
| `i18n.go`, `i18n/*.json` | embedded translations (12 locales), OS locale matching, `Note` rendered per desktop user |
| `platform_*.go` | paths, power off, uptime source, desktop dialogs (user language and theme), service integration |

## 2. Flows

### 2.1 Enrollment

```
admin ──► console: create token (label, validity, uses) ──► token shown once, stored as SHA-256
admin ──► machine: rsd-agent enroll --token T --fingerprint F [--master M]
agent:  discovery (if no M) → key P-256 + CSR → TLS pinned on F → POST /api/enroll
master: consume token → uuid → sign (CN=uuid, clientAuth) → agents row (serial) → audit
agent:  verify CA == F, store key/cert/CA → service connects on 8444
```

### 2.2 Command

```
console → POST /api/agents/{id}/shutdown {delay, message, force}
web.py  → audit + hub.send(SHUTDOWN) ──► agent: popup, countdown, STATE, ACK ──► poweroff
console polls GET /api/agents every 5 s (status, uptime, shutdown_at)
```

### 2.3 Uptime policy

Effective limit = `unlimited` → none; `custom` → the machine's minutes; `inherit` → the global
`default_limit_minutes` (0 = none). For each UP machine with a limit, every 15 s:
`warning_minutes` before the limit a popup is sent once per boot; at the limit a SHUTDOWN with
`shutdown_delay_seconds` is sent once per boot (re-sent if the machine is still up 2 minutes
after the countdown). Policy shutdowns are audited with actor `policy`.

The uptime reported by the agents restarts at boot **and at resume from sleep or hibernation**
(the wall clock is compared with a clock that stops during sleep). This also covers the Windows
"fast startup" hybrid shutdown, after which the boot counter would otherwise keep running.

## 3. PKI

| Object | Algorithm | Lifetime | Usage | Location |
|---|---|---|---|---|
| CA | ECDSA P-384, `pathlen:0` | 10 years | keyCertSign, cRLSign | `/var/lib/rsd-master/pki/ca.{key,crt}` |
| Server | ECDSA P-256 | 397 days, re-issued 30 days before expiry or when a LAN address changes (checked at start and hourly; the master then exits with status 75 and systemd restarts it) | serverAuth, SAN = names + LAN IPs | `pki/server.{key,crt}` (chain) |
| Agent | ECDSA P-256 (key generated on the agent) | 365 days, renewed at 30 days | clientAuth, `CN=<uuid>` | agent state directory |

Revocation is a database decision: deleting a machine (or renewing its certificate) changes the
accepted serial, so the hub refuses the old certificate at the next handshake and closes the
live connection at once. No CRL distribution is needed because the master is the only relying
party. `scripts/rsd-gen-certs.sh` reproduces the same PKI with openssl, e.g. to create the CA
offline and install it before the first start.

## 4. Packaging

| Package | Built by | Content |
|---|---|---|
| `rsd-master_<v>_all.deb` | `rsd-build-deb.sh` | `/usr/lib/rsd-master/rsd_master`, `/usr/bin/rsd-master`, unit, `/etc/rsd-master/master.ini`; depends on the distribution Python packages |
| `rsd-agent_<v>_<arch>.deb` | `rsd-build-deb.sh` | static binary, unit, `/etc/rsd-agent/agent.json` |
| `rsd-agent-<v>-x64.msi` | `rsd-build-msi.sh` (wixl) | binary, LocalSystem auto service, registry settings, major upgrade |
| `rsd-agent-<v>.pkg` | `rsd-build-pkg.sh` (macOS) | universal binary, launchd daemon, default config, uninstaller; optional signing and notarization |
| `rsd-master-<v>-1.noarch.rpm` | `rsd-build-rpm.sh` | same content as the `.deb`, `python3dist()` requirements (Fedora, openSUSE) |
| `rsd-agent-<v>-1.<arch>.rpm` | `rsd-build-rpm.sh` | static binary, unit, config (Fedora, RHEL/Rocky/Alma, openSUSE; x86_64, aarch64, armv7hl) |
| `rsd-agent-<v>-windows-<arch>.exe` | `rsd-build-exe.sh` | the standalone agent binary (amd64, arm64) |

Every agent package embeds the same **static** binary (`CGO_ENABLED=0`, translations
embedded): the computers need neither Go nor any library. Go, dpkg-deb, rpmbuild and wixl are
build-machine tools only (`make deps`). The version of every package comes from `VERSION`.

The CI (`.github/workflows/ci.yml`) builds the Linux and Windows packages on Ubuntu, the macOS
package on a macOS runner, runs the master suite inside Ubuntu 26.04/24.04/22.04 and Debian
13/12 on their own apt packages (`scripts/rsd-test-distro.sh`), installs the `.deb` in the same
containers, and publishes everything with `SHA256SUMS` on a `v*` tag.

## 5. Deployment and operations

| Artifact | Role |
|---|---|
| `deploy/ansible/` | IaC of the master: preflight (lockout protections) → base → hardening → nftables → sshd → `.deb` + `master.ini` + vault password → fail2ban (JSON journal filter) → node_exporter → MOTD → postflight (TLS, headers, mTLS, login, audit, backup, firewall, bans); tested twice (idempotence) on Ubuntu 26.04, Debian 13, Ubuntu 24.04 and Debian 12 systemd containers |
| `docker/` | `Dockerfile.master` (Ubuntu 26.04 LTS + the same distribution Python packages as the `.deb`, read-only root, no capability), `Dockerfile.agent` (static agent, dry run), `docker-compose.yml` (host networking), `docker-compose.local.yml` + `rsd-start/status/stop/clean.sh` (master + 2 simulated agents that discover the master by broadcast and enroll by themselves) |
| `packaging/systemd/rsd-master-backup.{service,timer}` | daily consistent backup, 14 archives, sandboxed, no network |
| `deploy/motd/` | pre-login banner and post-login dashboard (`rsd-motd`) |

## 6. Design decisions

| Decision | Reason |
|---|---|
| Agent-initiated persistent connection | No inbound port or firewall rule on the machines; commands arrive instantly |
| JSON lines over TLS instead of WebSocket | Same semantics, standard library only; `python3-websockets` 9.1 (Ubuntu 22.04) is broken on Python 3.10 |
| Distribution Python packages for the master | Security updates by the distribution, no vendored wheels; code limited to FastAPI 0.63 / pydantic 1–2 APIs |
| Go for the agent | One static binary per OS, no runtime, native service integration |
| Identity = certificate CN chosen by the master | An agent cannot claim another identity; deletion = revocation |
| Chain-only verification of the master | Survives DHCP address changes; only the master holds a serverAuth certificate of the CA |
| Discovery as a hint only | UDP cannot be authenticated; the pinned fingerprint is the trust anchor |
| SQLite | A home or a classroom: tens of machines; zero administration |
| Certificates follow the strict X.509 profile (SKI + AKI) | Python 3.13+ (Debian 13, Ubuntu 26.04) verifies with `VERIFY_X509_STRICT` by default; the hub still accepts the agent certificates of the first releases (chain, validity, EKU and recorded serial are verified), and the server certificate is re-issued at start when it lacks the AKI |
| No Ansible fact cache | A reinstalled host must never be handled with the facts (Python interpreter) of its previous system |
| Admin password from the vault, checked with `check-password` | No `admin`/`admin` window on an Ansible-deployed master; no login attempt (audit noise) to test idempotence |
