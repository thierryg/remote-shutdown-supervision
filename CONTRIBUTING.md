<!--
=============================================================================
Remote Shutdown - LAN parental control and machine management (master/agent)
=============================================================================
File    : CONTRIBUTING.md
Purpose : Development environment, conventions, tests and packaging for contributors
Author  : Thierry Gayet <thierry.gayet@labworks.fr>
Project : remote-shutdown (version: VERSION)
Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
=============================================================================
-->
# Contributing to Remote Shutdown

## Development environment

```bash
make venv              # Python virtualenv with recent dependencies (uv)
make venv-oldest       # Python 3.10 + the Ubuntu 22.04 / Mint 21 package versions
make check             # ruff, gofmt, bandit, ShellCheck, go vet (3 OSes), go test -race, pytest
make test-oldest       # the master suite against the oldest supported dependencies
make test-distro       # the master suite inside Ubuntu 26.04/24.04/22.04 and Debian 13/12 (Docker)
make run-master        # development master on https://localhost:8443 (data in ./.dev)
make ui-check          # real-browser check (Playwright + Google Chrome, live agent)
make audit             # pip-audit + govulncheck
make docker-start      # master + 2 simulated agents in Docker (docker-status / -stop / -clean)
make deploy-lint       # Ansible syntax, ansible-lint (production), yamllint
make deploy-test       # playbook twice against a systemd container (IMAGE=debian:12 ...)
uvx pre-commit install # run the hooks on every commit
```

Requirements: Python 3.10+, [uv](https://docs.astral.sh/uv/), Go (latest stable; `agent/go.mod`
states the minimum), ShellCheck, Docker for the package tests. The packaging tools are
installed by `make deps` (Go from go.dev, dpkg-deb, rpmbuild, wixl/msitools); the `.pkg` needs
a Mac.

```bash
make deps              # once per build machine
make build             # .deb + .rpm + .msi + .exe (+ .pkg on macOS) and dist/SHA256SUMS
make linux-deb | linux-rpm | win-msi | exe | macosx-pkg   # one format
make test-deb test-rpm # install the packages in Docker
```

A development agent can run without root against the development master:

```bash
cd agent && go build -o /tmp/rsd-agent . && cd ..
echo '{"master":"127.0.0.1","state_dir":"/tmp/rsd-state"}' > /tmp/agent.json
/tmp/rsd-agent --config /tmp/agent.json enroll --token <TOKEN> --fingerprint <FP>
/tmp/rsd-agent --config /tmp/agent.json run
```

## Conventions

- **Language:** identifiers, file names, comments, docstrings, logs and every Markdown file in
  **US English**. The console is translated (12 locales, reference `en-US.json`).
- **File header:** every source file starts with the standard header (copy it from a sibling).
- **Docstrings:** Google style in Python, doc comments in Go, JSDoc in `app.js`.
- **Compatibility:** the master must keep working with FastAPI 0.63, Starlette 0.13, pydantic 1,
  uvicorn 0.15 and cryptography 3.4 (`requirements-oldest.txt`); the CI runs both sets.
- **Style:** ruff (120 columns), gofmt; no inline style or script in the console.
- **Tests:** every behavior change comes with a test; tests need no root, network or hardware.
- **Scripts:** see AGENTS.md (naming `rsd-*.sh`, `lib/rsd-common.sh`, exit codes, `--help`).
- **Changelog:** add an entry under *Unreleased* in `CHANGELOG.md`.

## Versioning

The version lives only in `VERSION`. `make bump PART=patch|minor|major` updates it and opens the
CHANGELOG section; then tag `vX.Y.Z`: the CI builds and publishes every package.

## Commits and pull requests

[Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`,
`build:`, `ci:`, `test:`, `refactor:`, `security:`), imperative mood, English. One topic per pull
request; the CI must be green. Changes to authentication, sessions, PKI, the agent protocol or
the systemd sandboxing require a second review.
