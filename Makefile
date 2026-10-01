# =============================================================================
# Remote Shutdown - LAN parental control and machine management (master/agent)
# -----------------------------------------------------------------------------
# File    : Makefile
# Purpose : Developer entry points: lint, tests, security scans, agent build, deb/msi/pkg packages
# Author  : Thierry Gayet <thierry.gayet@labworks.fr>
# Project : remote-shutdown (version: VERSION)
# Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
# =============================================================================
# Python tools run through uv/uvx: nothing is installed globally.
# "make check" is the local equivalent of the CI pipeline (.github/workflows/ci.yml).

PYTHON  ?= 3.12
VENV    ?= .venv
PY      := $(VENV)/bin/python
OLDVENV ?= .venv-oldest
UVX     := uvx -q
GO      ?= go
PYSRC   := master tests scripts

.DEFAULT_GOAL := help
.PHONY: help deps build linux linux-deb linux-rpm macosx-pkg win-msi exe checksums venv venv-oldest lint sast \
        shellcheck test test-oldest go-test go-vet audit check agent deb rpm msi pkg packages test-distro test-deb \
        test-rpm ui-check run-master docker-start docker-status docker-stop docker-clean deploy-lint deploy-test \
        version bump secrets clean

help: ## List the available targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "} {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

venv: ## Development virtualenv (recent dependencies)
	uv venv --python $(PYTHON) $(VENV)
	uv pip install --python $(PY) -r requirements-dev.txt

venv-oldest: ## Virtualenv with the Ubuntu 22.04 / Mint 21 package versions (Python 3.10)
	uv venv --python 3.10 $(OLDVENV)
	uv pip install --python $(OLDVENV)/bin/python -r requirements-oldest.txt

lint: ## Static analysis (ruff for Python, gofmt + go vet for the agent)
	$(UVX) ruff check $(PYSRC)
	@test -z "$$(cd agent && gofmt -l .)" || { echo "gofmt: run 'gofmt -w agent'"; exit 1; }

sast: ## Security static analysis (bandit)
	$(UVX) --from "bandit[toml]" bandit -q -c pyproject.toml -r master scripts

shellcheck: ## Lint every shell script (scripts, docker, deploy, package maintainer scripts)
	$(UVX) --from shellcheck-py shellcheck scripts/*.sh scripts/lib/*.sh packaging/debian/*/postinst \
	  packaging/debian/*/prerm packaging/debian/*/postrm packaging/debian/rsd-master.sh \
	  packaging/macos/scripts/* packaging/macos/*.sh docker/*.sh deploy/motd/rsd-motd deploy/motd/10-rsd-master \
	  deploy/ansible/*.sh deploy/ansible/tests/*.sh

test: ## Master tests (recent dependencies)
	$(PY) -m pytest -q

test-oldest: ## Master tests with the oldest supported dependencies (make venv-oldest first)
	$(OLDVENV)/bin/python -m pytest -q

go-vet: ## go vet for every target OS
	cd agent && for os in linux windows darwin; do GOOS=$$os $(GO) vet ./... || exit 1; done

go-test: ## Agent unit tests (race detector)
	cd agent && $(GO) test -race -count=1 ./...

audit: ## Known vulnerabilities: Python dependencies (pip-audit) and the agent (govulncheck)
	$(UVX) pip-audit -r requirements-dev.txt --progress-spinner off
	cd agent && $(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

check: lint sast shellcheck go-vet go-test test ## Everything the CI runs locally (except packages and audit)

# --- packages -------------------------------------------------------------------------
# The agent is a static Go binary embedded in every package: the target computers need
# neither Go nor any library. Go, dpkg, rpmbuild and wixl are needed on the build machine only.
# Every package target first rebuilds the agent binaries ("agent", run once per make call;
# the Go build cache makes it fast), so a package never embeds a stale binary.

deps: ## Install the tools needed to build the packages (Go, dpkg-deb, rpmbuild, wixl/msitools)
	./scripts/rsd-install-deps.sh

build: linux win-msi exe ## Build every package of this OS (.deb, .rpm, .msi, .exe; + .pkg on macOS), then SHA256SUMS
ifeq ($(shell uname -s),Darwin)
	$(MAKE) macosx-pkg
else
	@echo "macosx-pkg skipped: the .pkg is built on macOS (make macosx-pkg) or by the CI macOS job"
endif
	$(MAKE) checksums

linux: linux-deb linux-rpm ## Linux packages: .deb (Debian/Ubuntu/Mint) and .rpm (Fedora/RHEL/openSUSE)

linux-deb: agent ## .deb: rsd-master (all) and rsd-agent (amd64, arm64, armhf)
	./scripts/rsd-build-deb.sh --arch amd64 --arch arm64 --arch armhf

linux-rpm: agent ## .rpm: rsd-master (noarch) and rsd-agent (x86_64, aarch64, armv7hl)
	./scripts/rsd-build-rpm.sh --arch x86_64 --arch aarch64 --arch armv7hl

macosx-pkg: ## macOS installer .pkg (universal binary, launchd daemon; on macOS only)
	./scripts/rsd-build-agent.sh --target darwin/amd64 --target darwin/arm64
	./scripts/rsd-build-pkg.sh

win-msi: agent ## Windows installer .msi (x64 service, unattended enrollment properties)
	./scripts/rsd-build-msi.sh

exe: agent ## Standalone Windows agent executables (dist/rsd-agent-<v>-windows-{amd64,arm64}.exe)
	./scripts/rsd-build-exe.sh

checksums: ## dist/SHA256SUMS of every package (sha256sum on Linux, shasum on macOS)
	cd dist && files=$$(ls -p | grep -v / | grep -vx SHA256SUMS) && \
	  { if command -v sha256sum >/dev/null; then sha256sum -- $$files; else shasum -a 256 -- $$files; fi; } > SHA256SUMS
	@echo "dist/SHA256SUMS: $$(wc -l < dist/SHA256SUMS) package(s)"

agent: ## Cross-compile the agent only (dist/bin/<os>-<arch>/)
	./scripts/rsd-build-agent.sh

# Former names, kept for compatibility.
deb: linux-deb ## Alias of linux-deb
rpm: linux-rpm ## Alias of linux-rpm
msi: win-msi ## Alias of win-msi
pkg: macosx-pkg ## Alias of macosx-pkg
packages: linux win-msi exe ## Every package buildable on Linux (alias of build without the .pkg)

test-distro: ## Master test suite inside Ubuntu 26.04/24.04/22.04 and Debian 13/12 on their own packages
	./scripts/rsd-test-distro.sh

test-deb: ## Install and exercise the .deb packages in Docker (Debian, Ubuntu, Mint)
	./scripts/rsd-test-deb.sh

test-rpm: ## Install and exercise the .rpm packages in Docker (Fedora, Rocky Linux, openSUSE)
	./scripts/rsd-test-rpm.sh --master-image $(or $(RSD_RPM_MASTER_IMAGE),fedora:latest)

ui-check: ## Real-browser check of the console (Playwright + Google Chrome, live agent)
	uv run --no-project --with playwright python tests/browser/ui_check.py --python $(PY)

docker-start: ## Build the images and start master + 2 simulated agents (https://localhost:8443)
	./docker/rsd-start.sh

docker-status: ## State of the local Docker test (containers, console, agents, audit)
	./docker/rsd-status.sh

docker-stop: ## Stop the local Docker test (data, agents and images kept)
	./docker/rsd-stop.sh

docker-clean: ## Remove the local Docker test (--volumes/--purge: see the script)
	./docker/rsd-clean.sh

deploy-lint: ## Ansible syntax check, ansible-lint (production profile) and yamllint
	./deploy/ansible/rsd-deploy.sh lint

deploy-test: ## Run the playbook twice against a systemd container (IMAGE=ubuntu:26.04 by default)
	./deploy/ansible/tests/rsd-container-test.sh --image $(or $(IMAGE),ubuntu:26.04)

run-master: ## Run a development master on https://localhost:8443 (data in ./.dev)
	RSD__PATHS__DATA_DIR=.dev RSD__LOG__LOG_JSON=false PYTHONPATH=master $(PY) -m rsd_master serve

version: ## Print the software version (single source: VERSION)
	@python3 scripts/rsd-bump-version.py --show

# Usage: make bump PART=patch|minor|major|X.Y.Z  (updates VERSION and the CHANGELOG)
bump: ## Bump the version and open the CHANGELOG entry (PART=patch|minor|major|X.Y.Z)
	python3 scripts/rsd-bump-version.py $(PART)

secrets: ## Secret scanning of the working tree (gitleaks)
	gitleaks dir --no-banner --redact . || gitleaks detect --no-git --no-banner --redact --source .

clean: ## Remove caches and build artifacts
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache .coverage htmlcov .dev
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
