#!/usr/bin/env bash
# =============================================================================
# Remote Shutdown - LAN parental control and machine management (master/agent)
# -----------------------------------------------------------------------------
# File    : docker/rsd-docker-common.sh
# Purpose : Shared helpers of the local Docker scripts (start, status, stop, clean)
# Author  : Thierry Gayet <thierry.gayet@labworks.fr>
# Project : remote-shutdown (version: VERSION)
# Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
# =============================================================================
#
# Sourced (never executed) by docker/rsd-start.sh, rsd-status.sh, rsd-stop.sh and rsd-clean.sh.
# Loads the shared bash library (colors, logging, error handling, exit codes) and defines:
#   DOCKER_DIR, REPO_ROOT, LOCAL_DIR, COMPOSE_FILE, PROJECT, NETWORK, SERVICES   paths and names
#   compose ARGS...        docker compose on the local project
#   require_docker         docker CLI, Compose v2 and a reachable daemon (E_DEPS / E_STATE),
#                          with the exact fix printed (package to install, group, session)
#   project_running        success when at least one container of the project exists
#   https_url              URL of the web console (https://localhost:<port>/)
#   master_cli ARGS...     run rsd-master inside the master container

DOCKER_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$DOCKER_DIR/.." && pwd)"
# shellcheck source=../scripts/lib/rsd-common.sh
. "$REPO_ROOT/scripts/lib/rsd-common.sh"

# Used by the scripts that source this file.
# shellcheck disable=SC2034
readonly LOCAL_DIR="$DOCKER_DIR/.local"
readonly COMPOSE_FILE="$DOCKER_DIR/docker-compose.local.yml"
readonly PROJECT="rsd-local"
# shellcheck disable=SC2034
readonly NETWORK="rsd-local-net"
# shellcheck disable=SC2034
readonly IMAGES=(rsd-master:local rsd-agent:local)
# shellcheck disable=SC2034
readonly SERVICES=(master kid-laptop living-room-pc)
# shellcheck disable=SC2034
readonly AGENT_SERVICES=(kid-laptop living-room-pc)
export RSD_HTTPS_PORT="${RSD_HTTPS_PORT:-8443}"
export RSD_AGENT_PORT="${RSD_AGENT_PORT:-8444}"

# compose ARGS...: docker compose on the local project file.
compose() { docker compose -f "$COMPOSE_FILE" -p "$PROJECT" "$@"; }

# master_cli ARGS...: rsd-master inside the running master container (as its service account).
master_cli() { compose exec -T master rsd-master "$@"; }

# docker_pkg_hint KIND: install command for "engine", "compose" or "buildx" on this distribution
# (the distribution's docker.io flavor and Docker's docker-ce flavor use different packages).
docker_pkg_hint() {
  local ce=0 bin
  bin="$(command -v docker 2>/dev/null || true)"
  [[ -n "$bin" ]] && command -v dpkg >/dev/null 2>&1 &&
    dpkg -S "$(readlink -f "$bin")" 2>/dev/null | grep -q '^docker-ce' && ce=1
  if command -v apt-get >/dev/null 2>&1; then
    case "$1:$ce" in
      engine:*) echo "sudo apt install docker.io" ;;
      compose:1) echo "sudo apt install docker-compose-plugin" ;;
      compose:0) echo "sudo apt install docker-compose-v2" ;;
      buildx:1) echo "sudo apt install docker-buildx-plugin" ;;
      buildx:0) echo "sudo apt install docker-buildx" ;;
    esac
  else
    echo "see https://docs.docker.com/engine/install/"
  fi
}

# diagnose_daemon: explain why the Docker daemon is unreachable, then exit E_STATE
# (stopped daemon, user outside the docker group, or a membership newer than the session).
diagnose_daemon() {
  local sock="${DOCKER_HOST:-unix:///var/run/docker.sock}" user group
  sock="${sock#unix://}"
  user="$(id -un)"
  if [[ ! -S "$sock" ]]; then
    log_info "no Docker socket at $sock: sudo systemctl enable --now docker.socket docker.service"
    die "the Docker daemon is not running" "$E_STATE"
  fi
  if [[ ! -w "$sock" ]]; then
    group="$(stat -c %G "$sock" 2>/dev/null || echo docker)"
    if id -nG "$user" 2>/dev/null | tr ' ' '\n' | grep -qx "$group"; then
      log_info "$user is in '$group' but this session predates it: newgrp $group (or log in again)"
    else
      log_info "sudo usermod -aG $group $user && newgrp $group   (members of '$group' are root-equivalent)"
    fi
    die "permission denied on the Docker socket $sock" "$E_STATE"
  fi
  die "cannot reach the Docker daemon" "$E_STATE"
}

# require_docker: docker CLI with the Compose v2 plugin, and a daemon we may talk to.
require_docker() {
  command -v docker >/dev/null 2>&1 || die "docker is missing: $(docker_pkg_hint engine)" "$E_DEPS"
  docker compose version >/dev/null 2>&1 ||
    die "Docker Compose v2 is missing: $(docker_pkg_hint compose)" "$E_DEPS"
  docker info >/dev/null 2>&1 || diagnose_daemon
}

# project_running: success when containers of the project exist (running or not).
project_running() { [[ -n "$(compose ps -a -q 2>/dev/null)" ]]; }

# https_url: address of the web console.
https_url() { echo "https://localhost:${RSD_HTTPS_PORT}/"; }
