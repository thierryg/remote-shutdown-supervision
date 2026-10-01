#!/usr/bin/env bash
# =============================================================================
# Remote Shutdown - LAN parental control and machine management (master/agent)
# -----------------------------------------------------------------------------
# File    : docker/rsd-stop.sh
# Purpose : Stop the local Docker test gracefully (containers, data and images kept)
# Author  : Thierry Gayet <thierry.gayet@labworks.fr>
# Project : remote-shutdown (version: VERSION)
# Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
# =============================================================================
#
# Stops the containers without removing them: the master data volume and the enrolled
# agents' certificates (stored in their containers) survive, so docker/rsd-start.sh restarts
# the same machines. docker/rsd-clean.sh frees everything.
#
# Usage:
#   docker/rsd-stop.sh [--timeout SECONDS] [--help]
#     --timeout SECONDS   grace period per container (default 20)
#
# Prerequisites: Docker Engine with the Compose v2 plugin.
#
# Exit codes:
#   0  stopped (or not running)
#   1  a docker command failed
#   2  usage error
#   4  prerequisite missing
#   7  Docker daemon unreachable

. "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/rsd-docker-common.sh"

TIMEOUT=20

usage() { sed -n '/^# Usage:/,/^# Prerequisites:/p' "${BASH_SOURCE[0]}" | sed -e 's/^# \{0,1\}//' -e '$d'; }

# parse_args ARGS...: command-line options.
parse_args() {
  while (($#)); do
    case "$1" in
      --timeout) TIMEOUT="${2:?--timeout needs seconds}"; shift ;;
      -h | --help) usage; exit "$E_OK" ;;
      *) die "unknown option: $1 (see --help)" "$E_USAGE" ;;
    esac
    shift
  done
  [[ "$TIMEOUT" =~ ^[0-9]+$ ]] || die "--timeout needs a number of seconds" "$E_USAGE"
}

# main ARGS...: graceful stop of the whole project.
main() {
  parse_args "$@"
  require_docker
  if ! project_running; then
    log_ok "the local test is not running"
    exit "$E_OK"
  fi
  log_step "Stopping $PROJECT (graceful, ${TIMEOUT} s per container)"
  compose stop --timeout "$TIMEOUT"
  log_ok "stopped; data, agents and images kept (docker/rsd-start.sh restarts, docker/rsd-clean.sh frees them)"
}

main "$@"
