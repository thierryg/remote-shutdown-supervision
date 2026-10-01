#!/usr/bin/env bash
# =============================================================================
# Remote Shutdown - LAN parental control and machine management (master/agent)
# -----------------------------------------------------------------------------
# File    : docker/rsd-clean.sh
# Purpose : Remove the local Docker test: containers, network, images (optionally data and config)
# Author  : Thierry Gayet <thierry.gayet@labworks.fr>
# Project : remote-shutdown (version: VERSION)
# Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
# =============================================================================
#
# Frees what docker/rsd-start.sh created, in three levels:
#   default     remove the containers (the simulated agents forget their certificates), the
#               network and the images rsd-master:local / rsd-agent:local
#   --volumes   also delete the master data volume: database, CA, audit log — asks first;
#               the next start creates a new CA and new tokens
#   --purge     everything above, plus docker/.local/ (exported CA, agents.env)
# Base images (ubuntu, golang, alpine) are never removed: other projects may use them.
#
# Usage:
#   docker/rsd-clean.sh [--volumes] [--purge] [--yes] [--help]
#     --volumes   delete the master data volume too (asks for confirmation)
#     --purge     delete the volume and docker/.local/ (asks for confirmation)
#     --yes       do not ask for confirmation (env ASSUME_YES=1)
#
# Prerequisites: Docker Engine with the Compose v2 plugin.
#
# Exit codes:
#   0  cleaned (or nothing to clean)
#   1  a docker command failed
#   2  usage error, or confirmation declined
#   4  prerequisite missing
#   7  Docker daemon unreachable

. "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/rsd-docker-common.sh"

VOLUMES=0
PURGE=0

usage() { sed -n '/^# Usage:/,/^# Prerequisites:/p' "${BASH_SOURCE[0]}" | sed -e 's/^# \{0,1\}//' -e '$d'; }

# parse_args ARGS...: command-line options.
parse_args() {
  while (($#)); do
    case "$1" in
      --volumes) VOLUMES=1 ;;
      --purge) VOLUMES=1; PURGE=1 ;;
      --yes) export ASSUME_YES=1 ;;
      -h | --help) usage; exit "$E_OK" ;;
      *) die "unknown option: $1 (see --help)" "$E_USAGE" ;;
    esac
    shift
  done
}

# main ARGS...: confirm, then remove each level.
main() {
  parse_args "$@"
  require_docker
  if ((VOLUMES)); then
    confirm "delete the master data (database, CA, audit log) of $PROJECT?" || die "cancelled" "$E_USAGE"
  fi
  log_step "Removing the containers of $PROJECT"
  local -a down=(down --remove-orphans --timeout 10)
  ((VOLUMES)) && down+=(--volumes)
  compose "${down[@]}"
  if docker network inspect "$NETWORK" >/dev/null 2>&1; then
    docker network rm "$NETWORK" >/dev/null
    log_ok "network $NETWORK removed"
  fi
  local image
  for image in "${IMAGES[@]}"; do
    if docker image inspect "$image" >/dev/null 2>&1; then
      docker image rm "$image" >/dev/null
      log_ok "image $image removed"
    fi
  done
  docker image prune -f --filter "label=com.docker.compose.project=$PROJECT" >/dev/null 2>&1 || true
  if ((PURGE)) && [[ -d "$LOCAL_DIR" ]]; then
    rm -rf -- "$LOCAL_DIR"
    log_ok "docker/.local/ removed"
  elif [[ -f "$LOCAL_DIR/agents.env" ]]; then
    # The agents are gone: their token must be issued again at the next start.
    rm -f -- "$LOCAL_DIR/agents.env"
  fi
  log_ok "cleaned"
}

main "$@"
