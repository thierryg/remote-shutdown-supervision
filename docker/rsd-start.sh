#!/usr/bin/env bash
# =============================================================================
# Remote Shutdown - LAN parental control and machine management (master/agent)
# -----------------------------------------------------------------------------
# File    : docker/rsd-start.sh
# Purpose : Build the images and start Remote Shutdown locally (master + 2 simulated agents)
# Author  : Thierry Gayet <thierry.gayet@labworks.fr>
# Project : remote-shutdown (version: VERSION)
# Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
# =============================================================================
#
# Tries Remote Shutdown on a workstation with nothing installed but Docker:
#   1. builds rsd-master:local (Ubuntu 26.04 LTS + distribution Python packages, like the .deb)
#      and rsd-agent:local (static Go agent, dry-run power off);
#   2. starts the master and waits until its console answers;
#   3. exports its CA to docker/.local/rsd-local-ca.crt (to trust in the browser);
#   4. on the first start, creates an enrollment token for the two simulated agents
#      (docker/.local/agents.env), which discover the master by UDP broadcast and enroll;
#   5. waits until both agents are UP and prints the URL and the first login (admin / admin).
# Only 127.0.0.1 is published: the local test is not reachable from the network.
#
# Usage:
#   docker/rsd-start.sh [--no-build] [--rebuild] [--no-agents] [--https-port N] [--agent-port N] [--help]
#     --no-build       use the existing images
#     --rebuild        rebuild without the Docker cache
#     --no-agents      start the master only
#     --https-port N   published console port (default 8443, env RSD_HTTPS_PORT)
#     --agent-port N   published agent port (default 8444, env RSD_AGENT_PORT)
#
# Environment: RSD_DOCKER_SUBNET=10.250.250.0/24 forces the subnet of the project network (by
# default Docker picks one; when its address pools are exhausted, a free /24 is chosen).
#
# Prerequisites: Docker Engine with the Compose v2 plugin, curl, about 1 GB of disk; Internet
# access for the first build. buildx is optional (the classic builder is used without it).
#
# Exit codes:
#   0  Remote Shutdown is up (URL printed)
#   1  a command failed (build, compose)
#   2  usage error
#   4  prerequisite missing (docker, compose, curl)
#   6  a published port (--https-port, --agent-port) is already taken on 127.0.0.1
#   7  Docker daemon unreachable, or the console / the agents did not come up in time
#   8  started, but the agents are not UP yet (see docker/rsd-status.sh --logs 50)
#   130 interrupted

. "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/rsd-docker-common.sh"

BUILD=1
NO_CACHE=0
AGENTS=1

usage() { sed -n '/^# Usage:/,/^# Prerequisites:/p' "${BASH_SOURCE[0]}" | sed -e 's/^# \{0,1\}//' -e '$d'; }

# parse_args ARGS...: command-line options.
parse_args() {
  while (($#)); do
    case "$1" in
      --no-build) BUILD=0 ;;
      --rebuild) NO_CACHE=1 ;;
      --no-agents) AGENTS=0 ;;
      --https-port) RSD_HTTPS_PORT="${2:?--https-port needs a number}"; shift ;;
      --agent-port) RSD_AGENT_PORT="${2:?--agent-port needs a number}"; shift ;;
      -h | --help) usage; exit "$E_OK" ;;
      *) die "unknown option: $1 (see --help)" "$E_USAGE" ;;
    esac
    shift
  done
  [[ "$RSD_HTTPS_PORT" =~ ^[0-9]+$ && "$RSD_AGENT_PORT" =~ ^[0-9]+$ ]] || die "ports must be numbers" "$E_USAGE"
}

# ensure_network: create the project network once (see RSD_DOCKER_SUBNET in the header).
ensure_network() { ensure_docker_network "$NETWORK" "com.docker.compose.project=$PROJECT"; }

# port_in_use PORT: success when something already listens on TCP PORT of this host.
port_in_use() {
  if command -v ss >/dev/null 2>&1; then
    [[ -n "$(ss -Hltn "sport = :$1" 2>/dev/null)" ]]
  else
    (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
  fi
}

# port_owner PORT: who holds PORT (container publishing it, else the listening process; best effort).
port_owner() {
  local who
  who="$(docker ps --filter "publish=$1" --format 'container {{.Names}}' 2>/dev/null | head -1)"
  [[ -z "$who" ]] && command -v ss >/dev/null 2>&1 &&
    who="$(ss -Hltnp "sport = :$1" 2>/dev/null | grep -o 'users:(("[^"]*",pid=[0-9]*' | head -1 |
      sed 's/users:(("\([^"]*\)",pid=\([0-9]*\)/process \1 (pid \2)/')"
  echo "${who:-an unknown process (sudo ss -ltnp | grep :$1)}"
}

# check_ports: fail before compose when a published port is taken by something else than our
# running master (Docker would only say "port is already allocated").
check_ports() {
  [[ -n "$(compose ps -q --status running master 2>/dev/null)" ]] && return 0
  local port opt busy=0
  for port in "$RSD_HTTPS_PORT" "$RSD_AGENT_PORT"; do
    port_in_use "$port" || continue
    [[ "$port" == "$RSD_HTTPS_PORT" ]] && opt=--https-port || opt=--agent-port
    log_error "port $port already in use by $(port_owner "$port"): stop it or pick another one ($opt N)"
    busy=1
  done
  ((busy == 0)) || die "published port(s) unavailable on 127.0.0.1" "$E_NETWORK"
}

# build_images: build the master and agent images (cached layers make later builds fast).
build_images() {
  ((BUILD)) || { log_info "build skipped (--no-build)"; return 0; }
  log_step "Building ${IMAGES[*]}"
  if [[ -z "${COMPOSE_BAKE:-}" ]] && ! docker buildx version >/dev/null 2>&1; then
    export COMPOSE_BAKE=false
    log_info "buildx not installed: classic builder (optional: $(docker_pkg_hint buildx))"
  fi
  local -a args=(build)
  ((NO_CACHE)) && args+=(--no-cache)
  compose "${args[@]}"
}

# wait_master: wait until the master container reports healthy.
wait_master() {
  local i health id
  log_step "Waiting for the master"
  for i in $(seq 1 45); do
    id="$(compose ps -q master 2>/dev/null)"
    health="$(docker inspect --format '{{.State.Health.Status}}' "$id" 2>/dev/null || echo starting)"
    [[ "$health" == healthy ]] && { log_ok "master healthy"; return 0; }
    sleep 2
  done
  compose logs --tail 30 master
  die "the master did not become healthy within 90 s" "$E_STATE"
}

# json_field NAME: value of a top-level field of the JSON on stdin (strings and numbers).
json_field() { sed -n "s/^ *\"$1\": \"\{0,1\}\([^\",]*\)\"\{0,1\},\{0,1\}$/\1/p" | head -1; }

# export_ca: copy the master CA to docker/.local/rsd-local-ca.crt.
export_ca() {
  compose exec -T master cat /var/lib/rsd-master/pki/ca.crt >"$LOCAL_DIR/rsd-local-ca.crt"
  log_ok "CA exported: docker/.local/rsd-local-ca.crt"
}

# prepare_agents: create the enrollment token on the first start (or after a data reset).
prepare_agents() {
  local total token fp
  total="$(master_cli status --json | json_field agents_total)"
  if [[ -f "$LOCAL_DIR/agents.env" && "${total:-0}" -gt 0 ]]; then
    log_ok "agents already enrolled ($total)"
    return 0
  fi
  token="$(master_cli create-token --label docker-local --uses "${#AGENT_SERVICES[@]}" --ttl 10080)"
  fp="$(master_cli info | json_field ca_fingerprint)"
  [[ ${#fp} -eq 64 && -n "$token" ]] || die "cannot read the token or the CA fingerprint from the master" "$E_STATE"
  (umask 077 && cat >"$LOCAL_DIR/agents.env" <<ENV
# Generated by docker/rsd-start.sh: unattended enrollment of the simulated agents.
# No RSD_MASTER: the agents find the master by UDP broadcast on the project network.
RSD_ENROLL_TOKEN=$token
RSD_CA_FINGERPRINT=$fp
ENV
  )
  log_ok "enrollment token created for ${#AGENT_SERVICES[@]} agents (docker/.local/agents.env)"
}

# wait_agents: wait until every simulated agent is UP (returns 1 on timeout).
wait_agents() {
  local i up
  log_step "Waiting for the agents (discovery, enrollment, connection)"
  for i in $(seq 1 40); do
    up="$(master_cli status --json | json_field agents_up)"
    [[ "${up:-0}" -ge "${#AGENT_SERVICES[@]}" ]] && { log_ok "$up agents UP"; return 0; }
    sleep 3
  done
  log_warn "only ${up:-0}/${#AGENT_SERVICES[@]} agents UP after 120 s"
  return 1
}

# summary: what to do next.
summary() {
  cat <<MSG

${C_GREEN}${C_BOLD}Remote Shutdown is running locally${C_RESET} (version $(rsd_version), project $PROJECT)
  Web console   : $(https_url)
  First login   : admin / admin (a new password is required at once)
  Trust the CA  : docker/.local/rsd-local-ca.crt (or accept the browser warning)
  Agents        : ${AGENT_SERVICES[*]} (simulated: orders are logged, see docker/rsd-status.sh --logs 20)
  Own agent     : rsd-agent enroll --master 127.0.0.1:${RSD_HTTPS_PORT} ... (token from the Enrollment tab)
  Next          : docker/rsd-status.sh   docker/rsd-stop.sh   docker/rsd-clean.sh
MSG
}

# main ARGS...: build, network, master, CA, agents, summary.
main() {
  parse_args "$@"
  require_docker
  require_cmd curl sed
  log_info "remote-shutdown $(rsd_version) · local Docker test"
  check_ports
  install -d -m 700 "$LOCAL_DIR"
  build_images
  ensure_network
  log_step "Starting the master"
  compose up -d master
  wait_master
  export_ca
  local verdict=$E_OK
  if ((AGENTS)); then
    prepare_agents
    log_step "Starting the simulated agents"
    compose up -d "${AGENT_SERVICES[@]}"
    wait_agents || verdict=$E_WARN
  fi
  summary
  exit "$verdict"
}

main "$@"
