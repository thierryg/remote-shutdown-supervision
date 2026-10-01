#!/usr/bin/env bash
# =============================================================================
# Remote Shutdown - LAN parental control and machine management (master/agent)
# -----------------------------------------------------------------------------
# File    : docker/rsd-status.sh
# Purpose : State of the local Docker test: containers, health, resources, console, agents
# Author  : Thierry Gayet <thierry.gayet@labworks.fr>
# Project : remote-shutdown (version: VERSION)
# Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
# =============================================================================
#
# Prints one line per container (state, health), the resources, the console check (HTTPS,
# certificate verified against the exported CA) and the master's own summary (agents UP,
# tokens, audit chain). --json gives the same verdict for scripts.
#
# Usage:
#   docker/rsd-status.sh [--logs N] [--json] [--help]
#     --logs N   also print the last N log lines of every container
#     --json     machine-readable output
#
# Prerequisites: Docker Engine with the Compose v2 plugin, curl.
#
# Exit codes:
#   0  every container runs, the console answers and every agent is UP
#   2  usage error
#   4  prerequisite missing
#   7  not started, a container is stopped/unhealthy, or the console does not answer
#   8  running with warnings (an agent is not UP, audit chain broken)

. "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/rsd-docker-common.sh"

LOGS=0
JSON=0

usage() { sed -n '/^# Usage:/,/^# Prerequisites:/p' "${BASH_SOURCE[0]}" | sed -e 's/^# \{0,1\}//' -e '$d'; }

# parse_args ARGS...: command-line options.
parse_args() {
  while (($#)); do
    case "$1" in
      --logs) LOGS="${2:?--logs needs a number}"; shift ;;
      --json) JSON=1 ;;
      -h | --help) usage; exit "$E_OK" ;;
      *) die "unknown option: $1 (see --help)" "$E_USAGE" ;;
    esac
    shift
  done
  [[ "$LOGS" =~ ^[0-9]+$ ]] || die "--logs needs a number" "$E_USAGE"
}

# row LABEL VALUE: aligned "label value" line.
row() { printf '  %s%-16s%s %s\n' "$C_DIM" "$1" "$C_RESET" "$2"; }

# state_color TEXT: green for running/healthy/200/OK, red for failures, yellow otherwise.
state_color() {
  case "$1" in
    running | healthy | 200 | OK) printf '%s%s%s' "$C_GREEN" "$1" "$C_RESET" ;;
    exited | dead | unhealthy | down | BROKEN | 000) printf '%s%s%s' "$C_RED" "$1" "$C_RESET" ;;
    *) printf '%s%s%s' "$C_YELLOW" "$1" "$C_RESET" ;;
  esac
}

# main ARGS...: collect every check, print it, compute the verdict.
main() {
  parse_args "$@"
  require_docker
  require_cmd curl
  if ! project_running; then
    ((JSON)) && { echo '{"running": false}'; exit "$E_STATE"; }
    log_warn "the local test is not started: docker/rsd-start.sh"
    exit "$E_STATE"
  fi
  local verdict=$E_OK svc state health line
  local -A STATE=() HEALTH=()
  for svc in "${SERVICES[@]}"; do
    line="$(docker inspect --format '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}-{{end}}' \
      "$(compose ps -a -q "$svc" 2>/dev/null | head -1)" 2>/dev/null || echo "down|-")"
    IFS='|' read -r state health <<<"$line"
    STATE[$svc]="${state:-down}"
    HEALTH[$svc]="${health:--}"
    if [[ "${STATE[$svc]}" != running && "$svc" == master ]]; then verdict=$E_STATE
    elif [[ "${STATE[$svc]}" != running ]]; then ((verdict == E_OK)) && verdict=$E_WARN
    elif [[ "${HEALTH[$svc]}" == unhealthy ]]; then verdict=$E_STATE
    fi
  done

  local ca="$LOCAL_DIR/rsd-local-ca.crt" console summary="" up="?" total="?" chain="?"
  console="$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 --cacert "$ca" "$(https_url)" 2>/dev/null || true)"
  [[ "$console" == 200 ]] || verdict=$E_STATE
  if [[ "${STATE[master]}" == running ]]; then
    summary="$(master_cli status --json 2>/dev/null || true)"
    up="$(sed -n 's/^ *"agents_up": \([0-9]*\).*/\1/p' <<<"$summary")"
    total="$(sed -n 's/^ *"agents_total": \([0-9]*\).*/\1/p' <<<"$summary")"
    chain="$(grep -q '"audit_chain_ok": true' <<<"$summary" && echo OK || echo BROKEN)"
    if [[ "${up:-0}" -lt "${total:-0}" || "$chain" != OK ]]; then ((verdict == E_OK)) && verdict=$E_WARN; fi
  fi

  if ((JSON)); then
    printf '{"running": true, "services": {'
    local first=1
    for svc in "${SERVICES[@]}"; do
      ((first)) || printf ', '
      first=0
      printf '"%s": {"state": "%s", "health": "%s"}' "$svc" "${STATE[$svc]}" "${HEALTH[$svc]}"
    done
    printf '}, "console_http": "%s", "agents_up": %s, "agents_total": %s, "audit_chain": "%s", "url": "%s", "exit_code": %d}\n' \
      "$console" "${up:-0}" "${total:-0}" "$chain" "$(https_url)" "$verdict"
    exit "$verdict"
  fi

  printf '\n%sRemote Shutdown local test%s  %s· version %s · project %s%s\n' "$C_BOLD" "$C_RESET" "$C_DIM" "$(rsd_version)" "$PROJECT" "$C_RESET"
  printf '\n%sContainers%s\n' "$C_CYAN$C_BOLD" "$C_RESET"
  for svc in "${SERVICES[@]}"; do
    row "$svc" "$(state_color "${STATE[$svc]}")  health $(state_color "${HEALTH[$svc]}")"
  done
  printf '\n%sResources%s\n' "$C_CYAN$C_BOLD" "$C_RESET"
  # shellcheck disable=SC2046  # one ID per word
  docker stats --no-stream --format '  {{.Name}}\t CPU {{.CPUPerc}}\t MEM {{.MemUsage}}\t NET {{.NetIO}}' \
    $(compose ps -q) 2>/dev/null | column -t -s $'\t' || true
  printf '\n%sChecks%s\n' "$C_CYAN$C_BOLD" "$C_RESET"
  row "console" "$(https_url) → HTTP $(state_color "${console:-000}")"
  row "agents" "${up:-?} UP / ${total:-?} enrolled"
  row "audit chain" "$(state_color "$chain")"
  if ((LOGS > 0)); then
    printf '\n%sLast %d log lines%s\n' "$C_CYAN$C_BOLD" "$LOGS" "$C_RESET"
    compose logs --no-color --tail "$LOGS" 2>/dev/null | sed 's/^/  /'
  fi
  echo
  case "$verdict" in
    "$E_OK") log_ok "all up" ;;
    "$E_WARN") log_warn "running with warnings (docker/rsd-status.sh --logs 50)" ;;
    *) log_error "not fully up: docker/rsd-status.sh --logs 50" ;;
  esac
  exit "$verdict"
}

main "$@"
