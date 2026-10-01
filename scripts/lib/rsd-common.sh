#!/usr/bin/env bash
# =============================================================================
# Remote Shutdown - LAN parental control and machine management (master/agent)
# -----------------------------------------------------------------------------
# File    : scripts/lib/rsd-common.sh
# Purpose : Shared bash library: colors, logging, error handling, exit codes, checks
# Author  : Thierry Gayet <thierry.gayet@labworks.fr>
# Project : remote-shutdown (version: VERSION)
# Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
# =============================================================================
#
# Sourced (never executed) by every Remote Shutdown shell script:
#
#   SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
#   # shellcheck source=lib/rsd-common.sh
#   . "$SCRIPT_DIR/lib/rsd-common.sh"
#
# It provides:
#   * strict mode (set -Eeuo pipefail) and an ERR trap that reports the failing
#     command, file and line, then exits with E_RUNTIME (or the command status);
#   * colorized log helpers (log_info, log_ok, log_warn, log_error, log_step,
#     log_debug), disabled automatically when stderr is not a terminal, when
#     NO_COLOR is set (https://no-color.org) or with RSD_COLOR=never;
#   * die MESSAGE [CODE]: log an error and exit with a documented code;
#   * requirement checks: require_root, require_cmd, require_file;
#   * cleanup registration (on_exit) run by the EXIT trap in LIFO order;
#   * small utilities: confirm, rsd_version, is_true, msi_version, ensure_docker_network.
#
# Standard exit codes (shared by every script, documented in their headers):
#   0  E_OK        success
#   1  E_RUNTIME   unexpected runtime failure (a command failed)
#   2  E_USAGE     invalid arguments / usage error
#   3  E_PRIV      insufficient privileges (root required)
#   4  E_DEPS      missing prerequisite (command, package, file)
#   5  E_CONFIG    invalid configuration or input data
#   6  E_NETWORK   network / remote service failure
#   7  E_STATE     unexpected system state (check failed, resource busy)
#   8  E_WARN      completed with warnings (e.g. certificate close to expiry)
#   130            interrupted (SIGINT)
#
# Environment variables:
#   NO_COLOR / RSD_COLOR=always|never|auto   color control
#   RSD_DEBUG=1                              enable log_debug output and xtrace

# Guard against double sourcing.
[[ -n "${_RSD_COMMON_SH:-}" ]] && return 0
readonly _RSD_COMMON_SH=1

set -Eeuo pipefail
shopt -s inherit_errexit 2>/dev/null || true

# --- exit codes ---------------------------------------------------------------
# Used by the scripts that source this library.
# shellcheck disable=SC2034
readonly E_OK=0 E_RUNTIME=1 E_USAGE=2 E_PRIV=3 E_DEPS=4 E_CONFIG=5 E_NETWORK=6 E_STATE=7 E_WARN=8

# Name of the calling script, used as the log prefix.
SCRIPT_NAME="$(basename -- "${0}")"
# Root of the repository (scripts/lib/.. /..), valid when run from a checkout.
RSD_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

# --- colors -------------------------------------------------------------------
# setup_colors: define the color variables according to the terminal and the
# NO_COLOR / RSD_COLOR conventions. Called once at source time.
setup_colors() {
  local mode="${RSD_COLOR:-auto}"
  if [[ "$mode" == "never" || -n "${NO_COLOR:-}" ]] || { [[ "$mode" == "auto" ]] && [[ ! -t 2 ]]; }; then
    C_RESET="" C_BOLD="" C_DIM="" C_RED="" C_GREEN="" C_YELLOW="" C_BLUE="" C_CYAN=""
  else
    C_RESET=$'\e[0m' C_BOLD=$'\e[1m' C_DIM=$'\e[2m' C_RED=$'\e[31m' C_GREEN=$'\e[32m'
    C_YELLOW=$'\e[33m' C_BLUE=$'\e[34m' C_CYAN=$'\e[36m'
  fi
  export C_RESET C_BOLD C_DIM C_RED C_GREEN C_YELLOW C_BLUE C_CYAN
}
setup_colors

# --- logging (all on stderr, so stdout stays usable for data) ----------------
# _log LEVEL COLOR MESSAGE...: internal formatter "HH:MM:SS LEVEL script: message".
_log() {
  local level="$1" color="$2"
  shift 2
  printf '%s%s%s %s%-5s%s %s%s:%s %s\n' "$C_DIM" "$(date +%H:%M:%S)" "$C_RESET" \
    "$color$C_BOLD" "$level" "$C_RESET" "$C_DIM" "$SCRIPT_NAME" "$C_RESET" "$*" >&2
}
log_info()  { _log INFO "$C_BLUE" "$@"; }
log_ok()    { _log OK "$C_GREEN" "$@"; }
log_warn()  { _log WARN "$C_YELLOW" "$@"; }
log_error() { _log ERROR "$C_RED" "$@"; }
log_debug() { [[ "${RSD_DEBUG:-0}" == 1 ]] && _log DEBUG "$C_DIM" "$@"; return 0; }
# log_step MESSAGE: highlighted section title.
log_step()  { printf '\n%s==>%s %s%s%s\n' "$C_CYAN$C_BOLD" "$C_RESET" "$C_BOLD" "$*" "$C_RESET" >&2; }

# die MESSAGE [CODE]: log an error and exit (default code E_RUNTIME).
die() {
  local msg="$1" code="${2:-$E_RUNTIME}"
  log_error "$msg"
  exit "$code"
}

# --- traps --------------------------------------------------------------------
_RSD_CLEANUPS=()
# on_exit COMMAND: register a cleanup command run at exit (last registered first).
on_exit() { _RSD_CLEANUPS+=("$1"); }

# _rsd_exit_trap: run the registered cleanups. The ERR trap is removed first so that a
# deliberate non-zero exit (die, verdict codes) is not reported again as a failed command;
# the script keeps the status given to "exit".
_rsd_exit_trap() {
  local i
  trap - ERR
  set +e
  for ((i = ${#_RSD_CLEANUPS[@]} - 1; i >= 0; i--)); do
    eval "${_RSD_CLEANUPS[i]}"
  done
  return 0
}

# _rsd_err_trap: report the failing command with its location, then exit with its status.
_rsd_err_trap() {
  local status=$? cmd="${BASH_COMMAND}" line="${BASH_LINENO[0]}" src="${BASH_SOURCE[1]:-$SCRIPT_NAME}"
  log_error "command failed (status ${status}) at $(basename -- "$src"):${line}: ${cmd}"
  exit "$status"
}

trap _rsd_exit_trap EXIT
trap _rsd_err_trap ERR
trap 'log_warn "interrupted"; exit 130' INT TERM
[[ "${RSD_DEBUG:-0}" == 1 ]] && set -x

# --- requirement checks ------------------------------------------------------
# require_root: exit with E_PRIV unless running as uid 0.
require_root() { [[ "${EUID}" -eq 0 ]] || die "this command must be run as root (use sudo)" "$E_PRIV"; }

# require_cmd CMD...: exit with E_DEPS if one of the commands is not in PATH.
require_cmd() {
  local c missing=()
  for c in "$@"; do command -v "$c" >/dev/null 2>&1 || missing+=("$c"); done
  ((${#missing[@]} == 0)) || die "missing required command(s): ${missing[*]}" "$E_DEPS"
}

# require_file PATH...: exit with E_DEPS if a file does not exist or is unreadable.
require_file() {
  local f
  for f in "$@"; do [[ -r "$f" ]] || die "required file not found or unreadable: $f" "$E_DEPS"; done
}

# --- utilities ---------------------------------------------------------------
# is_true VALUE: success for 1/yes/true/on (case-insensitive).
is_true() { [[ "${1,,}" =~ ^(1|y|yes|true|on)$ ]]; }

# confirm PROMPT: ask a yes/no question on the terminal; ASSUME_YES=1 answers yes.
confirm() {
  is_true "${ASSUME_YES:-0}" && return 0
  local answer
  read -r -p "${C_YELLOW}?${C_RESET} $1 [y/N] " answer
  is_true "$answer"
}

# rsd_version: print the software version (single source VERSION at the repository root).
rsd_version() {
  local f="$RSD_REPO_ROOT/VERSION"
  if [[ -r "$f" ]]; then
    tr -d '[:space:]' <"$f"
    echo
  else
    echo "unknown"
  fi
}

# msi_version VERSION: MSI ProductVersion form (numeric major.minor.patch, pre-release dropped).
msi_version() {
  local v="${1%%[-+]*}"
  [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "invalid version for MSI: $1" "$E_CONFIG"
  printf '%s\n' "$v"
}

# free_subnet: first candidate /24 overlapping neither a local route nor a Docker network.
free_subnet() {
  local used cand
  local -a nets
  mapfile -t nets < <(docker network ls -q)
  used="$( { ip -4 route 2>/dev/null | awk '$1 ~ /\// { print $1 }'
             docker network inspect "${nets[@]}" --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null | tr ' ' '\n'
           } | grep -E '^[0-9.]+/[0-9]+$' || true)"
  for cand in 10.250.250.0/24 10.251.251.0/24 10.252.252.0/24 172.31.250.0/24 192.168.250.0/24 10.99.99.0/24; do
    grep -q "^${cand%.0/24}\." <<<"$used" || { echo "$cand"; return 0; }
  done
}

# ensure_docker_network NAME [LABEL]: create a bridge network once. Uses RSD_DOCKER_SUBNET when
# set, else the Docker default pools, else a free /24 (pools exhausted on managed hosts).
ensure_docker_network() {
  local name="$1" label="${2:-}" subnet
  docker network inspect "$name" >/dev/null 2>&1 && return 0
  local -a create=(docker network create)
  [[ -n "$label" ]] && create+=(--label "$label")
  if [[ -n "${RSD_DOCKER_SUBNET:-}" ]]; then
    "${create[@]}" --subnet "$RSD_DOCKER_SUBNET" "$name" >/dev/null
    log_ok "network $name created ($RSD_DOCKER_SUBNET)"
    return 0
  fi
  if "${create[@]}" "$name" >/dev/null 2>&1; then
    log_ok "network $name created (Docker default pools)"
    return 0
  fi
  subnet="$(free_subnet)"
  [[ -n "$subnet" ]] || die "no free subnet for the Docker network: set RSD_DOCKER_SUBNET=a.b.c.0/24" "$E_STATE"
  "${create[@]}" --subnet "$subnet" "$name" >/dev/null
  log_ok "network $name created on $subnet (the Docker address pools are exhausted)"
}
