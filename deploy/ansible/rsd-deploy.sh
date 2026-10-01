#!/usr/bin/env bash
# =============================================================================
# Remote Shutdown - LAN parental control and machine management (master/agent)
# -----------------------------------------------------------------------------
# File    : deploy/ansible/rsd-deploy.sh
# Purpose : Wrapper around the master Ansible playbook: deps, lint, preflight, deploy, postflight
# Author  : Thierry Gayet <thierry.gayet@labworks.fr>
# Project : remote-shutdown (version: VERSION)
# Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
# =============================================================================
#
# Runs the playbook site.yml against the master host (Debian 12+, Ubuntu 22.04+, Linux Mint 21+).
# ansible-core >= 2.16 is taken from the PATH, or run through uvx when missing or
# too old (nothing to install besides uv). Collections go to ./collections.
#
# Usage:
#   ./rsd-deploy.sh [options] <command>
#
# Commands:
#   deps        install the Ansible collections (requirements.yml)
#   ping        check the SSH connection and sudo on the targets
#   preflight   run the preflight checks only (changes nothing)
#   check       dry run of the whole deployment (--check --diff)
#   deploy      full deployment: preflight, installation, hardening, postflight
#   postflight  run the postflight checks only
#   lint        syntax check + ansible-lint + yamllint (no target needed)
#
# Options:
#   -i, --inventory FILE   inventory (default: inventory/hosts.yml)
#   -l, --limit HOSTS      restrict to some hosts
#   -t, --tags TAGS        run only these tags (comma-separated)
#   -e, --extra VAR=VAL    extra variable (repeatable)
#   -K, --ask-become-pass  ask for the sudo password
#   -J, --ask-vault-pass   ask for the ansible-vault password (group_vars/all/vault.yml: rsd_admin_password)
#   -v, --verbose          more output (repeatable: -vv, -vvv)
#   --no-color             disable colors
#   -h, --help             this help
#
# Examples:
#   cp inventory/hosts.example.yml inventory/hosts.yml && $EDITOR inventory/hosts.yml
#   ./rsd-deploy.sh ping
#   ./rsd-deploy.sh deploy -K
#   ./rsd-deploy.sh deploy -t master,firewall -e rsd_web_port=9443
#
# Prerequisites: bash >= 4.4; ansible-core >= 2.16 or uv (uvx); dpkg-deb to build the package
# when dist/ has none; an SSH key accepted by the administrator account of the target.
#
# Exit codes:
#   0  success
#   1  the playbook or a tool failed (see its output)
#   2  usage error
#   4  prerequisite missing (uv/ansible, inventory)
#   130 interrupted

ANSIBLE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../scripts/lib/rsd-common.sh
. "$ANSIBLE_DIR/../../scripts/lib/rsd-common.sh"

readonly ANSIBLE_CORE_SPEC="ansible-core>=2.16,<2.20"
INVENTORY="$ANSIBLE_DIR/inventory/hosts.yml"
COMMAND=""
PLAY_ARGS=()

usage() { sed -n '/^# Usage:/,/^# Prerequisites:/p' "${BASH_SOURCE[0]}" | sed -e 's/^# \{0,1\}//' -e '$d'; }

# parse_args ARGS...: options and the command.
parse_args() {
  while (($#)); do
    case "$1" in
      -i | --inventory) INVENTORY="$(readlink -f -- "${2:?--inventory needs a file}")"; shift ;;
      -l | --limit) PLAY_ARGS+=(--limit "${2:?--limit needs hosts}"); shift ;;
      -t | --tags) PLAY_ARGS+=(--tags "${2:?--tags needs tags}"); shift ;;
      -e | --extra) PLAY_ARGS+=(--extra-vars "${2:?--extra needs VAR=VAL}"); shift ;;
      -K | --ask-become-pass) PLAY_ARGS+=(--ask-become-pass) ;;
      -J | --ask-vault-pass) PLAY_ARGS+=(--ask-vault-pass) ;;
      -v | -vv | -vvv | --verbose) PLAY_ARGS+=("${1/--verbose/-v}") ;;
      --no-color) export RSD_COLOR=never ANSIBLE_NOCOLOR=1; setup_colors ;;
      -h | --help) usage; exit "$E_OK" ;;
      -*) die "unknown option: $1 (see --help)" "$E_USAGE" ;;
      *) [[ -z "$COMMAND" ]] || die "only one command allowed (got '$COMMAND' and '$1')" "$E_USAGE"; COMMAND="$1" ;;
    esac
    shift
  done
  [[ -n "$COMMAND" ]] || { usage; exit "$E_USAGE"; }
}

# ansible_cmd TOOL: print the command line running TOOL (native ansible or uvx fallback).
ansible_cmd() {
  local tool="$1" version
  if command -v "$tool" >/dev/null; then
    version="$(ansible --version </dev/null 2>/dev/null | sed -n 's/.*core \([0-9.]*\).*/\1/p' | head -1)"
    if [[ -n "$version" ]] && printf '2.16\n%s\n' "$version" | sort -V -C; then
      echo "$tool"
      return 0
    fi
  fi
  command -v uvx >/dev/null || die "ansible-core >= 2.16 not found and uv is missing (https://docs.astral.sh/uv/)" "$E_DEPS"
  echo "uvx --from $ANSIBLE_CORE_SPEC $tool"
}

# run TOOL ARGS...: run an Ansible tool from the playbook directory (stdin detached: Ansible
# refuses non-blocking standard streams).
run() {
  local -a cmd
  read -r -a cmd <<<"$(ansible_cmd "$1")"
  shift
  log_debug "${cmd[*]} $*"
  (cd "$ANSIBLE_DIR" && "${cmd[@]}" "$@")
}

# require_inventory: the inventory must exist (copied from the example).
require_inventory() {
  [[ -r "$INVENTORY" ]] ||
    die "inventory not found: $INVENTORY (cp inventory/hosts.example.yml inventory/hosts.yml)" "$E_DEPS"
  PLAY_ARGS=(--inventory "$INVENTORY" "${PLAY_ARGS[@]}")
}

# cmd_deps: install the collections when missing.
cmd_deps() {
  log_step "Ansible collections"
  run ansible-galaxy collection install -r requirements.yml -p collections </dev/null
  log_ok "collections installed in $ANSIBLE_DIR/collections"
}

# ensure_deps: install the collections on first use.
ensure_deps() { [[ -d "$ANSIBLE_DIR/collections/ansible_collections/ansible/posix" ]] || cmd_deps; }

# playbook ARGS...: run site.yml with the common arguments.
playbook() {
  require_inventory
  ensure_deps
  run ansible-playbook site.yml "${PLAY_ARGS[@]}" "$@"
}

# cmd_lint: static checks that need no target.
cmd_lint() {
  ensure_deps
  log_step "Syntax check"
  run ansible-playbook --syntax-check -i inventory/hosts.example.yml site.yml </dev/null
  log_step "ansible-lint (production profile)"
  (cd "$ANSIBLE_DIR" && uvx --from "ansible-lint>=25" --with "$ANSIBLE_CORE_SPEC" ansible-lint --profile production site.yml </dev/null)
  log_step "yamllint"
  (cd "$ANSIBLE_DIR" && uvx yamllint -c .yamllint . </dev/null)
  log_ok "lint clean"
}

# main ARGS...: dispatch the command.
main() {
  parse_args "$@"
  log_info "remote-shutdown $(rsd_version) · command: $COMMAND"
  case "$COMMAND" in
    deps) cmd_deps ;;
    ping) require_inventory; ensure_deps; run ansible rsd_master -m ansible.builtin.ping "${PLAY_ARGS[@]}" </dev/null ;;
    preflight) playbook --tags preflight ;;
    check) playbook --check --diff ;;
    deploy) playbook ;;
    postflight) playbook --tags postflight ;;
    lint) cmd_lint ;;
    *) die "unknown command: $COMMAND (see --help)" "$E_USAGE" ;;
  esac
  log_ok "$COMMAND finished"
}

main "$@"
