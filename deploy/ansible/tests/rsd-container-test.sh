#!/usr/bin/env bash
# =============================================================================
# Remote Shutdown - LAN parental control and machine management (master/agent)
# -----------------------------------------------------------------------------
# File    : deploy/ansible/tests/rsd-container-test.sh
# Purpose : End-to-end test of the playbook against a systemd container over SSH (idempotence)
# Author  : Thierry Gayet <thierry.gayet@labworks.fr>
# Project : remote-shutdown (version: VERSION)
# Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
# =============================================================================
#
# Builds tests/Dockerfile.target on the chosen base image, starts it (systemd as PID 1, sshd on
# 127.0.0.1:PORT), creates a throw-away SSH key and inventory, then runs "rsd-deploy.sh deploy"
# and, unless --once, a second time that must report changed=0 (idempotence). Kernel settings
# are skipped in a container (the playbook detects it); everything else runs for real:
# package, nftables, sshd hardening, fail2ban, backups, postflight checks.
#
# Usage:
#   tests/rsd-container-test.sh [--image IMAGE] [--once] [--keep] [--port N] [--work DIR]
#     --image IMAGE  base image (default ubuntu:26.04, the reference platform; also debian:13,
#                    ubuntu:24.04, debian:12, ubuntu:22.04, linuxmintd/mint22-amd64)
#     --once         skip the idempotence re-run
#     --keep         leave the container running at the end (inspect with: ssh -p PORT ...)
#     --port N       host port for SSH (default 2222)
#     --work DIR     working directory for the key, inventory and logs (default: mktemp)
#
# Prerequisites: docker (privileged containers), ssh, uv or ansible-core >= 2.16, dpkg-deb.
#
# Exit codes:
#   0  deployment and postflight passed (and the re-run changed nothing)
#   1  the deployment, the postflight or the idempotence check failed
#   2  usage error
#   4  prerequisite missing (docker, ssh)
#   7  the container did not start or SSH never answered
#   130 interrupted

TESTS_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../../scripts/lib/rsd-common.sh
. "$TESTS_DIR/../../../scripts/lib/rsd-common.sh"

readonly NAME=rsd-ansible-test
BASE_IMAGE=ubuntu:26.04
PORT=2222
WORK=""
ONCE=0
KEEP=0

usage() { sed -n '/^# Usage:/,/^# Prerequisites:/p' "${BASH_SOURCE[0]}" | sed -e 's/^# \{0,1\}//' -e '$d'; }

# parse_args ARGS...: command-line options.
parse_args() {
  while (($#)); do
    case "$1" in
      --image) BASE_IMAGE="${2:?--image needs a value}"; shift ;;
      --once) ONCE=1 ;;
      --keep) KEEP=1 ;;
      --port) PORT="${2:?--port needs a value}"; shift ;;
      --work) WORK="${2:?--work needs a directory}"; shift ;;
      -h | --help) usage; exit "$E_OK" ;;
      *) die "unknown option: $1 (see --help)" "$E_USAGE" ;;
    esac
    shift
  done
  [[ "$PORT" =~ ^[0-9]+$ ]] || die "--port must be a number" "$E_USAGE"
}

# prepare: working directory, SSH key and inventory.
prepare() {
  require_cmd docker ssh ssh-keygen
  if [[ -z "$WORK" ]]; then WORK="$(mktemp -d)"; fi
  mkdir -p "$WORK"
  WORK="$(readlink -f -- "$WORK")"
  [[ -f "$WORK/id_ed25519" ]] || ssh-keygen -q -t ed25519 -N '' -C rsd-ansible-test -f "$WORK/id_ed25519"
  cat >"$WORK/hosts.yml" <<INV
all:
  children:
    rsd_master:
      hosts:
        rsd-test:
          ansible_host: 127.0.0.1
          ansible_port: $PORT
          ansible_user: admin
          ansible_ssh_private_key_file: $WORK/id_ed25519
          ansible_ssh_common_args: "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes -o IdentityAgent=none"
          rsd_upgrade_packages: false
          rsd_admin_password: "Container-Test-Passphrase-2026"
          rsd_metrics_token: "container-test-metrics-token"
          rsd_create_token: true
          # Docker publishes the SSH port from the bridge gateway: allow every private range.
          rsd_admin_networks: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"]
INV
  log_ok "work directory: $WORK"
}

# start_container: build the image and boot it with systemd.
start_container() {
  local image="rsd-ansible-target:${BASE_IMAGE//[:\/]/-}"
  log_step "Building $image (base $BASE_IMAGE)"
  docker build -q --build-arg "BASE=$BASE_IMAGE" -t "$image" -f "$TESTS_DIR/Dockerfile.target" "$TESTS_DIR" >/dev/null
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  ((KEEP)) || on_exit "docker rm -f $NAME >/dev/null 2>&1"
  log_step "Starting $NAME (systemd, ssh on 127.0.0.1:$PORT)"
  docker run -d --name "$NAME" --hostname rsd-test --privileged --cgroupns=private \
    --tmpfs /run --tmpfs /run/lock -p "127.0.0.1:$PORT:22" "$image" >/dev/null
  docker exec -i "$NAME" bash -c "install -m 600 -o admin -g admin /dev/stdin /home/admin/.ssh/authorized_keys" <"$WORK/id_ed25519.pub"
  local i
  for i in $(seq 1 30); do
    ssh -q -p "$PORT" -i "$WORK/id_ed25519" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o IdentitiesOnly=yes -o IdentityAgent=none -o ConnectTimeout=2 admin@127.0.0.1 true 2>/dev/null &&
      { log_ok "SSH ready"; return 0; }
    sleep 1
  done
  die "SSH did not answer on 127.0.0.1:$PORT" "$E_STATE"
}

# deploy_once LOG: run the full deployment, keeping the output in LOG.
deploy_once() {
  local log="$1"
  "$TESTS_DIR/../rsd-deploy.sh" --no-color -i "$WORK/hosts.yml" deploy </dev/null 2>&1 | tee "$log"
  return "${PIPESTATUS[0]}"
}

# main ARGS...: prepare, boot, deploy, re-deploy, report.
main() {
  parse_args "$@"
  prepare
  start_container
  log_step "Deployment #1"
  deploy_once "$WORK/deploy-1.log" || die "deployment #1 failed (log: $WORK/deploy-1.log)" "$E_RUNTIME"
  if ((!ONCE)); then
    log_step "Deployment #2 (idempotence)"
    deploy_once "$WORK/deploy-2.log" || die "deployment #2 failed (log: $WORK/deploy-2.log)" "$E_RUNTIME"
    local changed
    changed="$(sed -n 's/.*changed=\([0-9]*\).*/\1/p' "$WORK/deploy-2.log" | tail -1)"
    # The enrollment token (rsd_create_token) is the only task that changes on every run.
    [[ "$changed" == 1 ]] || die "re-run reported changed=$changed, expected 1 (log: $WORK/deploy-2.log)" "$E_RUNTIME"
    log_ok "idempotent re-run (only the requested enrollment token changed)"
  fi
  log_ok "end-to-end test passed on $BASE_IMAGE (logs in $WORK)"
  ((KEEP)) && log_info "container kept: ssh -p $PORT -i $WORK/id_ed25519 admin@127.0.0.1"
  return 0
}

main "$@"
