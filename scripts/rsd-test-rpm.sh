#!/usr/bin/env bash
# =============================================================================
# Remote Shutdown - LAN parental control and machine management (master/agent)
# -----------------------------------------------------------------------------
# File    : scripts/rsd-test-rpm.sh
# Purpose : Integration test of the RPM packages in Docker (Fedora, Rocky Linux / RHEL, openSUSE)
# Author  : Thierry Gayet <thierry.gayet@labworks.fr>
# Project : remote-shutdown (version: VERSION)
# Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
# =============================================================================
#
# 1. A master container (MASTER_IMAGE, default fedora:latest) installs rsd-master.noarch.rpm
#    with dnf (its python3dist() requirements come from the distribution), starts the master as
#    its service account and creates a multi-use enrollment token.
# 2. For every target image, on the same Docker network: install rsd-agent.<arch>.rpm (dnf or
#    zypper), enroll it against the master, run it, check that the master sees it UP, then
#    remove the package and check that its state is gone. Whether rsd-master.rpm itself
#    resolves on that distribution is reported too (informative: RHEL/Rocky ship no FastAPI).
# systemd is not running in the containers: the scriptlets must cope with that.
#
# Usage:
#   scripts/rsd-test-rpm.sh [--image IMAGE]... [--master-image IMAGE] [--no-color]
#   scripts/rsd-test-rpm.sh --help
#
# Default images: fedora:latest rockylinux/rockylinux:10 opensuse/leap:latest
#
# Environment variables:
#   DOCKER        docker command (default: docker)
#   NO_COLOR      disable colors (also RSD_COLOR=never)
#
# Prerequisites: bash >= 4.4, docker, the packages in dist/ (make linux-rpm).
#
# Exit codes:
#   0  every image passed
#   1  at least one image failed
#   2  usage error
#   4  missing prerequisite (docker, packages)
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/rsd-common.sh
. "$SCRIPT_DIR/lib/rsd-common.sh"

DOCKER="${DOCKER:-docker}"
IMAGES=()
DEFAULT_IMAGES=(fedora:latest rockylinux/rockylinux:10 opensuse/leap:latest)
MASTER_IMAGE=fedora:latest
readonly NETWORK=rsd-rpm-test MASTER=rsd-rpm-master

# usage: print the help text (the header comment block).
usage() {
  sed -n '12,/^SCRIPT_DIR=/p' "${BASH_SOURCE[0]}" | sed -e '$d' -e 's/^# \{0,1\}//'
}

# parse_args ARGS...: read the options.
parse_args() {
  while (($#)); do
    case "$1" in
      --image) [[ $# -ge 2 ]] || die "--image needs a value" "$E_USAGE"; IMAGES+=("$2"); shift 2 ;;
      --master-image) [[ $# -ge 2 ]] || die "--master-image needs a value" "$E_USAGE"; MASTER_IMAGE="$2"; shift 2 ;;
      --no-color) RSD_COLOR=never setup_colors; shift ;;
      -h | --help) usage; exit "$E_OK" ;;
      *) die "unknown option: $1 (see --help)" "$E_USAGE" ;;
    esac
  done
  ((${#IMAGES[@]})) || IMAGES=("${DEFAULT_IMAGES[@]}")
}

# Package manager helpers shared by the scenarios (POSIX sh).
# shellcheck disable=SC2016
PM='
pm_install() {
  if command -v dnf >/dev/null; then dnf install -y -q --setopt=install_weak_deps=False "$@" >/dev/null
  else zypper --non-interactive --quiet --no-gpg-checks install --no-recommends "$@" >/dev/null; fi
}
'

# shellcheck disable=SC2016
MASTER_SCENARIO='
set -eu
'"$PM"'
pm_install /dist/rsd-master-*.noarch.rpm curl util-linux
runuser -u rsd-master -- rsd-master serve >/tmp/master.log 2>&1 &
for i in $(seq 1 30); do curl -skf https://127.0.0.1:8443/robots.txt >/dev/null && break; sleep 1; done
rsd-master create-token --label rpm-test --uses 20 >/tmp/token
rsd-master info | sed -n "s/.*\"ca_fingerprint\": \"\([0-9a-f]*\)\".*/\1/p" >/tmp/fp
echo "master: $(rsd-master version) on $(. /etc/os-release; echo "$PRETTY_NAME")"
sleep infinity
'

# shellcheck disable=SC2016
AGENT_SCENARIO='
set -eu
'"$PM"'
. /etc/os-release
arch=$(uname -m)
pm_install /dist/rsd-agent-*."$arch".rpm
echo "installed: $(rpm -q rsd-agent) on $PRETTY_NAME"
test "$(stat -c %a /etc/rsd-agent/agent.json)" = 600
rsd-agent enroll --token "$TOKEN" --fingerprint "$FP" --master '"$MASTER"'
rsd-agent run >/tmp/agent.log 2>&1 &
for i in $(seq 1 30); do grep -q "connected to master" /tmp/agent.log && break; sleep 1; done
grep -q "connected to master" /tmp/agent.log && echo "connected: yes" || { echo "connected: NO"; cat /tmp/agent.log; }
sleep 6
rpm -e rsd-agent
test ! -e /etc/rsd-agent/agent.json.rpmsave
test ! -e /var/lib/rsd-agent && test ! -e /usr/bin/rsd-agent
echo "removal: clean"
if (command -v dnf >/dev/null && dnf install -y -q --assumeno /dist/rsd-master-*.noarch.rpm >/dev/null 2>&1) ||
   (command -v dnf >/dev/null && dnf install --assumeno /dist/rsd-master-*.noarch.rpm 2>&1 | grep -q "Operation aborted") ||
   (command -v zypper >/dev/null && zypper --non-interactive --no-gpg-checks install --dry-run /dist/rsd-master-*.noarch.rpm >/dev/null 2>&1); then
  echo "master rpm: installable here"
else
  echo "master rpm: NOT installable here (python3dist requirements missing: use a Fedora/openSUSE/Debian/Ubuntu master)"
fi
'

# start_master: run the master container and read the token and the CA fingerprint.
start_master() {
  ensure_docker_network "$NETWORK"
  "$DOCKER" rm -f "$MASTER" >/dev/null 2>&1 || true
  on_exit "$DOCKER rm -f $MASTER >/dev/null 2>&1; $DOCKER network rm $NETWORK >/dev/null 2>&1"
  log_step "master on $MASTER_IMAGE"
  "$DOCKER" run -d --name "$MASTER" --network "$NETWORK" -v "$RSD_REPO_ROOT/dist:/dist:ro" "$MASTER_IMAGE" \
    sh -c "$MASTER_SCENARIO" >/dev/null
  local i
  for i in $(seq 1 120); do
    "$DOCKER" exec "$MASTER" test -s /tmp/fp 2>/dev/null && break
    "$DOCKER" ps -q -f "name=^$MASTER$" | grep -q . || { "$DOCKER" logs "$MASTER"; die "master container exited" "$E_RUNTIME"; }
    sleep 2
  done
  TOKEN="$("$DOCKER" exec "$MASTER" cat /tmp/token)"
  FP="$("$DOCKER" exec "$MASTER" cat /tmp/fp)"
  [[ ${#FP} -eq 64 ]] || die "master not ready (no CA fingerprint)" "$E_RUNTIME"
  "$DOCKER" logs "$MASTER" | grep '^master:' || true
}

# agent_up NAME: success when the master sees the agent of host NAME UP (each agent container
# has its own host name, so agents of the previous images cannot be mistaken for it).
agent_up() { "$DOCKER" exec "$MASTER" rsd-master status --json | grep -q "\"$1\""; }

# test_image IMAGE: install, enroll, check UP, remove; return the status.
test_image() {
  local image="$1" after name
  log_step "agent on $image"
  name="rsd-rpm-agent-${image//[^a-z0-9]/-}"
  "$DOCKER" rm -f "$name" >/dev/null 2>&1 || true
  if ! "$DOCKER" run -d --name "$name" --hostname "$name" --network "$NETWORK" -e "TOKEN=$TOKEN" -e "FP=$FP" \
    -v "$RSD_REPO_ROOT/dist:/dist:ro" "$image" sh -c "$AGENT_SCENARIO
sleep 30" >/dev/null; then
    log_error "$image: cannot start"
    return 1
  fi
  local i
  for i in $(seq 1 180); do
    "$DOCKER" logs "$name" 2>&1 | grep -q '^master rpm:' && break
    "$DOCKER" ps -q -f "name=^$name$" | grep -q . || break
    agent_up "$name" && after=up
    sleep 1
  done
  "$DOCKER" logs "$name" 2>&1 | grep -E '^(installed|connected|removal|master rpm):' || true
  local ok=0
  "$DOCKER" logs "$name" 2>&1 | grep -q '^removal: clean' || ok=1
  [[ "${after:-}" == up ]] || { log_error "$image: the master never saw the agent UP"; ok=1; }
  ((ok == 0)) || "$DOCKER" logs "$name" 2>&1 | tail -15
  "$DOCKER" rm -f "$name" >/dev/null 2>&1 || true
  ((ok == 0)) && log_ok "$image passed (agent seen UP by the master)"
  return "$ok"
}

# main ARGS...: entry point.
main() {
  parse_args "$@"
  require_cmd "$DOCKER"
  compgen -G "$RSD_REPO_ROOT/dist/rsd-master-*.noarch.rpm" >/dev/null || die "no RPM in dist/ (make linux-rpm)" "$E_DEPS"
  start_master
  local image failed=0
  for image in "${IMAGES[@]}"; do
    test_image "$image" || failed=1
  done
  ((failed == 0)) || die "some images failed" "$E_RUNTIME"
  log_ok "every image passed"
}

main "$@"
