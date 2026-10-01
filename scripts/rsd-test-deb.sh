#!/usr/bin/env bash
# =============================================================================
# Remote Shutdown - LAN parental control and machine management (master/agent)
# -----------------------------------------------------------------------------
# File    : scripts/rsd-test-deb.sh
# Purpose : Integration test of the .deb packages in Docker (Debian, Ubuntu, Linux Mint)
# Author  : Thierry Gayet <thierry.gayet@labworks.fr>
# Project : remote-shutdown (version: VERSION)
# Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
# =============================================================================
#
# For every image, in a throw-away container: install rsd-master and rsd-agent with apt (the
# master dependencies come from the distribution), start the master as its service account,
# log in, create an enrollment token with the CLI, enroll the agent, run it, check that the
# console reports it UP, send a popup, then purge both packages. systemd is not running in
# the container: the maintainer scripts must cope with that.
#
# Usage:
#   scripts/rsd-test-deb.sh [--image IMAGE]... [--no-color]
#   scripts/rsd-test-deb.sh --help
#
# Default images: ubuntu:26.04 debian:13 (latest LTS / stable), ubuntu:24.04 debian:12 ubuntu:22.04,
# linuxmintd/mint22-amd64
#
# Environment variables:
#   DOCKER        docker command (default: docker)
#   NO_COLOR      disable colors (also RSD_COLOR=never)
#
# Prerequisites: bash >= 4.4, docker, the packages in dist/ (make deb).
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
DEFAULT_IMAGES=(ubuntu:26.04 debian:13 ubuntu:24.04 debian:12 ubuntu:22.04 linuxmintd/mint22-amd64)

# usage: print the help text (the header comment block).
usage() {
  sed -n '12,/^SCRIPT_DIR=/p' "${BASH_SOURCE[0]}" | sed -e '$d' -e 's/^# \{0,1\}//'
}

# parse_args ARGS...: read the options.
parse_args() {
  while (($#)); do
    case "$1" in
      --image) [[ $# -ge 2 ]] || die "--image needs a value" "$E_USAGE"; IMAGES+=("$2"); shift 2 ;;
      --no-color) RSD_COLOR=never setup_colors; shift ;;
      -h | --help) usage; exit "$E_OK" ;;
      *) die "unknown option: $1 (see --help)" "$E_USAGE" ;;
    esac
  done
  ((${#IMAGES[@]})) || IMAGES=("${DEFAULT_IMAGES[@]}")
}

# The scenario run inside each container (POSIX sh, as root).
# shellcheck disable=SC2016
SCENARIO='
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq curl ca-certificates python3 >/dev/null
apt-get install -y -qq /dist/rsd-master_*_all.deb /dist/rsd-agent_*_amd64.deb >/dev/null
echo "installed: $(dpkg-query -W -f="\${Package} \${Version}, " rsd-master rsd-agent)"
runuser -u rsd-master -- rsd-master serve >/tmp/master.log 2>&1 &
for i in $(seq 1 30); do curl -skf https://127.0.0.1:8443/ >/dev/null && break; sleep 1; done
FP=$(rsd-master info | python3 -c "import json,sys; print(json.load(sys.stdin)[\"ca_fingerprint\"])")
TOKEN=$(rsd-master create-token --label docker)
test "$(stat -c %U /var/lib/rsd-master/rsd-master.db)" = rsd-master
rsd-agent enroll --token "$TOKEN" --fingerprint "$FP" --master 127.0.0.1
rsd-agent run >/tmp/agent.log 2>&1 &
sleep 3
C="curl -skf -c /tmp/cj -b /tmp/cj -H X-RSD:1 -H content-type:application/json"
$C -X POST -d "{\"username\":\"admin\",\"password\":\"admin\"}" https://127.0.0.1:8443/api/login >/dev/null
$C -X POST -d "{\"current\":\"admin\",\"new\":\"Docker-Test-2026\"}" https://127.0.0.1:8443/api/password >/dev/null
STATUS=$($C https://127.0.0.1:8443/api/agents | python3 -c "import json,sys; a=json.load(sys.stdin)[\"agents\"]; print(a[0][\"status\"], a[0][\"os\"])")
echo "agent: $STATUS"
case "$STATUS" in UP*) ;; *) cat /tmp/master.log /tmp/agent.log; exit 1 ;; esac
ID=$($C https://127.0.0.1:8443/api/agents | python3 -c "import json,sys; print(json.load(sys.stdin)[\"agents\"][0][\"id\"])")
$C -X POST -d "{\"text\":\"docker test\"}" https://127.0.0.1:8443/api/agents/$ID/message >/dev/null
rsd-master verify-audit
kill %1 %2 2>/dev/null || true
apt-get purge -y -qq rsd-agent rsd-master >/dev/null
test ! -e /var/lib/rsd-master && test ! -e /var/lib/rsd-agent && ! getent passwd rsd-master >/dev/null
echo "purge: clean"
'

# test_image IMAGE: run the scenario in a container; return its status.
test_image() {
  local image="$1"
  log_step "$image"
  if "$DOCKER" run --rm -v "$RSD_REPO_ROOT/dist:/dist:ro" "$image" sh -c "$SCENARIO"; then
    log_ok "$image passed"
    return 0
  fi
  log_error "$image FAILED"
  return 1
}

# main ARGS...: entry point.
main() {
  parse_args "$@"
  require_cmd "$DOCKER"
  compgen -G "$RSD_REPO_ROOT/dist/rsd-master_*_all.deb" >/dev/null || die "no package in dist/ (run make deb)" "$E_DEPS"
  local image failed=0
  for image in "${IMAGES[@]}"; do
    test_image "$image" || failed=1
  done
  ((failed == 0)) || die "some images failed" "$E_RUNTIME"
  log_ok "every image passed"
}

main "$@"
