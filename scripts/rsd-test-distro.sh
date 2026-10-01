#!/usr/bin/env bash
# =============================================================================
# Remote Shutdown - LAN parental control and machine management (master/agent)
# -----------------------------------------------------------------------------
# File    : scripts/rsd-test-distro.sh
# Purpose : Run the master test suite inside Debian / Ubuntu / Mint containers on their own packages
# Author  : Thierry Gayet <thierry.gayet@labworks.fr>
# Project : remote-shutdown (version: VERSION)
# Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
# =============================================================================
#
# The .deb of the master depends on the distribution Python packages (python3-fastapi,
# python3-uvicorn, python3-cryptography, python3-bcrypt, python3-jwt). For every image, this
# script installs exactly those packages (plus python3-pytest and the HTTP client of the test
# client) with apt, prints their versions, and runs pytest on a read-only copy of the
# repository. No pip, no virtualenv: what passes here is what the package runs on.
#
# Usage:
#   scripts/rsd-test-distro.sh [--image IMAGE]... [--no-color]
#   scripts/rsd-test-distro.sh --help
#
# Default images: ubuntu:26.04 debian:13 ubuntu:24.04 debian:12 ubuntu:22.04
#
# Environment variables:
#   DOCKER        docker command (default: docker)
#   NO_COLOR      disable colors (also RSD_COLOR=never)
#
# Prerequisites: bash >= 4.4, docker, Internet access (apt).
#
# Exit codes:
#   0  the suite passed on every image
#   1  it failed on at least one image
#   2  usage error
#   4  missing prerequisite (docker)
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/rsd-common.sh
. "$SCRIPT_DIR/lib/rsd-common.sh"

DOCKER="${DOCKER:-docker}"
IMAGES=()
DEFAULT_IMAGES=(ubuntu:26.04 debian:13 ubuntu:24.04 debian:12 ubuntu:22.04)

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

# The scenario run inside each container (POSIX sh, as root). The test client of old Starlette
# releases uses python3-requests, the recent ones python3-httpx: both are installed.
# shellcheck disable=SC2016
SCENARIO='
set -eu
export DEBIAN_FRONTEND=noninteractive
. /etc/os-release
apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends python3 python3-fastapi python3-uvicorn python3-cryptography \
  python3-bcrypt python3-jwt python3-pytest python3-requests python3-httpx >/dev/null
printf "%s · " "$PRETTY_NAME"
dpkg-query -W -f="\${Package} \${Version}\n" python3 python3-fastapi python3-starlette python3-pydantic \
  python3-uvicorn python3-cryptography python3-bcrypt python3-jwt | awk "{printf \"%s %s, \", \$1, \$2}"
echo
cp -r /src /tmp/src && cd /tmp/src
python3 -m pytest -q -p no:cacheprovider tests
'

# test_image IMAGE: run the scenario in a container; return its status.
test_image() {
  local image="$1"
  log_step "$image"
  if "$DOCKER" run --rm -v "$RSD_REPO_ROOT:/src:ro" "$image" sh -c "$SCENARIO"; then
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
  local image failed=0
  for image in "${IMAGES[@]}"; do
    test_image "$image" || failed=1
  done
  ((failed == 0)) || die "some images failed" "$E_RUNTIME"
  log_ok "every image passed"
}

main "$@"
