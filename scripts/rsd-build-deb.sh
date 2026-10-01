#!/usr/bin/env bash
# =============================================================================
# Remote Shutdown - LAN parental control and machine management (master/agent)
# -----------------------------------------------------------------------------
# File    : scripts/rsd-build-deb.sh
# Purpose : Build the Debian / Ubuntu / Linux Mint packages (rsd-master all, rsd-agent per arch)
# Author  : Thierry Gayet <thierry.gayet@labworks.fr>
# Project : remote-shutdown (version: VERSION)
# Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
# =============================================================================
#
# Produces in dist/:
#   rsd-master_<version>_all.deb       Python master, depends on the distribution packages
#                                      (python3-fastapi, python3-uvicorn, ...): Debian 12+,
#                                      Ubuntu 22.04+, Linux Mint 21+
#   rsd-agent_<version>_<arch>.deb     static Go agent (amd64, arm64, armhf)
#
# The agent binaries are taken from dist/bin (scripts/rsd-build-agent.sh); missing ones are
# built on the fly.
#
# Usage:
#   scripts/rsd-build-deb.sh [--master] [--agent] [--arch amd64|arm64|armhf]... [--no-color]
#   scripts/rsd-build-deb.sh --help
#   (no --master/--agent: both; no --arch: amd64 and arm64)
#
# Environment variables:
#   NO_COLOR      disable colors (also RSD_COLOR=never)
#
# Prerequisites: bash >= 4.4, dpkg-deb >= 1.19 (--root-owner-group), gzip; go for the agent.
#
# Exit codes:
#   0  success
#   1  runtime failure (dpkg-deb, build)
#   2  usage error
#   4  missing prerequisite
#   5  invalid configuration (VERSION file)
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/rsd-common.sh
. "$SCRIPT_DIR/lib/rsd-common.sh"

DIST="$RSD_REPO_ROOT/dist"
PKG="$RSD_REPO_ROOT/packaging"
BUILD_MASTER=0
BUILD_AGENT=0
ARCHES=()

# usage: print the help text (the header comment block).
usage() {
  sed -n '12,/^SCRIPT_DIR=/p' "${BASH_SOURCE[0]}" | sed -e '$d' -e 's/^# \{0,1\}//'
}

# parse_args ARGS...: select what to build.
parse_args() {
  while (($#)); do
    case "$1" in
      --master) BUILD_MASTER=1; shift ;;
      --agent) BUILD_AGENT=1; shift ;;
      --arch)
        [[ $# -ge 2 ]] || die "--arch needs a value" "$E_USAGE"
        [[ "$2" =~ ^(amd64|arm64|armhf)$ ]] || die "unsupported arch: $2" "$E_USAGE"
        ARCHES+=("$2"); shift 2 ;;
      --no-color) RSD_COLOR=never setup_colors; shift ;;
      -h | --help) usage; exit "$E_OK" ;;
      *) die "unknown option: $1 (see --help)" "$E_USAGE" ;;
    esac
  done
  if ((BUILD_MASTER == 0 && BUILD_AGENT == 0)); then BUILD_MASTER=1 BUILD_AGENT=1; fi
  ((${#ARCHES[@]})) || ARCHES=(amd64 arm64)
}

# fill_control SRC DEST VERSION ARCH ROOT: render a control template (size in KiB of ROOT).
fill_control() {
  local src="$1" dest="$2" version="$3" arch="$4" root="$5" size
  size="$(du -sk --exclude=DEBIAN "$root" | cut -f1)"
  sed -e "s/@VERSION@/$version/" -e "s/@ARCH@/$arch/" -e "s/@SIZE@/$size/" "$src" >"$dest"
}

# add_docs ROOT NAME VERSION: copyright, README and Debian changelog in /usr/share/doc/NAME.
add_docs() {
  local root="$1" name="$2" version="$3" doc
  doc="$root/usr/share/doc/$name"
  install -d "$doc"
  install -m 0644 "$PKG/debian/copyright" "$doc/copyright"
  install -m 0644 "$RSD_REPO_ROOT/README.md" "$doc/README.md"
  printf '%s (%s) stable; urgency=medium\n\n  * Release %s, see /usr/share/doc/%s/README.md.\n\n -- Thierry Gayet <thierry.gayet@labworks.fr>  %s\n' \
    "$name" "$version" "$version" "$name" "$(date -R)" | gzip -9n >"$doc/changelog.Debian.gz"
}

# add_maintainer_scripts ROOT DIR: copy control scripts and conffiles.
add_maintainer_scripts() {
  local root="$1" dir="$2" f
  for f in postinst prerm postrm; do install -m 0755 "$dir/$f" "$root/DEBIAN/$f"; done
  install -m 0644 "$dir/conffiles" "$root/DEBIAN/conffiles"
}

# build_master VERSION: assemble and build rsd-master_<v>_all.deb.
build_master() {
  local version="$1" root
  root="$(mktemp -d)"
  on_exit "rm -rf '$root'"
  chmod 0755 "$root"
  log_step "rsd-master $version (all)"
  install -d "$root/DEBIAN" "$root/usr/lib/rsd-master" "$root/usr/bin" "$root/etc/rsd-master" "$root/lib/systemd/system"
  (cd "$RSD_REPO_ROOT/master" && find rsd_master -type f \( -name '*.py' -o -path '*/static/*' \) ! -path '*__pycache__*' -print0 |
    while IFS= read -r -d '' f; do install -D -m 0644 "$f" "$root/usr/lib/rsd-master/$f"; done)
  install -m 0644 "$RSD_REPO_ROOT/VERSION" "$root/usr/lib/rsd-master/rsd_master/VERSION"
  install -m 0755 "$PKG/debian/rsd-master.sh" "$root/usr/bin/rsd-master"
  install -m 0640 "$PKG/config/master.ini" "$root/etc/rsd-master/master.ini"
  install -m 0644 "$PKG/systemd/rsd-master.service" "$PKG/systemd/rsd-master-backup.service" \
    "$PKG/systemd/rsd-master-backup.timer" "$root/lib/systemd/system/"
  add_docs "$root" rsd-master "$version"
  add_maintainer_scripts "$root" "$PKG/debian/master"
  fill_control "$PKG/debian/master/control" "$root/DEBIAN/control" "$version" all "$root"
  dpkg-deb --root-owner-group -Zxz --build "$root" "$DIST/rsd-master_${version}_all.deb" >/dev/null
  log_ok "$DIST/rsd-master_${version}_all.deb"
}

# go_arch DEBARCH: Go target of a Debian architecture.
go_arch() {
  case "$1" in amd64) echo linux/amd64 ;; arm64) echo linux/arm64 ;; armhf) echo linux/arm ;; esac
}

# build_agent VERSION ARCH: assemble and build rsd-agent_<v>_<arch>.deb.
build_agent() {
  local version="$1" arch="$2" target bin root
  target="$(go_arch "$arch")"
  bin="$DIST/bin/${target/\//-}/rsd-agent"
  [[ -x "$bin" ]] || "$SCRIPT_DIR/rsd-build-agent.sh" --target "$target"
  root="$(mktemp -d)"
  on_exit "rm -rf '$root'"
  chmod 0755 "$root"
  log_step "rsd-agent $version ($arch)"
  install -d "$root/DEBIAN" "$root/usr/bin" "$root/etc/rsd-agent" "$root/lib/systemd/system"
  install -m 0755 "$bin" "$root/usr/bin/rsd-agent"
  install -m 0600 "$PKG/config/agent.json" "$root/etc/rsd-agent/agent.json"
  install -m 0644 "$PKG/systemd/rsd-agent.service" "$root/lib/systemd/system/rsd-agent.service"
  add_docs "$root" rsd-agent "$version"
  add_maintainer_scripts "$root" "$PKG/debian/agent"
  fill_control "$PKG/debian/agent/control" "$root/DEBIAN/control" "$version" "$arch" "$root"
  dpkg-deb --root-owner-group -Zxz --build "$root" "$DIST/rsd-agent_${version}_${arch}.deb" >/dev/null
  log_ok "$DIST/rsd-agent_${version}_${arch}.deb"
}

# main ARGS...: entry point.
main() {
  parse_args "$@"
  require_cmd dpkg-deb gzip du install
  umask 022
  local version arch
  version="$(rsd_version)"
  [[ "$version" != unknown ]] || die "VERSION file not found" "$E_CONFIG"
  mkdir -p "$DIST"
  ((BUILD_MASTER)) && build_master "$version"
  if ((BUILD_AGENT)); then
    for arch in "${ARCHES[@]}"; do build_agent "$version" "$arch"; done
  fi
  return 0
}

main "$@"
