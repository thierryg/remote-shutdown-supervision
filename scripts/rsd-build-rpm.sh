#!/usr/bin/env bash
# =============================================================================
# Remote Shutdown - LAN parental control and machine management (master/agent)
# -----------------------------------------------------------------------------
# File    : scripts/rsd-build-rpm.sh
# Purpose : Build the RPM packages (rsd-master noarch, rsd-agent x86_64 / aarch64 / armv7hl)
# Author  : Thierry Gayet <thierry.gayet@labworks.fr>
# Project : remote-shutdown (version: VERSION)
# Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
# =============================================================================
#
# Produces in dist/:
#   rsd-master-<version>-1.noarch.rpm   Python master on the distribution packages (python3dist
#                                       requirements): Fedora, openSUSE
#   rsd-agent-<version>-1.<arch>.rpm    static Go agent: Fedora, RHEL / Rocky / AlmaLinux, openSUSE
#
# The files are staged exactly like the .deb (same units, configuration and launcher), then
# rpmbuild wraps them with packaging/rpm/*.spec. The agent binaries come from dist/bin
# (scripts/rsd-build-agent.sh); missing ones are built on the fly. RPM forbids "-" in a
# version: a pre-release 1.0.0-rc.1 becomes 1.0.0~rc.1 (sorted before 1.0.0).
#
# Usage:
#   scripts/rsd-build-rpm.sh [--master] [--agent] [--arch x86_64|aarch64|armv7hl]... [--no-color]
#   scripts/rsd-build-rpm.sh --help
#   (no --master/--agent: both; no --arch: x86_64 and aarch64)
#
# Environment variables:
#   NO_COLOR      disable colors (also RSD_COLOR=never)
#
# Prerequisites: bash >= 4.4, rpmbuild (Debian/Ubuntu package "rpm", Fedora "rpm-build"); go
# for the agent.
#
# Exit codes:
#   0  success
#   1  runtime failure (rpmbuild, build)
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
        [[ "$2" =~ ^(x86_64|aarch64|armv7hl)$ ]] || die "unsupported arch: $2" "$E_USAGE"
        ARCHES+=("$2"); shift 2 ;;
      --no-color) RSD_COLOR=never setup_colors; shift ;;
      -h | --help) usage; exit "$E_OK" ;;
      *) die "unknown option: $1 (see --help)" "$E_USAGE" ;;
    esac
  done
  if ((BUILD_MASTER == 0 && BUILD_AGENT == 0)); then BUILD_MASTER=1 BUILD_AGENT=1; fi
  ((${#ARCHES[@]})) || ARCHES=(x86_64 aarch64)
}

# rpm_version VERSION: RPM form of a SemVer version (pre-release separator "~").
rpm_version() { printf '%s\n' "${1/-/\~}"; }

# go_target ARCH: Go target of an RPM architecture.
go_target() {
  case "$1" in x86_64) echo linux/amd64 ;; aarch64) echo linux/arm64 ;; armv7hl) echo linux/arm ;; esac
}

# rpmbuild_spec SPEC STAGE ARCH: run rpmbuild in a private top directory, copy the RPM to dist/.
rpmbuild_spec() {
  local spec="$1" stage="$2" arch="$3" top
  top="$(mktemp -d)"
  on_exit "rm -rf '$top'"
  rpmbuild -bb --quiet --target "$arch" \
    --define "_topdir $top" --define "rsd_version $RPM_VERSION" --define "rsd_stage $stage" \
    --define "_build_id_links none" "$spec" >/dev/null
  find "$top/RPMS" -name '*.rpm' -exec cp {} "$DIST/" \; -exec basename {} \; | while read -r f; do log_ok "$DIST/$f"; done
}

# stage_docs ROOT NAME: license and README in /usr/share/doc/NAME.
stage_docs() {
  install -d "$1/usr/share/doc/$2"
  install -m 0644 "$RSD_REPO_ROOT/LICENSE" "$RSD_REPO_ROOT/README.md" "$1/usr/share/doc/$2/"
}

# build_master: stage and build rsd-master.noarch.rpm.
build_master() {
  local root
  root="$(mktemp -d)"
  on_exit "rm -rf '$root'"
  log_step "rsd-master $VERSION (noarch rpm)"
  install -d "$root/usr/lib/rsd-master" "$root/usr/bin" "$root/etc/rsd-master" "$root/usr/lib/systemd/system" \
    "$root/var/lib/rsd-master"
  (cd "$RSD_REPO_ROOT/master" && find rsd_master -type f \( -name '*.py' -o -path '*/static/*' \) ! -path '*__pycache__*' -print0 |
    while IFS= read -r -d '' f; do install -D -m 0644 "$f" "$root/usr/lib/rsd-master/$f"; done)
  install -m 0644 "$RSD_REPO_ROOT/VERSION" "$root/usr/lib/rsd-master/rsd_master/VERSION"
  install -m 0755 "$PKG/debian/rsd-master.sh" "$root/usr/bin/rsd-master"
  install -m 0640 "$PKG/config/master.ini" "$root/etc/rsd-master/master.ini"
  install -m 0644 "$PKG/systemd/rsd-master.service" "$PKG/systemd/rsd-master-backup.service" \
    "$PKG/systemd/rsd-master-backup.timer" "$root/usr/lib/systemd/system/"
  stage_docs "$root" rsd-master
  rpmbuild_spec "$PKG/rpm/rsd-master.spec" "$root" noarch
}

# build_agent ARCH: stage and build rsd-agent.<arch>.rpm.
build_agent() {
  local arch="$1" target bin root
  target="$(go_target "$arch")"
  bin="$DIST/bin/${target/\//-}/rsd-agent"
  [[ -x "$bin" ]] || "$SCRIPT_DIR/rsd-build-agent.sh" --target "$target"
  root="$(mktemp -d)"
  on_exit "rm -rf '$root'"
  log_step "rsd-agent $VERSION ($arch rpm)"
  install -d "$root/usr/bin" "$root/etc/rsd-agent" "$root/usr/lib/systemd/system" "$root/var/lib/rsd-agent"
  install -m 0755 "$bin" "$root/usr/bin/rsd-agent"
  install -m 0600 "$PKG/config/agent.json" "$root/etc/rsd-agent/agent.json"
  install -m 0644 "$PKG/systemd/rsd-agent.service" "$root/usr/lib/systemd/system/rsd-agent.service"
  stage_docs "$root" rsd-agent
  rpmbuild_spec "$PKG/rpm/rsd-agent.spec" "$root" "$arch"
}

# main ARGS...: entry point.
main() {
  parse_args "$@"
  require_cmd rpmbuild install
  umask 022
  VERSION="$(rsd_version)"
  [[ "$VERSION" != unknown ]] || die "VERSION file not found" "$E_CONFIG"
  RPM_VERSION="$(rpm_version "$VERSION")"
  mkdir -p "$DIST"
  ((BUILD_MASTER)) && build_master
  if ((BUILD_AGENT)); then
    local arch
    for arch in "${ARCHES[@]}"; do build_agent "$arch"; done
  fi
  return 0
}

main "$@"
