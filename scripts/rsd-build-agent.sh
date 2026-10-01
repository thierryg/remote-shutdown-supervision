#!/usr/bin/env bash
# =============================================================================
# Remote Shutdown - LAN parental control and machine management (master/agent)
# -----------------------------------------------------------------------------
# File    : scripts/rsd-build-agent.sh
# Purpose : Cross-compile the Go agent for Linux, Windows and macOS (static, reproducible)
# Author  : Thierry Gayet <thierry.gayet@labworks.fr>
# Project : remote-shutdown (version: VERSION)
# Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
# =============================================================================
#
# Builds dist/bin/<os>-<arch>/rsd-agent[.exe] with CGO disabled, -trimpath and the version of
# the VERSION file injected at link time (-X main.version).
#
# Usage:
#   scripts/rsd-build-agent.sh [--target OS/ARCH]... [--out DIR] [--no-color]
#   scripts/rsd-build-agent.sh --help
#
# Default targets: linux/amd64 linux/arm64 linux/arm windows/amd64 windows/arm64 darwin/amd64 darwin/arm64
#
# Environment variables:
#   GO            Go command (default: go)
#   NO_COLOR      disable colors (also RSD_COLOR=never)
#
# Prerequisites: bash >= 4.4, Go (version of agent/go.mod or newer).
#
# Exit codes:
#   0  success
#   1  runtime failure (compilation error)
#   2  usage error
#   4  missing prerequisite (go)
#   5  invalid configuration (VERSION file)
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/rsd-common.sh
. "$SCRIPT_DIR/lib/rsd-common.sh"

DEFAULT_TARGETS=(linux/amd64 linux/arm64 linux/arm windows/amd64 windows/arm64 darwin/amd64 darwin/arm64)
TARGETS=()
OUT_DIR="$RSD_REPO_ROOT/dist/bin"
GO="${GO:-go}"

# usage: print the help text (the header comment block).
usage() {
  sed -n '12,/^SCRIPT_DIR=/p' "${BASH_SOURCE[0]}" | sed -e '$d' -e 's/^# \{0,1\}//'
}

# parse_args ARGS...: fill TARGETS and OUT_DIR.
parse_args() {
  while (($#)); do
    case "$1" in
      --target) [[ $# -ge 2 ]] || die "--target needs OS/ARCH" "$E_USAGE"; TARGETS+=("$2"); shift 2 ;;
      --out) [[ $# -ge 2 ]] || die "--out needs a directory" "$E_USAGE"; OUT_DIR="$2"; shift 2 ;;
      --no-color) RSD_COLOR=never setup_colors; shift ;;
      -h | --help) usage; exit "$E_OK" ;;
      *) die "unknown option: $1 (see --help)" "$E_USAGE" ;;
    esac
  done
  ((${#TARGETS[@]})) || TARGETS=("${DEFAULT_TARGETS[@]}")
}

# build_target OS/ARCH VERSION: compile one binary.
build_target() {
  local target="$1" version="$2" goos goarch ext="" dest
  goos="${target%/*}"
  goarch="${target#*/}"
  [[ "$goos" == windows ]] && ext=".exe"
  dest="$OUT_DIR/$goos-$goarch/rsd-agent$ext"
  mkdir -p "$(dirname -- "$dest")"
  log_info "building $target"
  (cd "$RSD_REPO_ROOT/agent" &&
    CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" GOARM=7 "$GO" build -trimpath -buildvcs=false \
      -ldflags "-s -w -X main.version=$version" -o "$dest" .)
  log_ok "$dest ($(du -h "$dest" | cut -f1))"
}

# main ARGS...: entry point.
main() {
  parse_args "$@"
  require_cmd "$GO"
  local version target
  version="$(rsd_version)"
  [[ "$version" != unknown ]] || die "VERSION file not found" "$E_CONFIG"
  log_step "rsd-agent $version"
  for target in "${TARGETS[@]}"; do
    [[ "$target" == */* ]] || die "invalid target: $target (expected OS/ARCH)" "$E_USAGE"
    build_target "$target" "$version"
  done
}

main "$@"
