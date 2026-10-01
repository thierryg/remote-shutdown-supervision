#!/usr/bin/env bash
# =============================================================================
# Remote Shutdown - LAN parental control and machine management (master/agent)
# -----------------------------------------------------------------------------
# File    : scripts/rsd-build-exe.sh
# Purpose : Standalone Windows agent executables (amd64, arm64), optionally Authenticode-signed
# Author  : Thierry Gayet <thierry.gayet@labworks.fr>
# Project : remote-shutdown (version: VERSION)
# Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
# =============================================================================
#
# Produces dist/rsd-agent-<version>-windows-amd64.exe and -windows-arm64.exe: the same static
# binary as the one embedded in the MSI, for a manual or scripted installation without MSI:
#   rsd-agent.exe enroll --token ... --fingerprint ... --master ...    (elevated prompt)
#   sc.exe create rsd-agent binPath= "C:\Program Files\rsd-agent\rsd-agent.exe run" start= auto
#   sc.exe start rsd-agent
#
# Usage:
#   scripts/rsd-build-exe.sh [--sign] [--no-color]
#   scripts/rsd-build-exe.sh --help
#
# Environment variables:
#   OSSLSIGNCODE_CERT     PKCS#12 code-signing certificate for --sign (osslsigncode)
#   OSSLSIGNCODE_PASS     its password
#   NO_COLOR              disable colors (also RSD_COLOR=never)
#
# Prerequisites: bash >= 4.4, go; osslsigncode for --sign.
#
# Exit codes:
#   0  success
#   1  runtime failure (build, signature)
#   2  usage error
#   4  missing prerequisite
#   5  invalid configuration (VERSION, signing certificate)
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/rsd-common.sh
. "$SCRIPT_DIR/lib/rsd-common.sh"

SIGN=0

# usage: print the help text (the header comment block).
usage() {
  sed -n '12,/^SCRIPT_DIR=/p' "${BASH_SOURCE[0]}" | sed -e '$d' -e 's/^# \{0,1\}//'
}

# parse_args ARGS...: read the options.
parse_args() {
  while (($#)); do
    case "$1" in
      --sign) SIGN=1; shift ;;
      --no-color) RSD_COLOR=never setup_colors; shift ;;
      -h | --help) usage; exit "$E_OK" ;;
      *) die "unknown option: $1 (see --help)" "$E_USAGE" ;;
    esac
  done
}

# main ARGS...: entry point.
main() {
  parse_args "$@"
  local version arch src out
  version="$(rsd_version)"
  [[ "$version" != unknown ]] || die "VERSION file not found" "$E_CONFIG"
  mkdir -p "$RSD_REPO_ROOT/dist"
  for arch in amd64 arm64; do
    src="$RSD_REPO_ROOT/dist/bin/windows-$arch/rsd-agent.exe"
    [[ -f "$src" ]] || "$SCRIPT_DIR/rsd-build-agent.sh" --target "windows/$arch"
    out="$RSD_REPO_ROOT/dist/rsd-agent-${version}-windows-$arch.exe"
    cp "$src" "$out"
    if ((SIGN)); then
      require_cmd osslsigncode
      [[ -r "${OSSLSIGNCODE_CERT:-}" ]] || die "OSSLSIGNCODE_CERT must point to a PKCS#12 file" "$E_CONFIG"
      osslsigncode sign -pkcs12 "$OSSLSIGNCODE_CERT" -pass "${OSSLSIGNCODE_PASS:-}" -n "Remote Shutdown Agent" \
        -t http://timestamp.digicert.com -in "$out" -out "$out.signed"
      mv "$out.signed" "$out"
    fi
    log_ok "$out"
  done
}

main "$@"
