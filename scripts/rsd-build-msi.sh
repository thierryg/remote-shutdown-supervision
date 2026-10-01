#!/usr/bin/env bash
# =============================================================================
# Remote Shutdown - LAN parental control and machine management (master/agent)
# -----------------------------------------------------------------------------
# File    : scripts/rsd-build-msi.sh
# Purpose : Build the Windows agent installer (MSI, x64) with wixl (msitools) from Linux
# Author  : Thierry Gayet <thierry.gayet@labworks.fr>
# Project : remote-shutdown (version: VERSION)
# Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
# =============================================================================
#
# Produces dist/rsd-agent-<version>-x64.msi from packaging/windows/rsd-agent.wxs: the agent
# is installed in "C:\Program Files\rsd-agent", registered as the automatic LocalSystem
# service "rsd-agent", and the MSI properties MASTER, ENROLL_TOKEN and CA_FINGERPRINT are
# written to HKLM\SOFTWARE\rsd-agent for an unattended enrollment:
#
#   msiexec /i rsd-agent-<version>-x64.msi /qn MASTER=192.168.1.10 ENROLL_TOKEN=... CA_FINGERPRINT=...
#
# Usage:
#   scripts/rsd-build-msi.sh [--sign] [--no-color]
#   scripts/rsd-build-msi.sh --help
#
# Environment variables:
#   WIXL                  wixl command (default: wixl; Debian/Ubuntu package "wixl")
#   MSIBUILD, MSIINFO     msitools commands (default: msibuild, msiinfo; package "msitools")
#   OSSLSIGNCODE_CERT     PKCS#12 code-signing certificate for --sign (osslsigncode)
#   OSSLSIGNCODE_PASS     its password
#   NO_COLOR              disable colors (also RSD_COLOR=never)
#
# Prerequisites: bash >= 4.4, wixl and msitools >= 0.101; go to build the agent; osslsigncode for --sign.
#
# Exit codes:
#   0  success
#   1  runtime failure (wixl, signature)
#   2  usage error
#   4  missing prerequisite
#   5  invalid configuration (VERSION, signing certificate)
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/rsd-common.sh
. "$SCRIPT_DIR/lib/rsd-common.sh"

WIXL="${WIXL:-wixl}"
MSIBUILD="${MSIBUILD:-msibuild}"
MSIINFO="${MSIINFO:-msiinfo}"
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

# sign_file FILE: Authenticode-sign a file in place with osslsigncode.
sign_file() {
  local file="$1"
  require_cmd osslsigncode
  [[ -r "${OSSLSIGNCODE_CERT:-}" ]] || die "OSSLSIGNCODE_CERT must point to a PKCS#12 file" "$E_CONFIG"
  osslsigncode sign -pkcs12 "$OSSLSIGNCODE_CERT" -pass "${OSSLSIGNCODE_PASS:-}" -n "Remote Shutdown Agent" \
    -t http://timestamp.digicert.com -in "$file" -out "$file.signed"
  mv "$file.signed" "$file"
  log_ok "signed $(basename -- "$file")"
}

# secure_properties MSI: add the public properties to SecureCustomProperties (msibuild).
secure_properties() {
  local msi="$1" current
  current="$("$MSIINFO" export "$msi" Property | awk -F'\t' '$1 == "SecureCustomProperties" {print $2}')"
  "$MSIBUILD" "$msi" -q "UPDATE \`Property\` SET \`Value\` = '${current:+$current;}MASTER;ENROLL_TOKEN;CA_FINGERPRINT' WHERE \`Property\` = 'SecureCustomProperties'"
}

# main ARGS...: entry point.
main() {
  parse_args "$@"
  require_cmd "$WIXL" "$MSIBUILD" "$MSIINFO"
  local version msi_ver bin out tmp
  version="$(rsd_version)"
  [[ "$version" != unknown ]] || die "VERSION file not found" "$E_CONFIG"
  msi_ver="$(msi_version "$version")"
  bin="$RSD_REPO_ROOT/dist/bin/windows-amd64/rsd-agent.exe"
  [[ -f "$bin" ]] || "$SCRIPT_DIR/rsd-build-agent.sh" --target windows/amd64
  ((SIGN)) && sign_file "$bin"
  tmp="$(mktemp -d)"
  on_exit "rm -rf '$tmp'"
  # The MSI ships a plain-text license with CRLF line endings.
  sed 's/$/\r/' "$RSD_REPO_ROOT/LICENSE" >"$tmp/LICENSE.txt"
  # wixl resolves File/@Source relative to the .wxs directory: stage everything together.
  cp "$bin" "$tmp/rsd-agent.exe"
  cp "$RSD_REPO_ROOT/packaging/windows/rsd-agent.wxs" "$tmp/"
  out="$RSD_REPO_ROOT/dist/rsd-agent-${version}-x64.msi"
  log_step "rsd-agent $version MSI (ProductVersion $msi_ver)"
  (cd "$tmp" && "$WIXL" -a x64 -D "Version=$msi_ver" -D "Binary=rsd-agent.exe" -D "License=LICENSE.txt" \
    -o "$out" rsd-agent.wxs)
  secure_properties "$out"
  ((SIGN)) && sign_file "$out"
  log_ok "$out"
}

main "$@"
