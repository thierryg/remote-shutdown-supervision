#!/usr/bin/env bash
# =============================================================================
# Remote Shutdown - LAN parental control and machine management (master/agent)
# -----------------------------------------------------------------------------
# File    : scripts/rsd-build-pkg.sh
# Purpose : Build the macOS agent installer (universal .pkg, macOS 12+) with pkgbuild/productbuild
# Author  : Thierry Gayet <thierry.gayet@labworks.fr>
# Project : remote-shutdown (version: VERSION)
# Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
# =============================================================================
#
# Produces dist/rsd-agent-<version>.pkg containing a universal (x86_64 + arm64) binary in
# /usr/local/bin, the launchd daemon com.labworks.rsd-agent, a default configuration and the
# rsd-agent-uninstall command. Must run on macOS (pkgbuild, productbuild and lipo are part of
# the Xcode command line tools).
#
# Usage:
#   scripts/rsd-build-pkg.sh [--no-color]
#   scripts/rsd-build-pkg.sh --help
#
# Environment variables:
#   DEVELOPER_ID_APP        "Developer ID Application: ..." identity to sign the binary (optional)
#   DEVELOPER_ID_INSTALLER  "Developer ID Installer: ..." identity to sign the pkg (optional)
#   NOTARY_PROFILE          notarytool keychain profile: notarize and staple the pkg (optional)
#   NO_COLOR                disable colors (also RSD_COLOR=never)
#
# Prerequisites: macOS, bash >= 4.4 (Homebrew), Xcode command line tools, go.
#
# Exit codes:
#   0  success
#   1  runtime failure (pkgbuild, productbuild, signature, notarization)
#   2  usage error
#   4  missing prerequisite (not macOS, tools missing)
#   5  invalid configuration (VERSION file)
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/rsd-common.sh
. "$SCRIPT_DIR/lib/rsd-common.sh"

IDENTIFIER="com.labworks.rsd-agent"
PKG="$RSD_REPO_ROOT/packaging/macos"

# usage: print the help text (the header comment block).
usage() {
  sed -n '12,/^SCRIPT_DIR=/p' "${BASH_SOURCE[0]}" | sed -e '$d' -e 's/^# \{0,1\}//'
}

# parse_args ARGS...: read the options.
parse_args() {
  while (($#)); do
    case "$1" in
      --no-color) RSD_COLOR=never setup_colors; shift ;;
      -h | --help) usage; exit "$E_OK" ;;
      *) die "unknown option: $1 (see --help)" "$E_USAGE" ;;
    esac
  done
}

# universal_binary DEST: build both architectures and merge them with lipo.
universal_binary() {
  local dest="$1" arch
  for arch in amd64 arm64; do
    [[ -f "$RSD_REPO_ROOT/dist/bin/darwin-$arch/rsd-agent" ]] || "$SCRIPT_DIR/rsd-build-agent.sh" --target "darwin/$arch"
  done
  lipo -create -output "$dest" "$RSD_REPO_ROOT/dist/bin/darwin-amd64/rsd-agent" "$RSD_REPO_ROOT/dist/bin/darwin-arm64/rsd-agent"
  chmod 0755 "$dest"
  if [[ -n "${DEVELOPER_ID_APP:-}" ]]; then
    codesign --force --options runtime --timestamp --sign "$DEVELOPER_ID_APP" "$dest"
    log_ok "binary signed"
  fi
}

# main ARGS...: entry point.
main() {
  parse_args "$@"
  [[ "$(uname -s)" == Darwin ]] || die "the .pkg can only be built on macOS (use the CI macOS job)" "$E_DEPS"
  require_cmd pkgbuild productbuild lipo
  local version tmp root out sign_args=()
  version="$(rsd_version)"
  [[ "$version" != unknown ]] || die "VERSION file not found" "$E_CONFIG"
  tmp="$(mktemp -d)"
  on_exit "rm -rf '$tmp'"
  root="$tmp/root"
  log_step "rsd-agent $version pkg"
  install -d "$root/usr/local/bin" "$root/Library/LaunchDaemons" "$root/Library/Application Support/rsd-agent"
  universal_binary "$root/usr/local/bin/rsd-agent"
  install -m 0755 "$PKG/rsd-agent-uninstall.sh" "$root/usr/local/bin/rsd-agent-uninstall"
  install -m 0644 "$PKG/com.labworks.rsd-agent.plist" "$root/Library/LaunchDaemons/"
  install -m 0600 "$RSD_REPO_ROOT/packaging/config/agent.json" "$root/Library/Application Support/rsd-agent/agent.json.default"
  install -d "$tmp/scripts" "$tmp/resources"
  install -m 0755 "$PKG/scripts/preinstall" "$PKG/scripts/postinstall" "$tmp/scripts/"
  cp "$RSD_REPO_ROOT/LICENSE" "$tmp/resources/LICENSE.txt"
  sed "s/@VERSION@/$version/g" "$PKG/distribution.xml" >"$tmp/distribution.xml"
  pkgbuild --root "$root" --scripts "$tmp/scripts" --identifier "$IDENTIFIER" --version "$version" \
    --install-location / --ownership recommended "$tmp/rsd-agent-component.pkg"
  [[ -n "${DEVELOPER_ID_INSTALLER:-}" ]] && sign_args=(--sign "$DEVELOPER_ID_INSTALLER" --timestamp)
  out="$RSD_REPO_ROOT/dist/rsd-agent-${version}.pkg"
  mkdir -p "$RSD_REPO_ROOT/dist"
  productbuild --distribution "$tmp/distribution.xml" --package-path "$tmp" --resources "$tmp/resources" \
    "${sign_args[@]}" "$out"
  if [[ -n "${NOTARY_PROFILE:-}" ]]; then
    xcrun notarytool submit "$out" --keychain-profile "$NOTARY_PROFILE" --wait
    xcrun stapler staple "$out"
    log_ok "notarized"
  fi
  log_ok "$out"
}

main "$@"
