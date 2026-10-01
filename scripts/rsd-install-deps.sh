#!/usr/bin/env bash
# =============================================================================
# Remote Shutdown - LAN parental control and machine management (master/agent)
# -----------------------------------------------------------------------------
# File    : scripts/rsd-install-deps.sh
# Purpose : Install the tools needed to build every package (make deps): Go, dpkg, rpmbuild, wixl
# Author  : Thierry Gayet <thierry.gayet@labworks.fr>
# Project : remote-shutdown (version: VERSION)
# Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
# =============================================================================
#
# Build machine only: the packages themselves need nothing of this on the target computers
# (the agent is a static binary, the master uses the distribution Python packages).
#
#   Debian / Ubuntu / Mint : dpkg-dev, rpm (rpmbuild), wixl + msitools, curl, python3
#   Fedora / RHEL / Rocky  : dpkg, rpm-build, msitools (wixl), curl, python3
#   openSUSE               : dpkg, rpm-build, msitools, curl, python3
#   macOS                  : Xcode command line tools (pkgbuild, productbuild, lipo), Homebrew
#                            bash; the .deb/.rpm/.msi are built on Linux (or by the CI)
#   Go (every OS)          : the official toolchain from go.dev (latest stable, SHA-256 checked)
#                            when the installed one is missing or older than agent/go.mod;
#                            the latest stable is preferred because its standard library
#                            security fixes are linked into the agent.
#
# Usage:
#   scripts/rsd-install-deps.sh [--no-go] [--go-dir DIR] [--dry-run] [--yes] [--no-color]
#   scripts/rsd-install-deps.sh --help
#     --no-go        do not install Go
#     --go-dir DIR   where to unpack Go (default /usr/local/go as root, ~/.local/go otherwise)
#     --dry-run      print the commands without running them
#     --yes          do not ask for confirmation (env ASSUME_YES=1)
#
# Environment variables:
#   NO_COLOR      disable colors (also RSD_COLOR=never)
#
# Prerequisites: bash >= 4.4, sudo (when not root) for the system packages, curl, Internet access.
#
# Exit codes:
#   0  every tool is installed
#   1  an installation command failed
#   2  usage error, or confirmation declined
#   3  root or sudo required for the system packages
#   4  unsupported operating system
#   6  network failure (go.dev unreachable, checksum mismatch)
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/rsd-common.sh
. "$SCRIPT_DIR/lib/rsd-common.sh"

WITH_GO=1
GO_DIR=""
DRY_RUN=0

# usage: print the help text (the header comment block).
usage() {
  sed -n '12,/^SCRIPT_DIR=/p' "${BASH_SOURCE[0]}" | sed -e '$d' -e 's/^# \{0,1\}//'
}

# parse_args ARGS...: read the options.
parse_args() {
  while (($#)); do
    case "$1" in
      --no-go) WITH_GO=0; shift ;;
      --go-dir) [[ $# -ge 2 ]] || die "--go-dir needs a directory" "$E_USAGE"; GO_DIR="$2"; shift 2 ;;
      --dry-run) DRY_RUN=1; shift ;;
      --yes) export ASSUME_YES=1; shift ;;
      --no-color) RSD_COLOR=never setup_colors; shift ;;
      -h | --help) usage; exit "$E_OK" ;;
      *) die "unknown option: $1 (see --help)" "$E_USAGE" ;;
    esac
  done
}

# run CMD...: run (or print with --dry-run) a command.
run() {
  log_info "+ $*"
  ((DRY_RUN)) || "$@"
}

# as_root CMD...: run a command as root (directly, or through sudo).
as_root() {
  if [[ $EUID -eq 0 ]]; then run "$@"
  elif command -v sudo >/dev/null 2>&1; then run sudo "$@"
  else die "root privileges required for: $* (install sudo or run as root)" "$E_PRIV"
  fi
}

# system_packages: install the packaging tools of this distribution.
system_packages() {
  if [[ "$(uname -s)" == Darwin ]]; then
    xcode-select -p >/dev/null 2>&1 || run xcode-select --install
    command -v brew >/dev/null 2>&1 || die "Homebrew is required on macOS: https://brew.sh" "$E_DEPS"
    run brew install bash coreutils
    return 0
  fi
  [[ -r /etc/os-release ]] || die "unsupported operating system (no /etc/os-release)" "$E_DEPS"
  local id like
  id="$(. /etc/os-release && echo "${ID:-}")"
  like="$(. /etc/os-release && echo "${ID_LIKE:-}")"
  case " $id $like " in
    *" debian "* | *" ubuntu "*)
      as_root apt-get update -qq
      as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        dpkg-dev rpm wixl msitools curl ca-certificates python3 tar gzip ;;
    *" fedora "* | *" rhel "* | *" centos "*)
      as_root dnf install -y dpkg rpm-build msitools curl python3 tar gzip ;;
    *" suse "* | *" opensuse "*)
      as_root zypper --non-interactive install dpkg rpm-build msitools curl python3 tar gzip ;;
    *) die "unsupported distribution: $id ($like); install dpkg-deb, rpmbuild, wixl, msitools by hand" "$E_DEPS" ;;
  esac
}

# required_go: minimum Go version of the agent (go directive of agent/go.mod).
required_go() { sed -n 's/^go \([0-9.]*\).*/\1/p' "$RSD_REPO_ROOT/agent/go.mod"; }

# version_ge A B: success when version A >= version B.
version_ge() { [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" == "$2" ]]; }

# install_go: unpack the latest stable Go from go.dev when the local one is missing or too old.
install_go() {
  local need have os arch latest file sum dir
  need="$(required_go)"
  have="$(go env GOVERSION 2>/dev/null | sed 's/^go//' || true)"
  if [[ -n "$have" ]] && version_ge "$have" "$need"; then
    log_ok "Go $have already installed (agent/go.mod needs $need)"
    return 0
  fi
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  case "$(uname -m)" in x86_64 | amd64) arch=amd64 ;; aarch64 | arm64) arch=arm64 ;; armv7l) arch=armv6l ;;
    *) die "unsupported CPU for the Go toolchain: $(uname -m)" "$E_DEPS" ;; esac
  latest="$(curl -fsSL 'https://go.dev/dl/?mode=json' | python3 -c "
import json, sys
release = json.load(sys.stdin)[0]
for f in release['files']:
    if f['os'] == '$os' and f['arch'] == '$arch' and f['kind'] == 'archive':
        print(release['version'], f['filename'], f['sha256'])
        break")" || die "cannot query go.dev" "$E_NETWORK"
  read -r version file sum <<<"$latest"
  [[ -n "${file:-}" ]] || die "no Go archive for $os/$arch on go.dev" "$E_NETWORK"
  dir="${GO_DIR:-$([[ $EUID -eq 0 ]] && echo /usr/local/go || echo "$HOME/.local/go")}"
  log_step "Installing $version into $dir (Go ${have:-absent} < $need)"
  confirm "replace $dir with $version?" || die "cancelled" "$E_USAGE"
  local tmp
  tmp="$(mktemp -d)"
  on_exit "rm -rf '$tmp'"
  run curl -fsSL -o "$tmp/$file" "https://go.dev/dl/$file"
  if ((!DRY_RUN)); then
    echo "$sum  $tmp/$file" | sha256sum -c --quiet - 2>/dev/null || echo "$sum  $tmp/$file" | shasum -a 256 -c --quiet - ||
      die "checksum mismatch for $file" "$E_NETWORK"
  fi
  local parent
  parent="$(dirname -- "$dir")"
  if [[ -w "$parent" ]] || { [[ ! -e "$parent" ]] && mkdir -p "$parent" 2>/dev/null; }; then
    run rm -rf "$dir"
    run tar -C "$parent" -xzf "$tmp/$file"
    [[ "$(basename -- "$dir")" == go ]] || run mv "$parent/go" "$dir"
  else
    as_root rm -rf "$dir"
    as_root tar -C "$parent" -xzf "$tmp/$file"
    [[ "$(basename -- "$dir")" == go ]] || as_root mv "$parent/go" "$dir"
  fi
  log_ok "$version installed: add $dir/bin to your PATH (export PATH=\"$dir/bin:\$PATH\")"
}

# main ARGS...: entry point.
main() {
  parse_args "$@"
  require_cmd curl
  log_step "Packaging tools"
  system_packages
  ((WITH_GO)) && install_go
  log_ok "build dependencies ready: make build"
}

main "$@"
