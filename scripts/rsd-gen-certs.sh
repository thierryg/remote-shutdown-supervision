#!/usr/bin/env bash
# =============================================================================
# Remote Shutdown - LAN parental control and machine management (master/agent)
# -----------------------------------------------------------------------------
# File    : scripts/rsd-gen-certs.sh
# Purpose : OpenSSL example / offline alternative to the built-in PKI (CA, server and client certs)
# Author  : Thierry Gayet <thierry.gayet@labworks.fr>
# Project : remote-shutdown (version: VERSION)
# Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
# =============================================================================
#
# The master creates its CA and server certificate by itself at first start, and the agents
# get their certificates through the automatic enrollment: this script is NOT needed for a
# normal installation. It is provided to:
#   * show, with plain openssl commands, exactly what the built-in PKI produces;
#   * prepare the CA offline (e.g. on an air-gapped machine) and install it on the master
#     before its first start (--install), so that the CA key is generated where you choose;
#   * issue a client certificate by hand for a test agent (--client NAME).
#
# Layout written in OUT_DIR (default ./certs; keys are 0600):
#   ca/ca.key ca/ca.crt                     ECDSA P-384, 10 years, CA:TRUE, pathlen 0
#   server/server.key server/server.crt     ECDSA P-256, 397 days, serverAuth, SAN
#   clients/NAME/client.key client.crt      ECDSA P-256, 365 days, clientAuth, CN=NAME
#
# Usage:
#   scripts/rsd-gen-certs.sh [--out DIR] [--name DNS]... [--ip IP]... [--client NAME]...
#                            [--install PKI_DIR] [--force] [--no-color]
#   scripts/rsd-gen-certs.sh --help
#
# Examples:
#   scripts/rsd-gen-certs.sh --name master.home.arpa --ip 192.168.1.10
#   sudo scripts/rsd-gen-certs.sh --ip 192.168.1.10 --install /var/lib/rsd-master/pki
#   openssl x509 -in certs/server/server.crt -noout -text
#
# Prerequisites: bash >= 4.4, openssl >= 1.1.1 (-addext).
#
# Exit codes:
#   0  success
#   1  runtime failure (openssl)
#   2  usage error
#   3  root required for --install into a system directory
#   4  missing prerequisite (openssl)
#   7  state: the CA already exists (use --force to replace it)
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/rsd-common.sh
. "$SCRIPT_DIR/lib/rsd-common.sh"

OUT_DIR="$PWD/certs"
NAMES=()
IPS=()
CLIENTS=()
INSTALL_DIR=""
FORCE=0

# usage: print the help text (the header comment block).
usage() {
  sed -n '12,/^SCRIPT_DIR=/p' "${BASH_SOURCE[0]}" | sed -e '$d' -e 's/^# \{0,1\}//'
}

# parse_args ARGS...: read the options.
parse_args() {
  while (($#)); do
    case "$1" in
      --out) [[ $# -ge 2 ]] || die "--out needs a directory" "$E_USAGE"; OUT_DIR="$2"; shift 2 ;;
      --name) [[ $# -ge 2 ]] || die "--name needs a value" "$E_USAGE"; NAMES+=("$2"); shift 2 ;;
      --ip) [[ $# -ge 2 ]] || die "--ip needs a value" "$E_USAGE"; IPS+=("$2"); shift 2 ;;
      --client) [[ $# -ge 2 ]] || die "--client needs a name" "$E_USAGE"; CLIENTS+=("$2"); shift 2 ;;
      --install) [[ $# -ge 2 ]] || die "--install needs a directory" "$E_USAGE"; INSTALL_DIR="$2"; shift 2 ;;
      --force) FORCE=1; shift ;;
      --no-color) RSD_COLOR=never setup_colors; shift ;;
      -h | --help) usage; exit "$E_OK" ;;
      *) die "unknown option: $1 (see --help)" "$E_USAGE" ;;
    esac
  done
}

# new_key FILE CURVE: generate an EC private key (PKCS#8, 0600).
new_key() {
  (umask 077 && openssl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:$2" -out "$1")
}

# make_ca: create the certificate authority.
make_ca() {
  local dir="$OUT_DIR/ca"
  if [[ -f "$dir/ca.key" && $FORCE -eq 0 ]]; then
    die "$dir/ca.key already exists (use --force to replace the CA and every certificate)" "$E_STATE"
  fi
  mkdir -p "$dir"
  log_info "CA (ECDSA P-384, 10 years)"
  new_key "$dir/ca.key" secp384r1
  openssl req -x509 -new -key "$dir/ca.key" -sha384 -days 3650 \
    -subj "/O=Remote Shutdown/CN=Remote Shutdown Local CA $(openssl rand -hex 4)" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" -out "$dir/ca.crt"
}

# san_list: build the subjectAltName value from --name/--ip and the local host name.
san_list() {
  local items=("DNS:localhost" "IP:127.0.0.1") n i host
  host="$(hostname -s 2>/dev/null || hostname)"
  items+=("DNS:$host" "DNS:$host.local")
  for n in "${NAMES[@]}"; do items+=("DNS:$n"); done
  for i in "${IPS[@]}"; do items+=("IP:$i"); done
  local IFS=,
  printf '%s\n' "${items[*]}"
}

# make_server: issue the server certificate (leaf + CA chain in server.crt).
make_server() {
  local dir="$OUT_DIR/server" ca="$OUT_DIR/ca" san ext
  mkdir -p "$dir"
  san="$(san_list)"
  log_info "server certificate (SAN: $san)"
  new_key "$dir/server.key" prime256v1
  openssl req -new -key "$dir/server.key" -subj "/O=Remote Shutdown/CN=${NAMES[0]:-$(hostname -s)}" -out "$dir/server.csr"
  ext="$(mktemp)"
  on_exit "rm -f '$ext'"
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=%s\n' \
    "$san" >"$ext"
  openssl x509 -req -in "$dir/server.csr" -CA "$ca/ca.crt" -CAkey "$ca/ca.key" -CAcreateserial \
    -CAserial "$ca/ca.srl" -days 397 -sha256 -extfile "$ext" -out "$dir/server.leaf.crt"
  cat "$dir/server.leaf.crt" "$ca/ca.crt" >"$dir/server.crt"
  rm -f "$dir/server.leaf.crt" "$dir/server.csr"
}

# make_client NAME: issue a client certificate (CN=NAME, clientAuth only).
make_client() {
  local name="$1" dir="$OUT_DIR/clients/$1" ca="$OUT_DIR/ca" ext
  [[ "$name" =~ ^[A-Za-z0-9._-]+$ ]] || die "invalid client name: $name" "$E_USAGE"
  mkdir -p "$dir"
  log_info "client certificate $name"
  new_key "$dir/client.key" prime256v1
  openssl req -new -key "$dir/client.key" -subj "/O=rsd-agent/CN=$name" -out "$dir/client.csr"
  ext="$(mktemp)"
  on_exit "rm -f '$ext'"
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n' >"$ext"
  openssl x509 -req -in "$dir/client.csr" -CA "$ca/ca.crt" -CAkey "$ca/ca.key" -CAserial "$ca/ca.srl" \
    -days 365 -sha256 -extfile "$ext" -out "$dir/client.crt"
  cp "$ca/ca.crt" "$dir/ca.crt"
  rm -f "$dir/client.csr"
}

# install_pki DIR: copy the CA and server material where the master expects it.
install_pki() {
  local dir="$1" owner="rsd-master"
  { mkdir -p "$dir" 2>/dev/null && [[ -w "$dir" ]]; } || die "cannot write $dir (root required?)" "$E_PRIV"
  install -m 0600 "$OUT_DIR/ca/ca.key" "$dir/ca.key"
  install -m 0644 "$OUT_DIR/ca/ca.crt" "$dir/ca.crt"
  install -m 0600 "$OUT_DIR/server/server.key" "$dir/server.key"
  install -m 0644 "$OUT_DIR/server/server.crt" "$dir/server.crt"
  chmod 0700 "$dir"
  if [[ $EUID -eq 0 ]] && getent passwd "$owner" >/dev/null; then chown -R "$owner:$owner" "$dir"; fi
  log_ok "installed in $dir (restart the master: systemctl restart rsd-master)"
}

# main ARGS...: entry point.
main() {
  parse_args "$@"
  require_cmd openssl
  local c
  make_ca
  make_server
  for c in "${CLIENTS[@]}"; do make_client "$c"; done
  log_ok "CA fingerprint (pin it on the agents): $(openssl x509 -in "$OUT_DIR/ca/ca.crt" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d : | tr '[:upper:]' '[:lower:]')"
  [[ -n "$INSTALL_DIR" ]] && install_pki "$INSTALL_DIR"
  log_warn "protect $OUT_DIR/ca/ca.key (offline backup, then delete this copy once installed): whoever holds it can impersonate the master"
}

main "$@"
