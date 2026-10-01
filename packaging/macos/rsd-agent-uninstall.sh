#!/bin/sh
# =============================================================================
# Remote Shutdown - LAN parental control and machine management (master/agent)
# -----------------------------------------------------------------------------
# File    : packaging/macos/rsd-agent-uninstall.sh
# Purpose : Installed as /usr/local/bin/rsd-agent-uninstall: remove the macOS agent completely
# Author  : Thierry Gayet <thierry.gayet@labworks.fr>
# Project : remote-shutdown (version: VERSION)
# Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
# =============================================================================
set -e
if [ "$(id -u)" -ne 0 ]; then
  echo "rsd-agent-uninstall: run with sudo" >&2
  exit 3
fi
LABEL=com.labworks.rsd-agent
/bin/launchctl bootout "system/$LABEL" >/dev/null 2>&1 || true
rm -f "/Library/LaunchDaemons/$LABEL.plist" /usr/local/bin/rsd-agent /Library/Logs/rsd-agent.log
rm -rf "/Library/Application Support/rsd-agent"
/usr/sbin/pkgutil --forget com.labworks.rsd-agent >/dev/null 2>&1 || true
rm -f /usr/local/bin/rsd-agent-uninstall
echo "Remote Shutdown agent removed; delete the machine in the web console as well."
