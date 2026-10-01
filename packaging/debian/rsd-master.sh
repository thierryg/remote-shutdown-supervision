#!/bin/sh
# =============================================================================
# Remote Shutdown - LAN parental control and machine management (master/agent)
# -----------------------------------------------------------------------------
# File    : packaging/debian/rsd-master.sh
# Purpose : /usr/bin/rsd-master launcher: runs the rsd_master package with the system Python
# Author  : Thierry Gayet <thierry.gayet@labworks.fr>
# Project : remote-shutdown (version: VERSION)
# Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
# =============================================================================
export PYTHONPATH="/usr/lib/rsd-master${PYTHONPATH:+:$PYTHONPATH}"
exec /usr/bin/python3 -m rsd_master "$@"
