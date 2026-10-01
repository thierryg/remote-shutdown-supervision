# =============================================================================
# Remote Shutdown - LAN parental control and machine management (master/agent)
# -----------------------------------------------------------------------------
# File    : master/rsd_master/__init__.py
# Purpose : Package marker; exposes the software version read from the single VERSION file
# Author  : Thierry Gayet <thierry.gayet@labworks.fr>
# Project : remote-shutdown (version: VERSION)
# Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
# =============================================================================
"""Remote Shutdown master: agent hub, PKI, policy engine and HTTPS web console.

The version has a single source, the ``VERSION`` file at the repository root. The Debian
package copies it next to this module (``rsd_master/VERSION``) at build time, so both a
checkout and an installed package resolve it without duplicating the number in code.
"""

from pathlib import Path


def _read_version() -> str:
    """Return the software version from the packaged copy or the repository root.

    Returns:
        The SemVer string, or ``"0.0.0+unknown"`` when no VERSION file is found.
    """
    here = Path(__file__).resolve().parent
    for candidate in (here / "VERSION", here.parent.parent / "VERSION"):
        try:
            return candidate.read_text(encoding="utf-8").strip()
        except OSError:
            continue
    return "0.0.0+unknown"


__version__ = _read_version()
