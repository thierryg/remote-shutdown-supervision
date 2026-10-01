# =============================================================================
# Remote Shutdown - LAN parental control and machine management (master/agent)
# -----------------------------------------------------------------------------
# File    : master/rsd_master/config.py
# Purpose : Master settings: INI file + RSD__SECTION__KEY environment overrides + defaults
# Author  : Thierry Gayet <thierry.gayet@labworks.fr>
# Project : remote-shutdown (version: VERSION)
# Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
# =============================================================================
"""Static (restart-required) settings of the master.

Precedence, highest first: environment ``RSD__SECTION__KEY`` > INI file
(``/etc/rsd-master/master.ini`` or ``--config``) > built-in defaults. The INI format is used
because it is parsed by the standard library (no extra dependency on old distributions).

Runtime parameters that the administrator changes from the web console (uptime limit,
warning delay...) are not here: they live in the database (see :mod:`rsd_master.db`).
"""

from __future__ import annotations

import configparser
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

DEFAULT_CONFIG_PATH = Path("/etc/rsd-master/master.ini")


@dataclass
class Settings:
    """Master settings, one attribute per ``section.key`` of the INI file."""

    # [server]
    web_host: str = "0.0.0.0"  # noqa: S104 - LAN service, the firewall restricts the exposure
    web_port: int = 8443
    agent_host: str = "0.0.0.0"  # noqa: S104
    agent_port: int = 8444
    discovery_enabled: bool = True
    discovery_port: int = 50000
    # Extra DNS names / IP addresses written in the server certificate (comma separated).
    tls_extra_names: List[str] = field(default_factory=list)
    # [paths]
    data_dir: Path = Path("/var/lib/rsd-master")
    # [security]
    session_minutes: int = 30
    session_max_hours: int = 12
    login_max_failures: int = 5
    login_window_seconds: int = 300
    keepalive_timeout: int = 35
    # File holding the bearer token of GET /metrics (Prometheus); empty = endpoint disabled.
    metrics_token_file: str = ""
    agent_cert_days: int = 365
    server_cert_days: int = 397
    # [log]
    log_level: str = "INFO"
    log_json: bool = True

    @property
    def db_path(self) -> Path:
        """Path of the SQLite database."""
        return self.data_dir / "rsd-master.db"

    @property
    def pki_dir(self) -> Path:
        """Directory of the local certificate authority and the server certificate."""
        return self.data_dir / "pki"


# section -> key -> attribute name. Keeps the INI layout readable while the dataclass stays flat.
_LAYOUT = {
    "server": [
        "web_host", "web_port", "agent_host", "agent_port", "discovery_enabled", "discovery_port",
        "tls_extra_names",
    ],
    "paths": ["data_dir"],
    "security": [
        "session_minutes", "session_max_hours", "login_max_failures", "login_window_seconds",
        "keepalive_timeout", "agent_cert_days", "server_cert_days", "metrics_token_file",
    ],
    "log": ["log_level", "log_json"],
}


def _convert(raw: str, current: object) -> object:
    """Convert an INI/environment string to the type of the default value.

    Args:
        raw: The textual value.
        current: The default value, whose type drives the conversion.

    Returns:
        The converted value.

    Raises:
        ValueError: When the value cannot be converted.
    """
    raw = raw.strip()
    if isinstance(current, bool):
        if raw.lower() in ("1", "yes", "true", "on"):
            return True
        if raw.lower() in ("0", "no", "false", "off"):
            return False
        raise ValueError(f"invalid boolean: {raw!r}")
    if isinstance(current, int):
        return int(raw)
    if isinstance(current, Path):
        return Path(raw)
    if isinstance(current, list):
        return [item.strip() for item in raw.split(",") if item.strip()]
    return raw


def load_settings(path: Path | None = None, environ: dict | None = None) -> Settings:
    """Load the settings from the INI file and the environment.

    Args:
        path: INI file; defaults to ``RSD_CONFIG`` or ``/etc/rsd-master/master.ini``. A missing
            file is not an error (defaults apply).
        environ: Environment mapping (defaults to ``os.environ``), injectable for the tests.

    Returns:
        The resolved :class:`Settings`.

    Raises:
        ValueError: When a value has the wrong type.
    """
    env = os.environ if environ is None else environ
    settings = Settings()
    cfg_path = Path(path or env.get("RSD_CONFIG") or DEFAULT_CONFIG_PATH)
    parser = configparser.ConfigParser(interpolation=None)
    if cfg_path.is_file():
        parser.read(cfg_path, encoding="utf-8")
    for section, keys in _LAYOUT.items():
        for key in keys:
            raw = env.get(f"RSD__{section.upper()}__{key.upper()}")
            if raw is None and parser.has_option(section, key):
                raw = parser.get(section, key)
            if raw is None:
                continue
            try:
                setattr(settings, key, _convert(raw, getattr(settings, key)))
            except ValueError as exc:
                raise ValueError(f"invalid setting {section}.{key}: {exc}") from exc
    return settings
