# =============================================================================
# Remote Shutdown - LAN parental control and machine management (master/agent)
# -----------------------------------------------------------------------------
# File    : master/rsd_master/logs.py
# Purpose : Structured logging (one JSON object per line on stderr, collected by journald)
# Author  : Thierry Gayet <thierry.gayet@labworks.fr>
# Project : remote-shutdown (version: VERSION)
# Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
# =============================================================================
"""Structured logging without third-party dependency.

Every record is written as one JSON object (``ts``, ``level``, ``logger``, ``msg`` and the
fields passed through ``extra=``), which journald stores verbatim and ``jq`` can filter::

    journalctl -u rsd-master -o cat | jq 'select(.agent == "...")'

``log_json = false`` switches to a human-readable format for development.
"""

from __future__ import annotations

import json
import logging
import sys
import time

# Attributes of every LogRecord: anything else was passed through ``extra=``.
# "color_message" is a duplicate with ANSI codes added by uvicorn.
_STANDARD = set(vars(logging.LogRecord("", 0, "", 0, "", (), None))) | {"message", "asctime", "color_message"}


class JsonFormatter(logging.Formatter):
    """Format a record as a single-line JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        """Serialize the record and its ``extra`` fields.

        Args:
            record: The log record.

        Returns:
            The JSON line.
        """
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key, value in vars(record).items():
            if key not in _STANDARD and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, ensure_ascii=False)


class TextFormatter(logging.Formatter):
    """Human-readable format that still shows the ``extra`` fields as key=value pairs."""

    def format(self, record: logging.LogRecord) -> str:
        """Render ``HH:MM:SS LEVEL logger: message key=value...``.

        Args:
            record: The log record.

        Returns:
            The formatted line.
        """
        extras = " ".join(
            f"{k}={v}" for k, v in vars(record).items() if k not in _STANDARD and not k.startswith("_")
        )
        line = f"{time.strftime('%H:%M:%S', time.localtime(record.created))} {record.levelname:<5} " \
               f"{record.name}: {record.getMessage()}"
        if extras:
            line += f" {extras}"
        if record.exc_info:
            line += "\n" + self.formatException(record.exc_info)
        return line


def setup_logging(level: str = "INFO", json_output: bool = True) -> None:
    """Install the structured handler on the root logger (idempotent).

    Args:
        level: Minimum level name (DEBUG, INFO, WARNING, ERROR).
        json_output: JSON lines when true, text otherwise.
    """
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter() if json_output else TextFormatter())
    root.addHandler(handler)
    root.setLevel(level.upper())
    # uvicorn logs one line per HTTP request at INFO.
    for noisy in ("uvicorn.access",):
        logging.getLogger(noisy).setLevel(logging.WARNING)
