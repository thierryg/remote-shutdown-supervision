# =============================================================================
# Remote Shutdown - LAN parental control and machine management (master/agent)
# -----------------------------------------------------------------------------
# File    : master/rsd_master/discovery.py
# Purpose : UDP discovery responder: answers the agents' DISCOVER broadcasts with the master ports
# Author  : Thierry Gayet <thierry.gayet@labworks.fr>
# Project : remote-shutdown (version: VERSION)
# Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
# =============================================================================
"""LAN discovery, used only to bootstrap (never for commands).

An agent without a configured master address broadcasts ``{"type": "DISCOVER"}`` to UDP
port 50000; the master answers by unicast with its ports and the fingerprint of its CA. The
agent takes the master address from the source of the answer.

UDP is unauthenticated, so the answer is only a hint: at enrollment the agent checks the
CA fingerprint it was given out of band (the command shown by the console), and afterwards
it verifies the master certificate against the stored CA. A forged answer can at worst
delay a connection, never redirect it to a fake master.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, Callable, Dict, Optional, Tuple

log = logging.getLogger(__name__)

MAX_DATAGRAM = 1024
# Answer at most this many requests per source address and second (amplification guard).
_RATE_WINDOW = 1.0


class DiscoveryProtocol(asyncio.DatagramProtocol):
    """Datagram protocol answering DISCOVER requests."""

    def __init__(self, answer: Callable[[], Dict[str, Any]]) -> None:
        """Create the responder.

        Args:
            answer: Callable returning the MASTER message to send.
        """
        self.answer = answer
        self.transport: Optional[asyncio.DatagramTransport] = None
        self._last: Dict[str, float] = {}

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """Remember the transport.

        Args:
            transport: The datagram transport.
        """
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        """Answer a valid DISCOVER datagram.

        Args:
            data: Datagram payload.
            addr: Source address.
        """
        if len(data) > MAX_DATAGRAM or self.transport is None:
            return
        try:
            message = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return
        if not isinstance(message, dict) or message.get("type") != "DISCOVER":
            return
        now = time.time()
        if now - self._last.get(addr[0], 0.0) < _RATE_WINDOW:
            return
        self._last[addr[0]] = now
        if len(self._last) > 4096:
            self._last.clear()
        self.transport.sendto(json.dumps(self.answer()).encode("utf-8"), addr)
        log.debug("discovery answered", extra={"ip": addr[0]})


async def start_discovery(host: str, port: int, answer: Callable[[], Dict[str, Any]]) -> asyncio.DatagramTransport:
    """Bind the discovery responder.

    Args:
        host: Bind address.
        port: UDP port.
        answer: Callable returning the MASTER message.

    Returns:
        The datagram transport (close it to stop).
    """
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: DiscoveryProtocol(answer), local_addr=(host, port), allow_broadcast=True
    )
    log.info("discovery listening", extra={"port": port})
    return transport  # type: ignore[return-value]
