# =============================================================================
# Remote Shutdown - LAN parental control and machine management (master/agent)
# -----------------------------------------------------------------------------
# File    : master/rsd_master/hub.py
# Purpose : Agent hub: mutual-TLS JSON-lines server, live agent state, command dispatch
# Author  : Thierry Gayet <thierry.gayet@labworks.fr>
# Project : remote-shutdown (version: VERSION)
# Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
# =============================================================================
"""Persistent, agent-initiated connections over mutual TLS (JSON lines on TCP 8444).

Every agent keeps one TLS connection to ``master:8444`` open and both sides exchange one
JSON object per line (UTF-8, ``\\n`` terminated, 64 KiB maximum). The framing is deliberately
minimal: it needs only the standard library on both sides (Python ``asyncio`` + ``ssl``,
Go ``crypto/tls``), so it runs unchanged on every supported distribution, including the old
Python packages of Ubuntu 22.04 / Linux Mint 21.

TLS requires a client certificate signed by the local CA; the agent identity is the
certificate CN (a UUID chosen by the master at enrollment), never a value sent by the agent.
The certificate serial must match the one recorded in the database, so a deleted agent or a
superseded certificate is refused even though it is still cryptographically valid.

Because connections are opened by the agents, the machines need no inbound port and no
firewall rule: commands (shutdown, popup, chat) travel back on the same connection.

Status: an agent is ``UP`` while its connection is open and a line (``KEEPALIVE`` every
10 s, answered by ``PONG``, or any message) arrived less than ``keepalive_timeout`` seconds
ago; it is ``DOWN`` otherwise. :meth:`AgentHub.monitor` closes stale connections.

See ``docs/PROTOCOL.md`` for the message reference.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import ssl
import time
import uuid
from typing import Any, Dict, List, Optional

from .db import Database
from .pki import PKI, PKIError, cert_pem, not_after, serial_hex

log = logging.getLogger(__name__)

PROTOCOL_VERSION = 1
MAX_MESSAGE_BYTES = 64 * 1024
KEEPALIVE_INTERVAL = 10
MAX_TEXT = 2000
MAX_INTERFACES = 64


class AgentConnection:
    """Live state of a connected agent and its line-oriented TLS stream."""

    def __init__(self, agent_id: str, writer: asyncio.StreamWriter, ip: str) -> None:
        """Wrap an authenticated stream.

        Args:
            agent_id: Agent UUID (certificate CN).
            writer: Stream writer of the TLS connection.
            ip: Peer address.
        """
        self.agent_id = agent_id
        self.writer = writer
        self.ip = ip
        self.connected_at = time.time()
        self.last_seen = self.connected_at
        self.uptime: Optional[float] = None
        self.shutdown_at: Optional[float] = None
        self._lock = asyncio.Lock()

    async def send(self, message: Dict[str, Any], timeout: float = 10.0) -> None:
        """Write one JSON line and wait until it is flushed.

        Args:
            message: JSON-serializable object.
            timeout: Maximum time to flush the line.

        Raises:
            OSError, asyncio.TimeoutError: When the connection is broken or stuck.
        """
        line = (json.dumps(message, separators=(",", ":")) + "\n").encode("utf-8")
        async with self._lock:
            self.writer.write(line)
            await asyncio.wait_for(self.writer.drain(), timeout=timeout)

    async def close(self) -> None:
        """Close the connection (errors on a broken socket are ignored)."""
        # Closing a broken socket may fail: there is nothing left to do then.
        with contextlib.suppress(Exception):
            self.writer.close()
            await asyncio.wait_for(self.writer.wait_closed(), timeout=5)


def peer_identity(ssl_object: Optional[ssl.SSLObject]) -> Optional[Dict[str, Any]]:
    """Extract the verified client certificate fields of a TLS connection.

    Args:
        ssl_object: The ``ssl_object`` extra info of the transport.

    Returns:
        ``{"cn": ..., "org": ..., "serial": int}`` or None when no certificate is available.
    """
    cert = ssl_object.getpeercert() if ssl_object is not None else None
    if not cert:
        return None
    fields: Dict[str, str] = {}
    for rdn in cert.get("subject", ()):
        for key, value in rdn:
            fields[key] = value
    try:
        serial = int(cert.get("serialNumber", ""), 16)
    except ValueError:
        return None
    return {"cn": fields.get("commonName", ""), "org": fields.get("organizationName", ""), "serial": serial}


def _clean_text(value: Any, limit: int = MAX_TEXT) -> str:
    """Coerce an untrusted value to a bounded, control-character-free string.

    Args:
        value: Untrusted value.
        limit: Maximum length.
    """
    text = value if isinstance(value, str) else ("" if value is None else str(value))
    return "".join(ch for ch in text if ch in "\n\t" or ch.isprintable())[:limit]


def _clean_interfaces(value: Any) -> List[Dict[str, Any]]:
    """Validate the interface list reported by an agent.

    Args:
        value: Untrusted list of ``{name, ipv4, ipv6, mac}`` objects; ``ipv4``/``ipv6`` may be
            a string or a list of strings.

    Returns:
        A sanitized list.
    """
    result: List[Dict[str, Any]] = []
    if not isinstance(value, list):
        return result
    for item in value[:MAX_INTERFACES]:
        if not isinstance(item, dict):
            continue
        entry: Dict[str, Any] = {"name": _clean_text(item.get("name"), 64), "mac": _clean_text(item.get("mac"), 64)}
        for family in ("ipv4", "ipv6"):
            raw = item.get(family) or []
            if isinstance(raw, str):
                raw = [raw]
            entry[family] = [_clean_text(a, 64) for a in raw if isinstance(a, str)][:16]
        result.append(entry)
    return result


class AgentHub:
    """Registry of the connected agents and entry point for every command sent to them."""

    def __init__(self, db: Database, pki: PKI, keepalive_timeout: int = 35) -> None:
        """Create an empty hub.

        Args:
            db: Database.
            pki: Certificate authority (used for certificate renewal).
            keepalive_timeout: Seconds without any frame before an agent is DOWN.
        """
        self.db = db
        self.pki = pki
        self.keepalive_timeout = keepalive_timeout
        self.connections: Dict[str, AgentConnection] = {}

    # --- TLS -----------------------------------------------------------------
    def ssl_context(self) -> ssl.SSLContext:
        """Build the mutual-TLS server context (client certificate signed by the CA required)."""
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(str(self.pki.server_cert_path), str(self.pki.server_key_path))
        ctx.load_verify_locations(cafile=str(self.pki.ca_cert_path))
        ctx.verify_mode = ssl.CERT_REQUIRED
        # Python 3.13+ enables the strict X.509 profile by default; agent certificates issued by
        # the first releases have no Authority Key Identifier and would be refused after an upgrade of
        # the master. The chain, the validity and the clientAuth usage are still verified, and
        # the identity is checked against the recorded serial; new certificates are compliant.
        ctx.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
        return ctx

    # --- status --------------------------------------------------------------
    def is_up(self, agent_id: str) -> bool:
        """Tell whether an agent is connected and alive.

        Args:
            agent_id: Agent UUID.
        """
        conn = self.connections.get(agent_id)
        return conn is not None and time.time() - conn.last_seen <= self.keepalive_timeout

    def live(self, agent_id: str) -> Dict[str, Any]:
        """Return the live fields of an agent for the API.

        Args:
            agent_id: Agent UUID.
        """
        conn = self.connections.get(agent_id)
        up = self.is_up(agent_id)
        return {
            "status": "UP" if up else "DOWN",
            "ip": conn.ip if conn else None,
            "connected_at": conn.connected_at if conn and up else None,
            "shutdown_at": conn.shutdown_at if conn and up else None,
        }

    # --- sending -------------------------------------------------------------
    async def send(self, agent_id: str, message: Dict[str, Any]) -> bool:
        """Send a message to one agent.

        Args:
            agent_id: Agent UUID.
            message: JSON-serializable message; a ``ref`` is added when missing.

        Returns:
            True when the message was written to an open connection.
        """
        conn = self.connections.get(agent_id)
        if conn is None or not self.is_up(agent_id):
            return False
        message.setdefault("ref", uuid.uuid4().hex)
        try:
            await conn.send(message)
        except Exception as exc:  # noqa: BLE001 - any transport error means the agent is gone
            log.warning("send failed", extra={"agent": agent_id, "type": message.get("type"), "error": str(exc)})
            await self._drop(conn)
            return False
        if message.get("type") != "PONG":
            log.info("command sent", extra={"agent": agent_id, "type": message.get("type"), "ref": message["ref"]})
        return True

    async def broadcast(self, message: Dict[str, Any]) -> List[str]:
        """Send a message to every UP agent.

        Args:
            message: Message (copied per agent).

        Returns:
            The ids of the agents that received it.
        """
        ids = [a for a in list(self.connections) if self.is_up(a)]
        results = await asyncio.gather(*(self.send(a, dict(message)) for a in ids))
        return [a for a, ok in zip(ids, results, strict=True) if ok]

    async def disconnect(self, agent_id: str) -> None:
        """Close the connection of an agent (after revocation).

        Args:
            agent_id: Agent UUID.
        """
        conn = self.connections.get(agent_id)
        if conn:
            await self._drop(conn)

    async def _drop(self, conn: AgentConnection) -> None:
        """Unregister (if still registered) and close a connection.

        Args:
            conn: The connection to drop.
        """
        if self.connections.get(conn.agent_id) is conn:
            del self.connections[conn.agent_id]
        await conn.close()

    # --- connection handling ---------------------------------------------------
    async def handle_stream(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Serve one agent connection (``asyncio.start_server`` callback).

        Args:
            reader: TLS stream reader (line limit = :data:`MAX_MESSAGE_BYTES`).
            writer: TLS stream writer.
        """
        peer = writer.get_extra_info("peername") or ("?",)
        ip = str(peer[0])
        identity = peer_identity(writer.get_extra_info("ssl_object"))
        agent = self.db.get_agent(identity["cn"]) if identity else None
        if identity is None or agent is None or int(agent["cert_serial"], 16) != identity["serial"]:
            log.warning("agent refused (unknown, deleted or superseded certificate)",
                        extra={"ip": ip, "cn": identity["cn"] if identity else None})
            conn = AgentConnection("?", writer, ip)
            with contextlib.suppress(Exception):  # best effort before closing
                await conn.send({"type": "ERROR", "error": "certificate not accepted", "fatal": True})
            await conn.close()
            return
        agent_id = agent["id"]
        conn = AgentConnection(agent_id, writer, ip)
        previous = self.connections.get(agent_id)
        self.connections[agent_id] = conn
        if previous is not None:
            await previous.close()
        self.db.update_agent_info(agent_id, last_seen=time.time(), last_ip=ip)
        log.info("agent connected", extra={"agent": agent_id, "ip": ip})
        try:
            await conn.send({
                "type": "WELCOME", "agent_id": agent_id, "protocol": PROTOCOL_VERSION,
                "server_time": time.time(), "keepalive_interval": KEEPALIVE_INTERVAL,
            })
            while True:
                try:
                    raw = await reader.readline()
                except ValueError:  # line longer than the limit: protocol violation
                    log.warning("oversized line from agent", extra={"agent": agent_id})
                    break
                if not raw:
                    break
                conn.last_seen = time.time()
                try:
                    message = json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, ValueError):
                    log.warning("invalid JSON from agent", extra={"agent": agent_id})
                    continue
                if isinstance(message, dict):
                    await self._dispatch(conn, message)
        except Exception as exc:  # noqa: BLE001 - connection reset, TLS error...
            log.info("agent connection ended", extra={"agent": agent_id, "reason": type(exc).__name__})
        finally:
            if self.connections.get(agent_id) is conn:
                del self.connections[agent_id]
                self.db.update_agent_info(agent_id, last_seen=conn.last_seen)
                log.info("agent disconnected", extra={"agent": agent_id})
            await conn.close()

    async def _dispatch(self, conn: AgentConnection, message: Dict[str, Any]) -> None:
        """Handle one message from an agent.

        Args:
            conn: The agent connection.
            message: Decoded JSON object.
        """
        kind = message.get("type")
        agent_id = conn.agent_id
        if kind == "DECLARE":
            boot_time = message.get("boot_time")
            self.db.update_agent_info(
                agent_id,
                hostname=_clean_text(message.get("hostname"), 255),
                os=_clean_text(message.get("os"), 64),
                arch=_clean_text(message.get("arch"), 32),
                agent_version=_clean_text(message.get("version"), 32),
                interfaces=_clean_interfaces(message.get("interfaces")),
                boot_time=float(boot_time) if isinstance(boot_time, (int, float)) else None,
                last_seen=conn.last_seen,
            )
        elif kind == "UPDATE":
            self.db.update_agent_info(agent_id, interfaces=_clean_interfaces(message.get("interfaces")),
                                      last_seen=conn.last_seen)
            log.info("agent interfaces updated", extra={"agent": agent_id})
        elif kind == "KEEPALIVE":
            uptime = message.get("uptime")
            if isinstance(uptime, (int, float)) and uptime >= 0:
                conn.uptime = float(uptime)
                self.db.update_agent_info(agent_id, boot_time=time.time() - float(uptime), last_seen=conn.last_seen)
            await self.send(agent_id, {"type": "PONG"})
        elif kind == "STATE":
            at = message.get("shutdown_at")
            conn.shutdown_at = float(at) if isinstance(at, (int, float)) else None
        elif kind == "ACK":
            log.info("command acknowledged", extra={
                "agent": agent_id, "ref": _clean_text(message.get("ref"), 64), "ok": bool(message.get("ok")),
                "error": _clean_text(message.get("error"), 300) or None,
            })
        elif kind == "CHAT":
            text = _clean_text(message.get("text")).strip()
            if text:
                self.db.add_chat(agent_id, "in", _clean_text(message.get("user"), 64) or "user", text)
        elif kind == "RENEW":
            await self._renew(conn, message.get("csr"))
        else:
            log.warning("unknown message type", extra={"agent": agent_id, "type": _clean_text(kind, 32)})

    async def _renew(self, conn: AgentConnection, csr: Any) -> None:
        """Issue a new certificate for an authenticated agent.

        Args:
            conn: The (already authenticated) agent connection.
            csr: PEM CSR sent by the agent.
        """
        if not isinstance(csr, str):
            return
        try:
            cert = self.pki.sign_agent_csr(csr, conn.agent_id)
        except PKIError as exc:
            log.warning("renewal refused", extra={"agent": conn.agent_id, "error": str(exc)})
            await self.send(conn.agent_id, {"type": "ERROR", "error": f"renewal refused: {exc}"})
            return
        if await self.send(conn.agent_id, {"type": "RENEWED", "cert": cert_pem(cert), "ca": self.pki.ca_pem()}):
            self.db.update_agent_cert(conn.agent_id, serial_hex(cert), not_after(cert).timestamp())
            self.db.audit("system", "agent.renew", conn.agent_id, {"serial": serial_hex(cert)})

    async def monitor(self, interval: float = 5.0) -> None:
        """Close the connections that stopped sending frames (runs forever).

        Args:
            interval: Check period in seconds.
        """
        while True:
            await asyncio.sleep(interval)
            now = time.time()
            for agent_id, conn in list(self.connections.items()):
                if now - conn.last_seen > self.keepalive_timeout:
                    log.warning("keepalive timeout, agent DOWN", extra={"agent": agent_id})
                    await self._drop(conn)
