# =============================================================================
# Remote Shutdown - LAN parental control and machine management (master/agent)
# -----------------------------------------------------------------------------
# File    : master/rsd_master/server.py
# Purpose : Service runtime: HTTPS console, mTLS agent hub, UDP discovery and policy in one event loop
# Author  : Thierry Gayet <thierry.gayet@labworks.fr>
# Project : remote-shutdown (version: VERSION)
# Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
# =============================================================================
"""Run every component of the master in a single asyncio event loop.

=================  ==========  ==============================================
Component          Port        Transport
=================  ==========  ==============================================
Web console + API  8443/tcp    HTTPS (uvicorn), no client certificate
Agent hub          8444/tcp    JSON lines over mutual TLS (asyncio)
Discovery          50000/udp   JSON datagrams (bootstrap only)
=================  ==========  ==============================================

Sharing one loop keeps the live agent registry in memory without locking: the REST
handlers await :meth:`rsd_master.hub.AgentHub.send` directly.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Any, Dict

import uvicorn

from . import __version__
from .auth import RateLimiter, SessionManager, hash_password, load_secret
from .config import Settings
from .db import Database
from .discovery import start_discovery
from .hub import MAX_MESSAGE_BYTES, AgentHub
from .pki import PKI
from .policy import PolicyEngine
from .web import AppContext, create_app

log = logging.getLogger(__name__)

DEFAULT_ADMIN = ("admin", "admin")
# Exit status asking systemd (Restart=on-failure) to restart the service with a new certificate.
EXIT_RESTART = 75
CERT_CHECK_INTERVAL = 3600


def build_context(settings: Settings) -> AppContext:
    """Prepare the data directory, the database, the PKI and the shared objects.

    Creates the default ``admin`` / ``admin`` account (to be changed at first login) when no
    administrator exists.

    Args:
        settings: Master settings.

    Returns:
        The application context.
    """
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    db = Database(settings.db_path)
    db.init()
    pki = PKI(settings.pki_dir, server_days=settings.server_cert_days, agent_days=settings.agent_cert_days)
    pki.ensure(settings.tls_extra_names)
    if db.count_users() == 0:
        db.upsert_user(DEFAULT_ADMIN[0], hash_password(DEFAULT_ADMIN[1]), must_change=True)
        db.audit("system", "auth.default_admin_created", DEFAULT_ADMIN[0])
        log.warning("default account admin/admin created: change the password at first login")
    hub = AgentHub(db, pki, keepalive_timeout=settings.keepalive_timeout)
    sessions = SessionManager(load_secret(settings.data_dir / "session.key"), settings.session_minutes,
                              settings.session_max_hours)
    return AppContext(
        settings=settings, db=db, pki=pki, hub=hub, sessions=sessions,
        login_limiter=RateLimiter(settings.login_max_failures, settings.login_window_seconds),
        enroll_limiter=RateLimiter(10, 600),
    )


def discovery_answer(ctx: AppContext) -> Dict[str, Any]:
    """Build the MASTER answer to a DISCOVER datagram.

    Args:
        ctx: Application context.
    """
    return {
        "type": "MASTER",
        "version": __version__,
        "web_port": ctx.settings.web_port,
        "agent_port": ctx.settings.agent_port,
        "ca_fingerprint": ctx.pki.ca_fingerprint(),
    }


async def watch_certificate(ctx: AppContext, web: uvicorn.Server, state: Dict[str, bool]) -> None:
    """Re-issue the server certificate when it nears expiry or an address changed (DHCP).

    uvicorn cannot reload its TLS context, so the master stops and exits with
    :data:`EXIT_RESTART`; systemd restarts it with the new certificate.

    Args:
        ctx: Application context.
        web: The uvicorn server to stop.
        state: Shared flags; ``restart`` is set when a certificate was issued.
    """
    while True:
        await asyncio.sleep(CERT_CHECK_INTERVAL)
        try:
            issued = ctx.pki.ensure(ctx.settings.tls_extra_names)
        except Exception:  # noqa: BLE001 - keep serving with the current certificate
            log.exception("server certificate check failed")
            continue
        if issued:
            log.warning("server certificate re-issued: restarting the master to load it")
            state["restart"] = True
            web.should_exit = True
            return


async def serve(settings: Settings) -> int:
    """Run the master until uvicorn receives SIGINT/SIGTERM.

    Args:
        settings: Master settings.

    Returns:
        0, or :data:`EXIT_RESTART` when a new server certificate requires a restart.
    """
    ctx = build_context(settings)
    app = create_app(ctx)
    config = uvicorn.Config(
        app, host=settings.web_host, port=settings.web_port, log_config=None, access_log=False,
        ssl_keyfile=str(ctx.pki.server_key_path), ssl_certfile=str(ctx.pki.server_cert_path),
        proxy_headers=False,
    )
    web = uvicorn.Server(config)
    agents = await asyncio.start_server(
        ctx.hub.handle_stream, settings.agent_host, settings.agent_port, ssl=ctx.hub.ssl_context(),
        limit=MAX_MESSAGE_BYTES, ssl_handshake_timeout=10,
    )
    log.info("agent hub listening", extra={"port": settings.agent_port})
    discovery = None
    if settings.discovery_enabled:
        try:
            discovery = await start_discovery("0.0.0.0", settings.discovery_port,  # noqa: S104 - LAN broadcast
                                              lambda: discovery_answer(ctx))
        except OSError as exc:
            log.error("discovery disabled: cannot bind UDP port", extra={"port": settings.discovery_port,
                                                                          "error": str(exc)})
    state = {"restart": False}
    tasks = [asyncio.ensure_future(ctx.hub.monitor()), asyncio.ensure_future(PolicyEngine(ctx.db, ctx.hub).run()),
             asyncio.ensure_future(watch_certificate(ctx, web, state))]
    log.info("master started", extra={"version": __version__, "web_port": settings.web_port,
                                      "ca_fingerprint": ctx.pki.ca_fingerprint()})
    try:
        await web.serve()
    finally:
        for task in tasks:
            task.cancel()
        for task in tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await task
        if discovery is not None:
            discovery.close()
        agents.close()
        for conn in list(ctx.hub.connections.values()):
            await conn.close()
        log.info("master stopped")
    return EXIT_RESTART if state["restart"] else 0
