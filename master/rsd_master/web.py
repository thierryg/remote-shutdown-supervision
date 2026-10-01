# =============================================================================
# Remote Shutdown - LAN parental control and machine management (master/agent)
# -----------------------------------------------------------------------------
# File    : master/rsd_master/web.py
# Purpose : FastAPI application: HTTPS web console, admin REST API and agent enrollment endpoint
# Author  : Thierry Gayet <thierry.gayet@labworks.fr>
# Project : remote-shutdown (version: VERSION)
# Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
# =============================================================================
"""Web console and REST API (served by uvicorn over HTTPS on port 8443).

Compatibility: the code only uses the FastAPI / Starlette features available since
FastAPI 0.63 (Ubuntu 22.04 / Linux Mint 21 ``python3-fastapi``) and parses the JSON bodies
itself, so it behaves the same with pydantic 1 and 2.

Security model:

* every ``/api/*`` route except ``/api/login`` and ``/api/enroll`` needs a valid session
  cookie (see :mod:`rsd_master.auth`); while the default password is not changed, only the
  password change, ``/api/me`` and logout are allowed;
* every state-changing request must carry the ``X-RSD: 1`` header (anti-CSRF, on top of the
  ``SameSite=Strict`` cookie); requests flagged ``X-RSD-Background: 1`` (polling) do not
  extend the idle session;
* strict security headers: CSP without ``unsafe-inline``, HSTS, no framing, no referrer;
* every administrative action is written to the hash-chained audit log, with a diff when
  it changes a value.
"""

import hashlib
import hmac
import json
import logging
import secrets
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from starlette.concurrency import run_in_threadpool

from . import __version__
from .auth import COOKIE_NAME, RateLimiter, SessionManager, check_login, hash_password, password_problem
from .config import Settings
from .db import SECRET_MASK, Database
from .hub import AgentHub
from .pki import PKI, PKIError, cert_pem, local_addresses, not_after, serial_hex
from .policy import effective_limit

log = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).resolve().parent / "static"
CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8", ".svg": "image/svg+xml", ".png": "image/png", ".ico": "image/x-icon",
}
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
                               "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    "Strict-Transport-Security": "max-age=31536000",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    # An administration console has nothing to do in a search engine or an AI training set.
    "X-Robots-Tag": "noindex, nofollow, noarchive",
}
ROBOTS_TXT = "User-agent: *\nDisallow: /\n"
PUBLIC_API = {"/api/login", "/api/enroll"}
# Allowed while the default password has not been changed.
MUST_CHANGE_API = {"/api/me", "/api/password", "/api/logout"}
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
LIMIT_MODES = ("inherit", "custom", "unlimited")
MAX_LIMIT_MINUTES = 99 * 24 * 60 + 23 * 60 + 59  # 99 days 23 h 59 min
MAX_TOKEN_TTL_MINUTES = 7 * 24 * 60


@dataclass
class AppContext:
    """Objects shared by the routes."""

    settings: Settings
    db: Database
    pki: PKI
    hub: AgentHub
    sessions: SessionManager
    login_limiter: RateLimiter
    enroll_limiter: RateLimiter


# --- helpers -------------------------------------------------------------------
def _error(status: int, key: str) -> HTTPException:
    """Build an API error whose detail is an i18n key understood by the console.

    Args:
        status: HTTP status.
        key: i18n key (``error.*``).
    """
    return HTTPException(status_code=status, detail=key)


async def _body(request: Request) -> Dict[str, Any]:
    """Return the JSON object of a request body.

    Args:
        request: The request.

    Raises:
        HTTPException: 400 when the body is not a JSON object.
    """
    try:
        data = await request.json()
    except (ValueError, UnicodeDecodeError):
        raise _error(400, "error.bad_request") from None
    if not isinstance(data, dict):
        raise _error(400, "error.bad_request")
    return data


def _int(data: Dict[str, Any], key: str, default: int, low: int, high: int) -> int:
    """Read a bounded integer from a request body.

    Args:
        data: Request body.
        key: Field name.
        default: Value when the field is absent.
        low: Minimum.
        high: Maximum.

    Raises:
        HTTPException: 400 when the value is not an integer in range.
    """
    value = data.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise _error(400, "error.bad_request")
    return value


def _text(data: Dict[str, Any], key: str, limit: int, required: bool = False) -> str:
    """Read a bounded string from a request body.

    Args:
        data: Request body.
        key: Field name.
        limit: Maximum length.
        required: Reject an empty value.

    Raises:
        HTTPException: 400 when the value is not a string, too long or missing.
    """
    value = data.get(key, "")
    if not isinstance(value, str) or len(value) > limit or (required and not value.strip()):
        raise _error(400, "error.bad_request")
    return value.strip()


def _client_ip(request: Request) -> str:
    """Return the client address (no proxy in front of the master).

    Args:
        request: The request.
    """
    return request.client.host if request.client else "?"


def _ctx(request: Request) -> AppContext:
    """Return the application context.

    Args:
        request: The request.
    """
    return request.app.state.ctx


def _admin(request: Request) -> str:
    """Return the authenticated admin name (set in the ASGI scope by the middleware).

    The scope is used rather than ``request.state`` because old Starlette releases do not
    share ``state`` between the middleware and the endpoint.

    Args:
        request: The request.
    """
    return request.scope["rsd.user"]


def _set_session_cookie(response: Response, token: str, max_age: int) -> None:
    """Attach the session cookie.

    Args:
        response: Response to modify.
        token: Session JWT.
        max_age: Cookie lifetime in seconds.
    """
    response.set_cookie(COOKIE_NAME, token, max_age=max_age, path="/", secure=True, httponly=True, samesite="strict")


def _agent_view(ctx: AppContext, agent: Dict[str, Any], defaults: Dict[str, int], last_in: Dict[str, int],
                now: float) -> Dict[str, Any]:
    """Merge the stored and live fields of an agent for the console.

    Args:
        ctx: Application context.
        agent: Agent row.
        defaults: Runtime settings.
        last_in: Last incoming chat id per agent.
        now: Current time.
    """
    live = ctx.hub.live(agent["id"])
    up = live["status"] == "UP"
    boot = agent.get("boot_time")
    view = {k: agent[k] for k in ("id", "display_name", "hostname", "os", "arch", "agent_version", "interfaces",
                                  "first_seen", "last_seen", "limit_mode", "limit_minutes", "cert_not_after")}
    view.update(live)
    view["ip"] = live["ip"] or agent.get("last_ip")
    view["uptime"] = (now - boot) if (up and boot) else None
    view["effective_limit_minutes"] = effective_limit(agent, defaults["default_limit_minutes"])
    view["last_chat_in"] = last_in.get(agent["id"], 0)
    return view


def _metrics_token(path: str) -> str:
    """Read the metrics bearer token (empty when disabled or unreadable).

    Args:
        path: Token file (``security.metrics_token_file``).
    """
    if not path:
        return ""
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except OSError:
        log.warning("metrics token file unreadable", extra={"path": path})
        return ""


def _label(value: Any) -> str:
    """Escape a Prometheus label value.

    Args:
        value: Raw value.
    """
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def render_metrics(ctx: AppContext) -> str:
    """Render the Prometheus text exposition of the master state.

    Args:
        ctx: Application context.
    """
    now = time.time()
    agents = ctx.db.list_agents()
    defaults = ctx.db.get_settings()
    lines = [
        "# HELP rsd_info Remote Shutdown master version.", "# TYPE rsd_info gauge",
        f'rsd_info{{version="{_label(__version__)}"}} 1',
        "# HELP rsd_agents_total Enrolled machines.", "# TYPE rsd_agents_total gauge",
        f"rsd_agents_total {len(agents)}",
        "# HELP rsd_agents_up Machines connected and alive.", "# TYPE rsd_agents_up gauge",
        f"rsd_agents_up {sum(1 for a in agents if ctx.hub.is_up(a['id']))}",
        "# HELP rsd_enroll_tokens_active Usable enrollment tokens.", "# TYPE rsd_enroll_tokens_active gauge",
        f"rsd_enroll_tokens_active {len(ctx.db.list_tokens())}",
        "# HELP rsd_audit_chain_ok 1 when the audit hash chain is intact.", "# TYPE rsd_audit_chain_ok gauge",
        f"rsd_audit_chain_ok {int(ctx.db.verify_audit())}",
        "# HELP rsd_agent_up 1 when the machine is UP.", "# TYPE rsd_agent_up gauge",
    ]
    uptimes, limits = [], []
    for a in agents:
        labels = f'agent="{_label(a["id"])}",name="{_label(a["display_name"] or a["hostname"])}"'
        up = ctx.hub.is_up(a["id"])
        lines.append(f"rsd_agent_up{{{labels}}} {int(up)}")
        if up and a.get("boot_time"):
            uptimes.append(f"rsd_agent_uptime_seconds{{{labels}}} {now - a['boot_time']:.0f}")
        limits.append(f"rsd_agent_limit_seconds{{{labels}}} {effective_limit(a, defaults['default_limit_minutes']) * 60}")
    lines += ["# HELP rsd_agent_uptime_seconds Uptime since boot or resume.",
              "# TYPE rsd_agent_uptime_seconds gauge", *uptimes,
              "# HELP rsd_agent_limit_seconds Effective uptime limit (0 = unlimited).",
              "# TYPE rsd_agent_limit_seconds gauge", *limits]
    return "\n".join(lines) + "\n"


def _diff(before: Dict[str, Any], after: Dict[str, Any]) -> Dict[str, Any]:
    """Return ``{field: [old, new]}`` for the fields that changed.

    Args:
        before: Old values.
        after: New values.
    """
    return {k: [before.get(k), v] for k, v in after.items() if before.get(k) != v}


# --- application ---------------------------------------------------------------
def create_app(ctx: AppContext) -> FastAPI:
    """Build the FastAPI application.

    Args:
        ctx: Shared objects.

    Returns:
        The application.
    """
    app = FastAPI(title="Remote Shutdown master", version=__version__, docs_url=None, redoc_url=None,
                  openapi_url=None)
    app.state.ctx = ctx

    @app.middleware("http")
    async def security_middleware(request: Request, call_next):
        """Enforce authentication, CSRF header and security headers; renew the session.

        Args:
            request: Incoming request.
            call_next: Next handler.
        """
        path = request.url.path
        request.scope["rsd.user"] = None
        renew: Optional[Dict[str, Any]] = None
        if path.startswith("/api/"):
            if request.method not in SAFE_METHODS and path != "/api/enroll" and request.headers.get("x-rsd") != "1":
                return _secure(JSONResponse({"detail": "error.csrf"}, status_code=403))
            if path not in PUBLIC_API:
                claims = ctx.sessions.decode(request.cookies.get(COOKIE_NAME, ""))
                user = ctx.db.get_user(claims["sub"]) if claims else None
                if not claims or not user or user["token_version"] != claims.get("tv"):
                    return _secure(JSONResponse({"detail": "error.unauthorized"}, status_code=401))
                if user["must_change"] and path not in MUST_CHANGE_API:
                    return _secure(JSONResponse({"detail": "error.password_change_required"}, status_code=403))
                request.scope["rsd.user"] = user["username"]
                if request.headers.get("x-rsd-background") != "1" and ctx.sessions.needs_renewal(claims):
                    renew = {"user": user, "auth": claims["auth"]}
        response = await call_next(request)
        if renew and not request.scope.get("rsd.session_replaced"):
            user = renew["user"]
            token = ctx.sessions.issue(user["username"], user["token_version"], bool(user["must_change"]),
                                       renew["auth"])
            _set_session_cookie(response, token, ctx.sessions.idle)
        return _secure(response)

    def _secure(response: Response) -> Response:
        """Add the security headers to a response.

        Args:
            response: Response to modify.
        """
        for key, value in SECURITY_HEADERS.items():
            response.headers[key] = value
        if "cache-control" not in response.headers:
            response.headers["Cache-Control"] = "no-store"
        return response

    # --- static console ------------------------------------------------------
    def _static(rel: str) -> Response:
        """Serve a file of the static directory (path traversal safe).

        Args:
            rel: Path relative to the static directory.
        """
        target = (STATIC_DIR / rel).resolve()
        if STATIC_DIR not in target.parents or not target.is_file() or target.suffix not in CONTENT_TYPES:
            raise HTTPException(status_code=404)
        return Response(target.read_bytes(), media_type=CONTENT_TYPES[target.suffix],
                        headers={"Cache-Control": "no-cache"})

    @app.get("/")
    async def index() -> Response:
        """Serve the single-page console."""
        return _static("index.html")

    @app.get("/static/{rel:path}")
    async def static(rel: str) -> Response:
        """Serve a console asset.

        Args:
            rel: Asset path.
        """
        return _static(rel)

    @app.get("/robots.txt")
    async def robots() -> Response:
        """Forbid every crawler."""
        return Response(ROBOTS_TXT, media_type="text/plain; charset=utf-8")

    @app.get("/metrics")
    async def metrics(request: Request) -> Response:
        """Prometheus metrics, enabled by ``security.metrics_token_file`` (bearer token).

        Args:
            request: The request (``Authorization: Bearer <token>``).
        """
        expected = _metrics_token(ctx.settings.metrics_token_file)
        given = request.headers.get("authorization", "")
        if not expected:
            raise HTTPException(status_code=404)
        if not hmac.compare_digest(given.encode(), f"Bearer {expected}".encode()):
            raise _error(401, "error.unauthorized")
        return Response(render_metrics(ctx), media_type="text/plain; version=0.0.4; charset=utf-8")

    @app.get("/ca.crt")
    async def ca_certificate() -> Response:
        """Download the local CA certificate (to trust the console in a browser)."""
        return Response(ctx.pki.ca_pem(), media_type="application/x-x509-ca-cert",
                        headers={"Content-Disposition": 'attachment; filename="rsd-local-ca.crt"'})

    # --- session -------------------------------------------------------------
    @app.post("/api/login")
    async def login(request: Request) -> Response:
        """Open a session.

        Args:
            request: Body ``{username, password}``.
        """
        ip = _client_ip(request)
        if ctx.login_limiter.blocked(ip):
            raise _error(429, "error.too_many_attempts")
        data = await _body(request)
        username = _text(data, "username", 64)
        password = data.get("password") if isinstance(data.get("password"), str) else ""
        user = ctx.db.get_user(username)
        if not await run_in_threadpool(check_login, password[:256], user):
            ctx.login_limiter.failure(ip)
            log.warning("login failed", extra={"ip": ip, "user": username})
            ctx.db.audit(username or "?", "auth.login_failed", "", {"ip": ip})
            raise _error(401, "error.bad_credentials")
        ctx.login_limiter.reset(ip)
        token = ctx.sessions.issue(user["username"], user["token_version"], bool(user["must_change"]))
        response = JSONResponse({"username": user["username"], "must_change": bool(user["must_change"])})
        _set_session_cookie(response, token, ctx.sessions.idle)
        ctx.db.audit(user["username"], "auth.login", "", {"ip": ip})
        return response

    @app.post("/api/logout")
    async def logout(request: Request) -> Response:
        """Close every session of the current admin.

        Args:
            request: The request.
        """
        user = _admin(request)
        ctx.db.bump_token_version(user)
        ctx.db.audit(user, "auth.logout")
        request.scope["rsd.session_replaced"] = True
        response = JSONResponse({"ok": True})
        response.delete_cookie(COOKIE_NAME, path="/")
        return response

    @app.get("/api/me")
    async def me(request: Request) -> Dict[str, Any]:
        """Return the current admin and the software version.

        Args:
            request: The request.
        """
        user = ctx.db.get_user(_admin(request)) or {}
        return {"username": user.get("username"), "must_change": bool(user.get("must_change")),
                "version": __version__}

    @app.post("/api/password")
    async def change_password(request: Request) -> Response:
        """Change the password of the current admin (invalidates the other sessions).

        Args:
            request: Body ``{current, new}``.
        """
        username = _admin(request)
        data = await _body(request)
        current = data.get("current") if isinstance(data.get("current"), str) else ""
        new = data.get("new") if isinstance(data.get("new"), str) else ""
        user = ctx.db.get_user(username)
        if not await run_in_threadpool(check_login, current[:256], user):
            raise _error(403, "error.bad_credentials")
        problem = password_problem(new, username)
        if problem or len(new) > 256 or new == current:
            raise _error(400, problem or "error.password_too_common")
        ctx.db.upsert_user(username, await run_in_threadpool(hash_password, new), must_change=False)
        user = ctx.db.get_user(username)
        ctx.db.audit(username, "auth.password_changed")
        request.scope["rsd.session_replaced"] = True
        response = JSONResponse({"ok": True})
        _set_session_cookie(response, ctx.sessions.issue(username, user["token_version"], False), ctx.sessions.idle)
        return response

    # --- information ---------------------------------------------------------
    @app.get("/api/info")
    async def info() -> Dict[str, Any]:
        """Return what the console needs to build the agent installation commands."""
        names, ips = local_addresses()
        lan_ips = sorted(i for i in ips if ":" not in i and not i.startswith("127."))
        return {
            "version": __version__,
            "ca_fingerprint": ctx.pki.ca_fingerprint(),
            "web_port": ctx.settings.web_port,
            "agent_port": ctx.settings.agent_port,
            "discovery_port": ctx.settings.discovery_port if ctx.settings.discovery_enabled else None,
            "addresses": lan_ips,
            "names": sorted(n for n in names if n != "localhost"),
        }

    # --- agents --------------------------------------------------------------
    @app.get("/api/agents")
    async def list_agents() -> Dict[str, Any]:
        """List every machine with its live status."""
        defaults = ctx.db.get_settings()
        last_in = ctx.db.last_incoming_chat()
        now = time.time()
        agents = [_agent_view(ctx, a, defaults, last_in, now) for a in ctx.db.list_agents()]
        return {"agents": agents, "server_time": now}

    def _get_agent(agent_id: str) -> Dict[str, Any]:
        """Return an agent or raise 404.

        Args:
            agent_id: Agent UUID.
        """
        agent = ctx.db.get_agent(agent_id)
        if agent is None:
            raise _error(404, "error.unknown_agent")
        return agent

    @app.patch("/api/agents/{agent_id}")
    async def update_agent(agent_id: str, request: Request) -> Dict[str, Any]:
        """Rename a machine or change its uptime limit.

        Args:
            agent_id: Agent UUID.
            request: Body ``{display_name, limit_mode, limit_minutes}`` (all optional).
        """
        agent = _get_agent(agent_id)
        data = await _body(request)
        name = _text(data, "display_name", 64) if "display_name" in data else agent["display_name"]
        mode = data.get("limit_mode", agent["limit_mode"])
        if mode not in LIMIT_MODES:
            raise _error(400, "error.bad_request")
        minutes = _int(data, "limit_minutes", agent["limit_minutes"], 0, MAX_LIMIT_MINUTES)
        if mode == "custom" and minutes == 0:
            raise _error(400, "error.limit_required")
        after = {"display_name": name or agent["hostname"], "limit_mode": mode, "limit_minutes": minutes}
        ctx.db.update_agent_admin(agent_id, **after)
        ctx.db.audit(_admin(request), "agent.update", agent_id, _diff(agent, after))
        return {"ok": True}

    @app.delete("/api/agents/{agent_id}")
    async def delete_agent(agent_id: str, request: Request) -> Dict[str, Any]:
        """Forget a machine and revoke its certificate.

        Args:
            agent_id: Agent UUID.
            request: The request.
        """
        agent = _get_agent(agent_id)
        ctx.db.delete_agent(agent_id)
        await ctx.hub.disconnect(agent_id)
        ctx.db.audit(_admin(request), "agent.delete", agent_id, {"hostname": agent["hostname"]})
        return {"ok": True}

    def _shutdown_message(data: Dict[str, Any], default_delay: int) -> Dict[str, Any]:
        """Validate a shutdown request body.

        Args:
            data: Body ``{delay, message, force}``.
            default_delay: Delay used when absent.
        """
        delay = _int(data, "delay", default_delay, 0, 3600)
        message = _text(data, "message", 500)
        order = {"type": "SHUTDOWN", "delay": delay, "message": message, "force": data.get("force") is True}
        if not message:
            # Default text: rendered by the agent in the language of the computer.
            order.update(message=f"This computer will shut down in {delay} seconds.", key="shutdown.default",
                         params={"seconds": delay})
        return order

    @app.post("/api/agents/{agent_id}/shutdown")
    async def shutdown_agent(agent_id: str, request: Request) -> Dict[str, Any]:
        """Shut one machine down after a countdown.

        Args:
            agent_id: Agent UUID.
            request: Body ``{delay, message, force}``.
        """
        _get_agent(agent_id)
        message = _shutdown_message(await _body(request), ctx.db.get_settings()["shutdown_delay_seconds"])
        if not await ctx.hub.send(agent_id, dict(message)):
            raise _error(409, "error.agent_down")
        ctx.db.audit(_admin(request), "agent.shutdown", agent_id,
                     {"delay": message["delay"], "force": message["force"], "message": message["message"]})
        return {"ok": True}

    @app.post("/api/agents/{agent_id}/cancel")
    async def cancel_shutdown(agent_id: str, request: Request) -> Dict[str, Any]:
        """Cancel a pending shutdown.

        Args:
            agent_id: Agent UUID.
            request: The request.
        """
        _get_agent(agent_id)
        if not await ctx.hub.send(agent_id, {"type": "CANCEL_SHUTDOWN"}):
            raise _error(409, "error.agent_down")
        ctx.db.audit(_admin(request), "agent.cancel_shutdown", agent_id)
        return {"ok": True}

    @app.post("/api/shutdown-all")
    async def shutdown_all(request: Request) -> Dict[str, Any]:
        """Shut every UP machine down.

        Args:
            request: Body ``{delay, message, force}``.
        """
        message = _shutdown_message(await _body(request), ctx.db.get_settings()["shutdown_delay_seconds"])
        sent = await ctx.hub.broadcast(message)
        ctx.db.audit(_admin(request), "agent.shutdown_all", "", {"delay": message["delay"], "agents": sent})
        return {"ok": True, "agents": sent}

    @app.post("/api/agents/{agent_id}/message")
    async def popup(agent_id: str, request: Request) -> Dict[str, Any]:
        """Show a popup message on a machine.

        Args:
            agent_id: Agent UUID.
            request: Body ``{text}``.
        """
        _get_agent(agent_id)
        text = _text(await _body(request), "text", 1000, required=True)
        if not await ctx.hub.send(agent_id, {"type": "MESSAGE", "title": "Remote Shutdown", "text": text}):
            raise _error(409, "error.agent_down")
        ctx.db.audit(_admin(request), "agent.message", agent_id, {"text": text})
        return {"ok": True}

    @app.get("/api/agents/{agent_id}/chat")
    async def get_chat(agent_id: str, after: int = 0) -> Dict[str, Any]:
        """Return the chat history of a machine.

        Args:
            agent_id: Agent UUID.
            after: Only messages with a greater id.
        """
        _get_agent(agent_id)
        return {"messages": ctx.db.list_chat(agent_id, after_id=max(0, after))}

    @app.post("/api/agents/{agent_id}/chat")
    async def post_chat(agent_id: str, request: Request) -> Dict[str, Any]:
        """Send a chat message to the user of a machine.

        Args:
            agent_id: Agent UUID.
            request: Body ``{text}``.
        """
        _get_agent(agent_id)
        text = _text(await _body(request), "text", 1000, required=True)
        user = _admin(request)
        if not await ctx.hub.send(agent_id, {"type": "CHAT", "text": text, "author": user}):
            raise _error(409, "error.agent_down")
        return {"message": ctx.db.add_chat(agent_id, "out", user, text)}

    # --- settings ------------------------------------------------------------
    @app.get("/api/settings")
    async def get_settings() -> Dict[str, Any]:
        """Return the runtime parameters."""
        return ctx.db.get_settings()

    @app.put("/api/settings")
    async def put_settings(request: Request) -> Dict[str, Any]:
        """Update the runtime parameters.

        Args:
            request: Body with any of ``default_limit_minutes``, ``warning_minutes``,
                ``shutdown_delay_seconds``.
        """
        before = ctx.db.get_settings()
        data = await _body(request)
        after = {
            "default_limit_minutes": _int(data, "default_limit_minutes", before["default_limit_minutes"], 0,
                                          MAX_LIMIT_MINUTES),
            "warning_minutes": _int(data, "warning_minutes", before["warning_minutes"], 0, 120),
            "shutdown_delay_seconds": _int(data, "shutdown_delay_seconds", before["shutdown_delay_seconds"], 0, 3600),
        }
        ctx.db.set_settings(after)
        ctx.db.audit(_admin(request), "settings.update", "", _diff(before, after))
        return after

    # --- enrollment tokens ---------------------------------------------------
    @app.get("/api/tokens")
    async def list_tokens() -> Dict[str, Any]:
        """List the usable enrollment tokens (never the token values)."""
        ctx.db.purge_tokens()
        return {"tokens": ctx.db.list_tokens()}

    @app.post("/api/tokens")
    async def create_token(request: Request) -> Dict[str, Any]:
        """Create an enrollment token; its value is returned once and never stored in clear.

        Args:
            request: Body ``{label, ttl_minutes, uses}``.
        """
        data = await _body(request)
        label = _text(data, "label", 64)
        ttl = _int(data, "ttl_minutes", 60, 5, MAX_TOKEN_TTL_MINUTES)
        uses = _int(data, "uses", 1, 1, 100)
        token = secrets.token_urlsafe(18)
        token_id = ctx.db.create_token(hashlib.sha256(token.encode()).hexdigest(), label, ttl * 60, uses)
        ctx.db.audit(_admin(request), "token.create", str(token_id),
                     {"label": label, "ttl_minutes": ttl, "uses": uses, "token": SECRET_MASK})
        return {"id": token_id, "token": token, "expires": time.time() + ttl * 60, "uses_left": uses}

    @app.delete("/api/tokens/{token_id}")
    async def delete_token(token_id: int, request: Request) -> Dict[str, Any]:
        """Revoke an enrollment token.

        Args:
            token_id: Token row id.
            request: The request.
        """
        if not ctx.db.delete_token(token_id):
            raise _error(404, "error.not_found")
        ctx.db.audit(_admin(request), "token.delete", str(token_id))
        return {"ok": True}

    # --- audit ---------------------------------------------------------------
    @app.get("/api/audit")
    async def audit(limit: int = 200) -> Dict[str, Any]:
        """Return the latest audit entries and the integrity of the hash chain.

        Args:
            limit: Maximum number of entries (1..1000).
        """
        return {"entries": ctx.db.list_audit(max(1, min(limit, 1000))), "chain_ok": ctx.db.verify_audit()}

    # --- enrollment (agents, token-authenticated) -----------------------------
    @app.post("/api/enroll")
    async def enroll(request: Request) -> Dict[str, Any]:
        """Issue a client certificate to a new agent presenting a valid enrollment token.

        Args:
            request: Body ``{token, csr, hostname}``.
        """
        ip = _client_ip(request)
        if ctx.enroll_limiter.blocked(ip):
            raise _error(429, "error.too_many_attempts")
        data = await _body(request)
        token = data.get("token") if isinstance(data.get("token"), str) else ""
        csr = data.get("csr") if isinstance(data.get("csr"), str) else ""
        hostname = _text(data, "hostname", 255) or "unknown"
        if not token or len(token) > 128 or not csr or len(csr) > 16384:
            ctx.enroll_limiter.failure(ip)
            raise _error(400, "error.bad_request")
        if not ctx.db.consume_token(hashlib.sha256(token.encode()).hexdigest()):
            ctx.enroll_limiter.failure(ip)
            log.warning("enrollment refused: invalid token", extra={"ip": ip, "hostname": hostname})
            ctx.db.audit("system", "agent.enroll_refused", "", {"ip": ip, "hostname": hostname})
            raise _error(403, "error.invalid_token")
        agent_id = str(uuid.uuid4())
        try:
            cert = ctx.pki.sign_agent_csr(csr, agent_id)
        except PKIError as exc:
            log.warning("enrollment refused: bad CSR", extra={"ip": ip, "error": str(exc)})
            raise _error(400, "error.bad_csr") from None
        ctx.db.create_agent(agent_id, hostname, serial_hex(cert), not_after(cert).timestamp(), ip)
        ctx.db.audit("system", "agent.enroll", agent_id, {"ip": ip, "hostname": hostname})
        log.info("agent enrolled", extra={"agent": agent_id, "ip": ip, "hostname": hostname})
        return {"agent_id": agent_id, "cert": cert_pem(cert), "ca": ctx.pki.ca_pem(),
                "agent_port": ctx.settings.agent_port}

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException) -> Response:
        """Render API errors as ``{"detail": key}`` JSON.

        Args:
            request: The request.
            exc: The error.
        """
        del request
        detail = exc.detail if isinstance(exc.detail, str) else "error.unexpected"
        return JSONResponse({"detail": detail}, status_code=exc.status_code)

    return app


def dumps(data: Any) -> str:
    """Serialize to JSON (used by the CLI ``info`` command).

    Args:
        data: Data to serialize.
    """
    return json.dumps(data, indent=2, default=str)
