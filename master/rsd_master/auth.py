# =============================================================================
# Remote Shutdown - LAN parental control and machine management (master/agent)
# -----------------------------------------------------------------------------
# File    : master/rsd_master/auth.py
# Purpose : Admin authentication: bcrypt passwords, short-lived JWT sessions, login rate limit
# Author  : Thierry Gayet <thierry.gayet@labworks.fr>
# Project : remote-shutdown (version: VERSION)
# Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
# =============================================================================
"""Authentication primitives of the web console.

* Passwords are hashed with bcrypt (cost 12). The default ``admin`` / ``admin`` account is
  flagged "must change": until the password is changed, the API only accepts the password
  change, ``/api/me`` and logout.
* A session is an HS256 JWT in an ``HttpOnly; Secure; SameSite=Strict`` cookie. It expires
  after ``session_minutes`` of inactivity (sliding renewal, background polling excluded) and
  in any case ``session_max_hours`` after login. The ``tv`` claim carries the user's token
  version: logout and password changes increment it, which invalidates every issued token.
* The JWT secret is random, generated at first start, stored 0600 in the data directory.
"""

from __future__ import annotations

import os
import secrets
import threading
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Deque, Dict, Optional

import bcrypt
import jwt

ALGORITHM = "HS256"
COOKIE_NAME = "rsd_session"
MIN_PASSWORD_LENGTH = 10


def hash_password(password: str) -> str:
    """Hash a password with bcrypt.

    Args:
        password: Clear-text password.

    Returns:
        The bcrypt hash (text).
    """
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("ascii")


def check_password(password: str, pw_hash: str) -> bool:
    """Verify a password against its bcrypt hash in constant time.

    Args:
        password: Clear-text candidate.
        pw_hash: Stored hash.

    Returns:
        True when the password matches.
    """
    try:
        return bcrypt.checkpw(password.encode("utf-8"), pw_hash.encode("ascii"))
    except ValueError:
        return False


# A valid hash of a random string: comparing against it when the user does not exist keeps the
# response time identical, so the login form does not reveal which accounts exist.
_DUMMY_HASH = hash_password(secrets.token_hex(16))


def check_login(password: str, user: Optional[Dict[str, Any]]) -> bool:
    """Verify credentials without leaking whether the account exists.

    Args:
        password: Clear-text candidate.
        user: The user row, or None when unknown.

    Returns:
        True for a known user with the right password.
    """
    if user is None:
        check_password(password, _DUMMY_HASH)
        return False
    return check_password(password, user["pw_hash"])


def password_problem(password: str, username: str) -> Optional[str]:
    """Return an i18n error key when a new password is too weak, else None.

    Args:
        password: Proposed password.
        username: Account name (the password must differ from it).
    """
    if len(password) < MIN_PASSWORD_LENGTH:
        return "error.password_too_short"
    if password.lower() in {username.lower(), "admin", "password", "motdepasse"}:
        return "error.password_too_common"
    return None


def load_secret(path: Path) -> bytes:
    """Return the JWT signing secret, creating it (0600) at first use.

    Args:
        path: Secret file.
    """
    try:
        data = path.read_bytes()
        if len(data) >= 32:
            return data
    except FileNotFoundError:
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    data = secrets.token_bytes(48)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    return data


class SessionManager:
    """Issue and validate session tokens."""

    def __init__(self, secret: bytes, idle_minutes: int, max_hours: int) -> None:
        """Configure the session lifetimes.

        Args:
            secret: HMAC key.
            idle_minutes: Inactivity timeout.
            max_hours: Absolute lifetime since login.
        """
        self.secret = secret
        self.idle = idle_minutes * 60
        self.max_age = max_hours * 3600

    def issue(self, username: str, token_version: int, must_change: bool, auth_time: Optional[float] = None) -> str:
        """Create a session token.

        Args:
            username: Login name.
            token_version: Current token version of the user.
            must_change: Password change still required.
            auth_time: Login time (kept across renewals); now by default.

        Returns:
            The encoded JWT.
        """
        now = int(time.time())
        auth = int(auth_time or now)
        claims = {
            "sub": username,
            "iat": now,
            "exp": min(now + self.idle, auth + self.max_age),
            "auth": auth,
            "tv": token_version,
            "mc": bool(must_change),
        }
        token = jwt.encode(claims, self.secret, algorithm=ALGORITHM)
        return token.decode("ascii") if isinstance(token, bytes) else token

    def decode(self, token: str) -> Optional[Dict[str, Any]]:
        """Validate a token.

        Args:
            token: Encoded JWT.

        Returns:
            The claims, or None when the token is invalid or expired.
        """
        try:
            claims = jwt.decode(token, self.secret, algorithms=[ALGORITHM])
        except jwt.PyJWTError:
            return None
        if not isinstance(claims.get("sub"), str) or time.time() > claims.get("auth", 0) + self.max_age:
            return None
        return claims

    def needs_renewal(self, claims: Dict[str, Any]) -> bool:
        """Tell whether a token should be re-issued (less than half of the idle time left).

        Args:
            claims: Decoded claims.
        """
        return claims["exp"] - time.time() < self.idle / 2


class RateLimiter:
    """Sliding-window failure counter per key (client IP)."""

    def __init__(self, max_failures: int, window_seconds: int) -> None:
        """Configure the limiter.

        Args:
            max_failures: Failures allowed in the window.
            window_seconds: Window length.
        """
        self.max_failures = max_failures
        self.window = window_seconds
        self._events: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def _prune(self, key: str, now: float) -> Deque[float]:
        """Drop the events older than the window and return the remaining ones.

        Args:
            key: Client key.
            now: Current time.
        """
        events = self._events[key]
        while events and now - events[0] > self.window:
            events.popleft()
        return events

    def blocked(self, key: str) -> bool:
        """Tell whether a client is currently blocked.

        Args:
            key: Client key.
        """
        with self._lock:
            return len(self._prune(key, time.time())) >= self.max_failures

    def failure(self, key: str) -> None:
        """Record a failure.

        Args:
            key: Client key.
        """
        with self._lock:
            now = time.time()
            self._prune(key, now).append(now)

    def reset(self, key: str) -> None:
        """Forget the failures of a client (successful login).

        Args:
            key: Client key.
        """
        with self._lock:
            self._events.pop(key, None)
