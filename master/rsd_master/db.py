# =============================================================================
# Remote Shutdown - LAN parental control and machine management (master/agent)
# -----------------------------------------------------------------------------
# File    : master/rsd_master/db.py
# Purpose : SQLite (WAL) persistence: admins, agents, enrollment tokens, settings, chat, audit
# Author  : Thierry Gayet <thierry.gayet@labworks.fr>
# Project : remote-shutdown (version: VERSION)
# Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
# =============================================================================
"""SQLite persistence of the master.

A new connection is opened for every operation: SQLite stays fast at this data volume
(a home or a classroom: tens of machines) and no connection is shared across threads.

Stored data:

* ``users``: web administrators (bcrypt hash, "must change password" flag, token version
  used to invalidate every session at logout or password change);
* ``agents``: enrolled machines, identified by the UUID written in their certificate CN;
* ``enroll_tokens``: one-time (or N-times) enrollment tokens, stored as SHA-256 hashes;
* ``settings``: runtime parameters edited from the console (uptime limit...);
* ``chat``: messages exchanged with the users of the machines;
* ``audit``: tamper-evident log of every administrative action, each row chained to the
  previous one with SHA-256 (see :meth:`Database.verify_audit`).
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username      TEXT PRIMARY KEY,
    pw_hash       TEXT NOT NULL,
    must_change   INTEGER NOT NULL DEFAULT 0,
    token_version INTEGER NOT NULL DEFAULT 0,
    created       REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS agents (
    id                TEXT PRIMARY KEY,
    display_name      TEXT NOT NULL DEFAULT '',
    hostname          TEXT NOT NULL DEFAULT '',
    os                TEXT NOT NULL DEFAULT '',
    arch              TEXT NOT NULL DEFAULT '',
    agent_version     TEXT NOT NULL DEFAULT '',
    interfaces        TEXT NOT NULL DEFAULT '[]',
    boot_time         REAL,
    first_seen        REAL NOT NULL,
    last_seen         REAL,
    last_ip           TEXT NOT NULL DEFAULT '',
    cert_serial       TEXT NOT NULL,
    cert_not_after    REAL NOT NULL,
    limit_mode        TEXT NOT NULL DEFAULT 'inherit',
    limit_minutes     INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS enroll_tokens (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT NOT NULL UNIQUE,
    label      TEXT NOT NULL DEFAULT '',
    created    REAL NOT NULL,
    expires    REAL NOT NULL,
    uses_left  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS chat (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        REAL NOT NULL,
    agent_id  TEXT NOT NULL,
    direction TEXT NOT NULL,
    author    TEXT NOT NULL,
    text      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS chat_agent ON chat(agent_id, id);
CREATE TABLE IF NOT EXISTS audit (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        REAL NOT NULL,
    actor     TEXT NOT NULL,
    action    TEXT NOT NULL,
    target    TEXT NOT NULL DEFAULT '',
    details   TEXT NOT NULL DEFAULT '{}',
    prev_hash TEXT NOT NULL,
    hash      TEXT NOT NULL
);
"""

# Runtime parameters and their defaults (all integers, in minutes or seconds as named).
DEFAULT_SETTINGS: Dict[str, int] = {
    "default_limit_minutes": 0,      # global uptime limit, 0 = unlimited
    "warning_minutes": 5,            # popup this long before the limit
    "shutdown_delay_seconds": 60,    # countdown shown before a policy or manual shutdown
}

# Agent columns returned to the API (everything but the certificate details).
_AGENT_COLUMNS = (
    "id", "display_name", "hostname", "os", "arch", "agent_version", "interfaces", "boot_time",
    "first_seen", "last_seen", "last_ip", "cert_serial", "cert_not_after", "limit_mode", "limit_minutes",
)

GENESIS_HASH = "0" * 64
# Replacement of a secret value in the audit log (a mask, not a credential).
SECRET_MASK = "***"  # noqa: S105  # nosec B105


class Database:
    """Thin data-access layer over one SQLite file."""

    def __init__(self, path: Path) -> None:
        """Remember the database path (the file is created by :meth:`init`).

        Args:
            path: Path of the SQLite file.
        """
        self.path = Path(path)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        """Open a connection, commit on success, roll back on error, always close.

        Yields:
            A connection whose rows behave like mappings.
        """
        conn = sqlite3.connect(str(self.path), timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init(self) -> None:
        """Create the file, enable WAL mode and create the schema (idempotent)."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.executescript(SCHEMA)

    # --- users ---------------------------------------------------------------
    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        """Return a web administrator, or None.

        Args:
            username: Login name.
        """
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        return dict(row) if row else None

    def count_users(self) -> int:
        """Return the number of web administrators."""
        with self.connect() as conn:
            return int(conn.execute("SELECT COUNT(*) FROM users").fetchone()[0])

    def upsert_user(self, username: str, pw_hash: str, must_change: bool) -> None:
        """Create a user or replace its password; every existing session is invalidated.

        Args:
            username: Login name.
            pw_hash: bcrypt hash of the password.
            must_change: Force a password change at the next login.
        """
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO users (username, pw_hash, must_change, token_version, created) VALUES (?, ?, ?, 0, ?) "
                "ON CONFLICT(username) DO UPDATE SET pw_hash = excluded.pw_hash, "
                "must_change = excluded.must_change, token_version = users.token_version + 1",
                (username, pw_hash, int(must_change), time.time()),
            )

    def bump_token_version(self, username: str) -> None:
        """Invalidate every session of a user (logout).

        Args:
            username: Login name.
        """
        with self.connect() as conn:
            conn.execute("UPDATE users SET token_version = token_version + 1 WHERE username = ?", (username,))

    # --- agents --------------------------------------------------------------
    def create_agent(self, agent_id: str, hostname: str, serial: str, not_after: float, ip: str) -> None:
        """Register a freshly enrolled agent.

        Args:
            agent_id: UUID written in the certificate CN.
            hostname: Hostname announced at enrollment.
            serial: Certificate serial number (hex).
            not_after: Certificate expiry (Unix time).
            ip: Address the enrollment came from.
        """
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO agents (id, display_name, hostname, first_seen, last_ip, cert_serial, cert_not_after) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (agent_id, hostname, hostname, time.time(), ip, serial, not_after),
            )

    def update_agent_cert(self, agent_id: str, serial: str, not_after: float) -> None:
        """Record a renewed certificate (the previous one is no longer accepted).

        Args:
            agent_id: Agent UUID.
            serial: New serial number (hex).
            not_after: New expiry (Unix time).
        """
        with self.connect() as conn:
            conn.execute(
                "UPDATE agents SET cert_serial = ?, cert_not_after = ? WHERE id = ?", (serial, not_after, agent_id)
            )

    def get_agent(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Return one agent with its decoded interfaces, or None.

        Args:
            agent_id: Agent UUID.
        """
        with self.connect() as conn:
            # The column list is a constant, the value is bound.
            row = conn.execute(f"SELECT {', '.join(_AGENT_COLUMNS)} FROM agents WHERE id = ?",  # noqa: S608  # nosec B608
                               (agent_id,)).fetchone()
        return _decode_agent(row) if row else None

    def list_agents(self) -> List[Dict[str, Any]]:
        """Return every agent, sorted by display name."""
        with self.connect() as conn:
            rows = conn.execute(
                f"SELECT {', '.join(_AGENT_COLUMNS)} FROM agents ORDER BY display_name COLLATE NOCASE"  # noqa: S608  # nosec B608
            ).fetchall()
        return [_decode_agent(r) for r in rows]

    def update_agent_info(self, agent_id: str, **fields: Any) -> None:
        """Update the facts reported by an agent (hostname, OS, interfaces, boot time...).

        Args:
            agent_id: Agent UUID.
            **fields: Columns to update; ``interfaces`` is JSON-encoded.

        Raises:
            ValueError: For an unknown column.
        """
        allowed = {"hostname", "os", "arch", "agent_version", "interfaces", "boot_time", "last_seen", "last_ip"}
        if not fields:
            return
        unknown = set(fields) - allowed
        if unknown:
            raise ValueError(f"unknown agent fields: {sorted(unknown)}")
        if "interfaces" in fields:
            fields["interfaces"] = json.dumps(fields["interfaces"])
        assignments = ", ".join(f"{k} = ?" for k in fields)
        with self.connect() as conn:
            # The column names are checked against a whitelist above; the values are bound.
            conn.execute(f"UPDATE agents SET {assignments} WHERE id = ?",  # noqa: S608  # nosec B608
                         (*fields.values(), agent_id))

    def update_agent_admin(self, agent_id: str, display_name: str, limit_mode: str, limit_minutes: int) -> None:
        """Update the administrator-owned fields of an agent.

        Args:
            agent_id: Agent UUID.
            display_name: Name shown in the console.
            limit_mode: ``inherit``, ``custom`` or ``unlimited``.
            limit_minutes: Uptime limit in minutes when the mode is ``custom``.
        """
        with self.connect() as conn:
            conn.execute(
                "UPDATE agents SET display_name = ?, limit_mode = ?, limit_minutes = ? WHERE id = ?",
                (display_name, limit_mode, limit_minutes, agent_id),
            )

    def delete_agent(self, agent_id: str) -> bool:
        """Forget an agent: its certificate is no longer accepted (revocation).

        Args:
            agent_id: Agent UUID.

        Returns:
            True when a row was deleted.
        """
        with self.connect() as conn:
            conn.execute("DELETE FROM chat WHERE agent_id = ?", (agent_id,))
            return conn.execute("DELETE FROM agents WHERE id = ?", (agent_id,)).rowcount > 0

    # --- enrollment tokens ---------------------------------------------------
    def create_token(self, token_hash: str, label: str, ttl_seconds: int, uses: int) -> int:
        """Store an enrollment token hash.

        Args:
            token_hash: SHA-256 (hex) of the token; the clear token is never stored.
            label: Free text shown in the console.
            ttl_seconds: Validity duration.
            uses: Number of enrollments allowed.

        Returns:
            The token row id.
        """
        now = time.time()
        with self.connect() as conn:
            cur = conn.execute(
                "INSERT INTO enroll_tokens (token_hash, label, created, expires, uses_left) VALUES (?, ?, ?, ?, ?)",
                (token_hash, label, now, now + ttl_seconds, uses),
            )
            return int(cur.lastrowid)

    def consume_token(self, token_hash: str) -> bool:
        """Atomically use one enrollment of a valid token.

        Args:
            token_hash: SHA-256 (hex) of the presented token.

        Returns:
            True when the token was valid (not expired, uses left) and one use was consumed.
        """
        with self.connect() as conn:
            cur = conn.execute(
                "UPDATE enroll_tokens SET uses_left = uses_left - 1 "
                "WHERE token_hash = ? AND uses_left > 0 AND expires > ?",
                (token_hash, time.time()),
            )
            return cur.rowcount == 1

    def list_tokens(self) -> List[Dict[str, Any]]:
        """Return the tokens that are still usable (the hash is not returned)."""
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT id, label, created, expires, uses_left FROM enroll_tokens "
                "WHERE uses_left > 0 AND expires > ? ORDER BY created DESC",
                (time.time(),),
            ).fetchall()
        return [dict(r) for r in rows]

    def delete_token(self, token_id: int) -> bool:
        """Revoke an enrollment token.

        Args:
            token_id: Row id.

        Returns:
            True when a row was deleted.
        """
        with self.connect() as conn:
            return conn.execute("DELETE FROM enroll_tokens WHERE id = ?", (token_id,)).rowcount > 0

    def purge_tokens(self) -> None:
        """Delete the expired or exhausted tokens."""
        with self.connect() as conn:
            conn.execute("DELETE FROM enroll_tokens WHERE uses_left <= 0 OR expires <= ?", (time.time(),))

    # --- settings ------------------------------------------------------------
    def get_settings(self) -> Dict[str, int]:
        """Return the runtime parameters, defaults included."""
        values = dict(DEFAULT_SETTINGS)
        with self.connect() as conn:
            for row in conn.execute("SELECT key, value FROM settings"):
                if row["key"] in values:
                    values[row["key"]] = int(row["value"])
        return values

    def set_settings(self, values: Dict[str, int]) -> None:
        """Store runtime parameters (unknown keys are ignored).

        Args:
            values: Parameters to store.
        """
        with self.connect() as conn:
            for key, value in values.items():
                if key in DEFAULT_SETTINGS:
                    conn.execute(
                        "INSERT INTO settings (key, value) VALUES (?, ?) "
                        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                        (key, str(int(value))),
                    )

    # --- chat ----------------------------------------------------------------
    def add_chat(self, agent_id: str, direction: str, author: str, text: str) -> Dict[str, Any]:
        """Store a chat message.

        Args:
            agent_id: Agent UUID.
            direction: ``out`` (admin to machine) or ``in`` (machine user to admin).
            author: Admin login or local user name.
            text: Message text.

        Returns:
            The stored message.
        """
        now = time.time()
        with self.connect() as conn:
            cur = conn.execute(
                "INSERT INTO chat (ts, agent_id, direction, author, text) VALUES (?, ?, ?, ?, ?)",
                (now, agent_id, direction, author, text),
            )
            msg_id = int(cur.lastrowid)
        return {"id": msg_id, "ts": now, "agent_id": agent_id, "direction": direction, "author": author, "text": text}

    def list_chat(self, agent_id: str, after_id: int = 0, limit: int = 200) -> List[Dict[str, Any]]:
        """Return the chat messages of an agent, oldest first.

        Args:
            agent_id: Agent UUID.
            after_id: Only messages with a greater id (incremental polling).
            limit: Maximum number of messages.
        """
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM (SELECT * FROM chat WHERE agent_id = ? AND id > ? ORDER BY id DESC LIMIT ?) "
                "ORDER BY id",
                (agent_id, after_id, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def last_incoming_chat(self) -> Dict[str, int]:
        """Return the id of the last incoming message per agent (unread badge of the console).

        Returns:
            Mapping agent id -> id of its last incoming message.
        """
        with self.connect() as conn:
            rows = conn.execute("SELECT agent_id, MAX(id) AS last FROM chat WHERE direction = 'in' GROUP BY agent_id")
            return {r["agent_id"]: int(r["last"]) for r in rows}

    # --- audit ---------------------------------------------------------------
    def audit(self, actor: str, action: str, target: str = "", details: Optional[Dict[str, Any]] = None) -> None:
        """Append a tamper-evident audit entry.

        The hash covers the previous hash and every field of the row, so editing or deleting a
        row breaks the chain (detected by :meth:`verify_audit`).

        Args:
            actor: Admin login, ``policy`` or ``system``.
            action: Action name (``agent.shutdown``, ``settings.update``...).
            target: Object of the action (agent id, token id...).
            details: Extra data, e.g. a before/after diff. Never put a secret here.
        """
        body = json.dumps(details or {}, sort_keys=True, default=str)
        now = time.time()
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
            prev = row["hash"] if row else GENESIS_HASH
            digest = _audit_hash(prev, now, actor, action, target, body)
            conn.execute(
                "INSERT INTO audit (ts, actor, action, target, details, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (now, actor, action, target, body, prev, digest),
            )

    def list_audit(self, limit: int = 200) -> List[Dict[str, Any]]:
        """Return the most recent audit entries, newest first.

        Args:
            limit: Maximum number of entries.
        """
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        result = []
        for r in rows:
            item = dict(r)
            item["details"] = json.loads(item["details"])
            result.append(item)
        return result

    def verify_audit(self) -> bool:
        """Recompute the whole hash chain.

        Returns:
            True when no row was altered, removed or reordered.
        """
        prev = GENESIS_HASH
        with self.connect() as conn:
            for r in conn.execute("SELECT * FROM audit ORDER BY id"):
                expected = _audit_hash(prev, r["ts"], r["actor"], r["action"], r["target"], r["details"])
                if r["prev_hash"] != prev or r["hash"] != expected:
                    return False
                prev = r["hash"]
        return True


def _audit_hash(prev: str, ts: float, actor: str, action: str, target: str, details: str) -> str:
    """Return the SHA-256 chaining hash of an audit row.

    Args:
        prev: Hash of the previous row (or the genesis hash).
        ts: Timestamp.
        actor: Actor.
        action: Action.
        target: Target.
        details: JSON-encoded details.
    """
    material = json.dumps([prev, repr(ts), actor, action, target, details], ensure_ascii=False)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _decode_agent(row: sqlite3.Row) -> Dict[str, Any]:
    """Convert an agent row to a dict with decoded interfaces.

    Args:
        row: The database row.
    """
    item = dict(row)
    try:
        item["interfaces"] = json.loads(item["interfaces"] or "[]")
    except ValueError:
        item["interfaces"] = []
    return item
