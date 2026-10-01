# =============================================================================
# Remote Shutdown - LAN parental control and machine management (master/agent)
# -----------------------------------------------------------------------------
# File    : master/rsd_master/cli.py
# Purpose : rsd-master command line: serve, info, reset-password, create-token, verify-audit, version
# Author  : Thierry Gayet <thierry.gayet@labworks.fr>
# Project : remote-shutdown (version: VERSION)
# Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
# =============================================================================
"""``rsd-master`` command line.

Exit codes (same table as the shell scripts): 0 OK, 1 runtime, 2 usage, 5 configuration,
7 state (e.g. broken audit chain); ``serve`` exits with 75 to be restarted by systemd after
re-issuing its server certificate.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import hashlib
import json
import os
import pwd
import secrets
import sqlite3
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from typing import List, Optional

from . import __version__
from .auth import check_password, hash_password, password_problem
from .config import load_settings
from .db import SECRET_MASK, Database
from .logs import setup_logging
from .pki import PKI

E_OK, E_RUNTIME, E_USAGE, E_CONFIG, E_STATE = 0, 1, 2, 5, 7
SERVICE_USER = "rsd-master"


def _drop_privileges(data_dir: Path) -> None:
    """Switch to the service account when an admin runs the CLI as root.

    The database and the PKI belong to ``rsd-master``; a root-owned file created by
    ``sudo rsd-master ...`` would later be unreadable by the service.

    Args:
        data_dir: Data directory; the switch happens only when it belongs to the account.
    """
    if os.geteuid() != 0:
        return
    try:
        account = pwd.getpwnam(SERVICE_USER)
        if data_dir.stat().st_uid != account.pw_uid:
            return
    except (KeyError, OSError):
        return
    os.setgroups([])
    os.setgid(account.pw_gid)
    os.setuid(account.pw_uid)


def _parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(prog="rsd-master", description="Remote Shutdown master service.")
    parser.add_argument("--config", type=Path, help="INI file (default /etc/rsd-master/master.ini, env RSD_CONFIG)")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("serve", help="run the service (default)")
    sub.add_parser("info", help="print the CA fingerprint, ports and agent enrollment hints")
    reset = sub.add_parser("reset-password", help="set the password of a web administrator")
    reset.add_argument("--user", default="admin")
    reset.add_argument("--temporary", action="store_true", help="force a change at the next login")
    reset.add_argument("--password-stdin", action="store_true",
                       help="read the password from the first line of stdin (automation, e.g. Ansible)")
    check = sub.add_parser("check-password", help="exit 0 when the password (first line of stdin) is current")
    check.add_argument("--user", default="admin")
    token = sub.add_parser("create-token", help="create an enrollment token (printed once)")
    token.add_argument("--label", default="cli")
    token.add_argument("--ttl", type=int, default=60, help="validity in minutes (default 60)")
    token.add_argument("--uses", type=int, default=1, help="number of enrollments (default 1)")
    sub.add_parser("verify-audit", help="check the integrity of the audit hash chain")
    status = sub.add_parser("status", help="summary: agents (UP by last keepalive), tokens, audit chain")
    status.add_argument("--json", action="store_true", help="machine-readable output")
    backup = sub.add_parser("backup", help="archive the database, the PKI and the session key (tar.gz, 0600)")
    backup.add_argument("--dir", type=Path, help="destination (default <data_dir>/backups)")
    backup.add_argument("--keep", type=int, default=14, help="archives to keep (default 14)")
    sub.add_parser("version", help="print the version")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Entry point.

    Args:
        argv: Arguments (defaults to ``sys.argv[1:]``).

    Returns:
        The exit code.
    """
    args = _parser().parse_args(argv)
    command = args.command or "serve"
    if command == "version":
        print(__version__)
        return E_OK
    try:
        settings = load_settings(args.config)
    except ValueError as exc:
        print(f"rsd-master: {exc}", file=sys.stderr)
        return E_CONFIG
    setup_logging(settings.log_level, settings.log_json)

    if command == "serve":
        from .server import serve

        try:
            return asyncio.run(serve(settings))
        except KeyboardInterrupt:
            return E_OK

    _drop_privileges(settings.data_dir)
    db = Database(settings.db_path)
    db.init()
    if command == "info":
        pki = PKI(settings.pki_dir)
        if not pki.ca_cert_path.exists():
            print("rsd-master: the CA does not exist yet (start the service once)", file=sys.stderr)
            return E_STATE
        print(json.dumps({
            "version": __version__,
            "ca_fingerprint": pki.ca_fingerprint(),
            "web_port": settings.web_port,
            "agent_port": settings.agent_port,
            "discovery_port": settings.discovery_port if settings.discovery_enabled else None,
            "enroll_example": f"sudo rsd-agent enroll --token <TOKEN> --fingerprint {pki.ca_fingerprint()}",
        }, indent=2))
        return E_OK
    if command == "reset-password":
        if args.password_stdin:
            password = sys.stdin.readline().rstrip("\r\n")
        else:
            password = getpass.getpass(f"New password for {args.user}: ")
            if getpass.getpass("Repeat: ") != password:
                print("rsd-master: passwords differ", file=sys.stderr)
                return E_USAGE
        problem = password_problem(password, args.user)
        if problem:
            print(f"rsd-master: password refused ({problem})", file=sys.stderr)
            return E_USAGE
        db.upsert_user(args.user, hash_password(password), must_change=args.temporary)
        db.audit("cli", "auth.password_reset", args.user)
        print(f"password of {args.user} updated; every session was closed")
        return E_OK
    if command == "check-password":
        # Exit 0: valid and not flagged "must change"; 1: wrong, unknown user, or must change.
        user = db.get_user(args.user)
        password = sys.stdin.readline().rstrip("\r\n")
        return E_OK if user and not user["must_change"] and check_password(password, user["pw_hash"]) else E_RUNTIME
    if command == "create-token":
        if not (5 <= args.ttl <= 10080 and 1 <= args.uses <= 100):
            print("rsd-master: --ttl must be 5..10080 and --uses 1..100", file=sys.stderr)
            return E_USAGE
        token = secrets.token_urlsafe(18)
        token_id = db.create_token(hashlib.sha256(token.encode()).hexdigest(), args.label, args.ttl * 60, args.uses)
        db.audit("cli", "token.create", str(token_id), {"label": args.label, "ttl_minutes": args.ttl,
                                                        "uses": args.uses, "token": SECRET_MASK})
        print(token)
        return E_OK
    if command == "verify-audit":
        ok = db.verify_audit()
        print("audit chain OK" if ok else "audit chain BROKEN")
        return E_OK if ok else E_STATE
    if command == "status":
        return _status(db, settings, args.json)
    if command == "backup":
        if not 1 <= args.keep <= 1000:
            print("rsd-master: --keep must be 1..1000", file=sys.stderr)
            return E_USAGE
        try:
            archive = create_backup(settings, args.dir or settings.data_dir / "backups", args.keep)
        except (OSError, sqlite3.Error) as exc:
            print(f"rsd-master: backup failed: {exc}", file=sys.stderr)
            return E_RUNTIME
        db.audit("cli", "system.backup", archive.name)
        print(archive)
        return E_OK
    return E_USAGE


def _status(db: Database, settings, as_json: bool) -> int:
    """Print the service summary used by the MOTD and the monitoring scripts.

    An agent counts as UP when its last keepalive is more recent than ``keepalive_timeout``
    (the CLI does not see the live connections of the service).

    Args:
        db: Database.
        settings: Master settings.
        as_json: JSON instead of text.

    Returns:
        The exit code (7 when the audit chain is broken).
    """
    now = time.time()
    agents = db.list_agents()
    up = [a for a in agents if a.get("last_seen") and now - a["last_seen"] <= settings.keepalive_timeout]
    chain_ok = db.verify_audit()
    data = {
        "version": __version__,
        "agents_total": len(agents),
        "agents_up": len(up),
        "agents_up_names": sorted(a["display_name"] or a["hostname"] for a in up),
        "tokens_active": len(db.list_tokens()),
        "audit_chain_ok": chain_ok,
        "web_port": settings.web_port,
    }
    if as_json:
        print(json.dumps(data, indent=2))
    else:
        print(f"Remote Shutdown master {data['version']}: {data['agents_up']}/{data['agents_total']} agents UP, "
              f"{data['tokens_active']} active token(s), audit chain {'OK' if chain_ok else 'BROKEN'}")
        if up:
            print("UP: " + ", ".join(data["agents_up_names"]))
    return E_OK if chain_ok else E_STATE


def create_backup(settings, directory: Path, keep: int) -> Path:
    """Archive a consistent snapshot of the master state and prune the old archives.

    The database is copied with the SQLite online backup API (consistent while the service
    runs); the PKI directory and the session key are added as they are. The archive holds the
    CA private key: it is created 0600 in a 0700 directory.

    Args:
        settings: Master settings.
        directory: Destination directory.
        keep: Number of archives to keep (the oldest are deleted).

    Returns:
        Path of the new archive.
    """
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    archive = directory / f"rsd-master-{stamp}.tar.gz"
    with tempfile.TemporaryDirectory(dir=directory) as tmp:
        snapshot = Path(tmp) / "rsd-master.db"
        src = sqlite3.connect(str(settings.db_path))
        dst = sqlite3.connect(str(snapshot))
        try:
            src.backup(dst)
        finally:
            dst.close()
            src.close()
        fd = os.open(str(archive), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh, tarfile.open(fileobj=fh, mode="w:gz") as tar:
            tar.add(str(snapshot), arcname="rsd-master.db")
            for extra in (settings.pki_dir, settings.data_dir / "session.key"):
                if extra.exists():
                    tar.add(str(extra), arcname=extra.name)
    archives = sorted(directory.glob("rsd-master-*.tar.gz"))
    for old in archives[:-keep]:
        old.unlink()
    return archive
