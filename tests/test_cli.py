# =============================================================================
# Remote Shutdown - LAN parental control and machine management (master/agent)
# -----------------------------------------------------------------------------
# File    : tests/test_cli.py
# Purpose : CLI tests: status, backup (consistent snapshot, rotation), non-interactive password
# Author  : Thierry Gayet <thierry.gayet@labworks.fr>
# Project : remote-shutdown (version: VERSION)
# Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
# =============================================================================
"""Tests of the ``rsd-master`` command line."""

import io
import json
import sqlite3
import tarfile
import time

from rsd_master import auth, cli


def run(settings, monkeypatch, *argv, stdin=""):
    """Run the CLI against the test data directory."""
    monkeypatch.setenv("RSD__PATHS__DATA_DIR", str(settings.data_dir))
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    return cli.main(["--config", "/nonexistent.ini", *argv])


def test_status_counts_recent_keepalives(ctx, settings, monkeypatch, capsys):
    ctx.db.create_agent("a1", "pc1", "0A", 2e9, "10.0.0.2")
    ctx.db.create_agent("a2", "pc2", "0B", 2e9, "10.0.0.3")
    ctx.db.update_agent_info("a1", last_seen=time.time())
    ctx.db.update_agent_info("a2", last_seen=time.time() - 3600)
    capsys.readouterr()
    assert run(settings, monkeypatch, "status", "--json") == 0
    data = json.loads(capsys.readouterr().out)
    assert data["agents_total"] == 2 and data["agents_up"] == 1 and data["agents_up_names"] == ["pc1"]


def test_password_from_stdin(ctx, settings, monkeypatch):
    assert run(settings, monkeypatch, "reset-password", "--password-stdin", stdin="short\n") == 2
    assert run(settings, monkeypatch, "reset-password", "--password-stdin", stdin="Ansible-Managed-42\n") == 0
    user = ctx.db.get_user("admin")
    assert auth.check_password("Ansible-Managed-42", user["pw_hash"]) and not user["must_change"]


def test_backup_is_private_consistent_and_rotated(ctx, settings, monkeypatch, capsys, tmp_path):
    dest = tmp_path / "backups"
    for _ in range(3):
        assert run(settings, monkeypatch, "backup", "--dir", str(dest), "--keep", "2") == 0
        time.sleep(1.05)  # one archive per second (timestamped names)
    archives = sorted(dest.glob("rsd-master-*.tar.gz"))
    assert len(archives) == 2
    assert archives[-1].stat().st_mode & 0o777 == 0o600
    with tarfile.open(archives[-1]) as tar:
        names = tar.getnames()
        assert {"rsd-master.db", "pki/ca.key", "session.key"} <= set(names)
        (tmp_path / "snapshot.db").write_bytes(tar.extractfile("rsd-master.db").read())
    conn = sqlite3.connect(tmp_path / "snapshot.db")
    assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1
    conn.close()


def test_check_password(ctx, settings, monkeypatch):
    assert run(settings, monkeypatch, "check-password", stdin="admin\n") == 1  # default account: must change
    run(settings, monkeypatch, "reset-password", "--password-stdin", stdin="Ansible-Managed-42\n")
    assert run(settings, monkeypatch, "check-password", stdin="Ansible-Managed-42\n") == 0
    assert run(settings, monkeypatch, "check-password", stdin="wrong-password\n") == 1
