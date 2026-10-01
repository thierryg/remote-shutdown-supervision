# =============================================================================
# Remote Shutdown - LAN parental control and machine management (master/agent)
# -----------------------------------------------------------------------------
# File    : tests/conftest.py
# Purpose : Shared pytest fixtures: temporary master context, HTTPS test client, admin session
# Author  : Thierry Gayet <thierry.gayet@labworks.fr>
# Project : remote-shutdown (version: VERSION)
# Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
# =============================================================================
"""Fixtures shared by the master tests (no network, no root, no systemd needed)."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "master"))

from rsd_master import auth  # noqa: E402
from rsd_master.config import Settings  # noqa: E402
from rsd_master.server import build_context  # noqa: E402
from rsd_master.web import create_app  # noqa: E402

PASSWORD = "Correct-Horse-42"


@pytest.fixture(autouse=True)
def fast_bcrypt(monkeypatch):
    """Use the minimum bcrypt cost so that the suite stays fast."""
    import bcrypt

    real = bcrypt.gensalt
    monkeypatch.setattr(bcrypt, "gensalt", lambda rounds=12, prefix=b"2b": real(4, prefix))


@pytest.fixture
def settings(tmp_path):
    """Settings pointing at a temporary data directory."""
    s = Settings()
    s.data_dir = tmp_path / "data"
    s.tls_extra_names = ["master.test", "192.0.2.10"]
    return s


@pytest.fixture
def ctx(settings):
    """A fully initialized master context (database, PKI, default admin)."""
    return build_context(settings)


@pytest.fixture
def client(ctx):
    """HTTPS test client (the session cookie is Secure)."""
    from fastapi.testclient import TestClient

    return TestClient(create_app(ctx), base_url="https://testserver")


@pytest.fixture
def admin(client, ctx):
    """A test client logged in with a changed (non-default) password."""
    ctx.db.upsert_user("admin", auth.hash_password(PASSWORD), must_change=False)
    r = client.post("/api/login", json={"username": "admin", "password": PASSWORD}, headers={"X-RSD": "1"})
    assert r.status_code == 200, r.text
    client.headers.update({"X-RSD": "1"})
    return client
