# =============================================================================
# Remote Shutdown - LAN parental control and machine management (master/agent)
# -----------------------------------------------------------------------------
# File    : tests/test_api.py
# Purpose : REST API tests: authentication, forced password change, CSRF, headers, enrollment
# Author  : Thierry Gayet <thierry.gayet@labworks.fr>
# Project : remote-shutdown (version: VERSION)
# Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
# =============================================================================
"""Tests of the web API through the ASGI test client."""

from cryptography import x509

from conftest import PASSWORD
from test_core import make_csr


def test_static_console_and_security_headers(client):
    r = client.get("/")
    assert r.status_code == 200 and "Remote Shutdown" in r.text
    assert "unsafe-inline" not in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"
    assert client.get("/static/../web.py").status_code == 404
    assert client.get("/static/i18n/fr.json").json()["nav.machines"] == "Machines"
    assert "BEGIN CERTIFICATE" in client.get("/ca.crt").text


def test_api_requires_a_session(client):
    assert client.get("/api/agents").status_code == 401


def test_default_admin_must_change_password(client):
    h = {"X-RSD": "1"}
    r = client.post("/api/login", json={"username": "admin", "password": "admin"}, headers=h)
    assert r.status_code == 200 and r.json()["must_change"] is True
    assert "httponly" in r.headers["set-cookie"].lower() and "secure" in r.headers["set-cookie"].lower()
    assert client.get("/api/agents").json()["detail"] == "error.password_change_required"
    assert client.post("/api/password", json={"current": "admin", "new": "short"}, headers=h).status_code == 400
    r = client.post("/api/password", json={"current": "admin", "new": PASSWORD}, headers=h)
    assert r.status_code == 200
    assert client.get("/api/agents").status_code == 200


def test_login_failures_are_rate_limited(client):
    h = {"X-RSD": "1"}
    for _ in range(5):
        assert client.post("/api/login", json={"username": "admin", "password": "nope"}, headers=h).status_code == 401
    assert client.post("/api/login", json={"username": "admin", "password": "admin"}, headers=h).status_code == 429


def test_csrf_header_is_required(admin):
    r = admin.put("/api/settings", json={"warning_minutes": 3}, headers={"X-RSD": ""})
    assert r.status_code == 403 and r.json()["detail"] == "error.csrf"


def test_logout_invalidates_the_session(admin):
    assert admin.post("/api/logout").status_code == 200
    assert admin.get("/api/agents").status_code == 401


def test_settings_validation_and_audit(admin, ctx):
    assert admin.put("/api/settings", json={"default_limit_minutes": -1}).status_code == 400
    r = admin.put("/api/settings", json={"default_limit_minutes": 150, "warning_minutes": 10})
    assert r.status_code == 200 and r.json()["default_limit_minutes"] == 150
    entry = ctx.db.list_audit()[0]
    assert entry["action"] == "settings.update"
    assert entry["details"]["default_limit_minutes"] == [0, 150]


def test_enrollment_flow(admin, ctx):
    token = admin.post("/api/tokens", json={"label": "pc", "ttl_minutes": 10, "uses": 1}).json()["token"]
    assert admin.get("/api/tokens").json()["tokens"][0]["uses_left"] == 1
    body = {"token": token, "csr": make_csr(), "hostname": "kid-pc"}
    r = admin.post("/api/enroll", json=body)
    assert r.status_code == 200, r.text
    data = r.json()
    cert = x509.load_pem_x509_certificate(data["cert"].encode())
    assert cert.subject.rfc4514_string().endswith(f"CN={data['agent_id']}") or data["agent_id"] in cert.subject.rfc4514_string()
    assert admin.post("/api/enroll", json=body).status_code == 403  # single use
    agents = admin.get("/api/agents").json()["agents"]
    assert agents[0]["hostname"] == "kid-pc" and agents[0]["status"] == "DOWN"
    agent_id = agents[0]["id"]
    assert admin.post(f"/api/agents/{agent_id}/shutdown", json={"delay": 5}).status_code == 409
    r = admin.patch(f"/api/agents/{agent_id}", json={"limit_mode": "custom", "limit_minutes": 0})
    assert r.status_code == 400
    r = admin.patch(f"/api/agents/{agent_id}", json={"display_name": "Kid", "limit_mode": "custom",
                                                       "limit_minutes": 120})
    assert r.status_code == 200
    assert admin.get("/api/agents").json()["agents"][0]["effective_limit_minutes"] == 120
    assert admin.delete(f"/api/agents/{agent_id}").status_code == 200
    assert admin.get("/api/agents").json()["agents"] == []
    assert admin.get("/api/audit").json()["chain_ok"] is True


def test_enroll_rejects_bad_input(client):
    assert client.post("/api/enroll", json={"token": "x", "csr": "y"}).status_code == 403
    assert client.post("/api/enroll", json=["not", "an", "object"]).status_code == 400


def test_robots_are_refused_everywhere(client):
    assert client.get("/robots.txt").text == "User-agent: *\nDisallow: /\n"
    assert "noindex" in client.get("/").headers["x-robots-tag"]


def test_metrics_need_their_token(client, ctx, tmp_path):
    assert client.get("/metrics").status_code == 404  # disabled by default
    token_file = tmp_path / "metrics.token"
    token_file.write_text("s3cret-metrics\n")
    ctx.settings.metrics_token_file = str(token_file)
    ctx.db.create_agent("a1", 'pc "kid"', "0A", 2e9, "10.0.0.2")
    assert client.get("/metrics").status_code == 401
    r = client.get("/metrics", headers={"Authorization": "Bearer s3cret-metrics"})
    assert r.status_code == 200
    assert "rsd_agents_total 1" in r.text and "rsd_agents_up 0" in r.text
    assert 'name="pc \\"kid\\""' in r.text and "rsd_audit_chain_ok 1" in r.text
