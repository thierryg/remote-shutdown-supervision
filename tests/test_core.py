# =============================================================================
# Remote Shutdown - LAN parental control and machine management (master/agent)
# -----------------------------------------------------------------------------
# File    : tests/test_core.py
# Purpose : Unit tests: configuration, database, audit chain, PKI, sessions, rate limiter, policy
# Author  : Thierry Gayet <thierry.gayet@labworks.fr>
# Project : remote-shutdown (version: VERSION)
# Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
# =============================================================================
"""Unit tests of the master building blocks."""

import asyncio
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from rsd_master import __version__
from rsd_master.auth import RateLimiter, SessionManager, password_problem
from rsd_master.config import load_settings
from rsd_master.db import Database
from rsd_master.pki import PKI, PKIError
from rsd_master.policy import PolicyEngine, effective_limit


def make_csr(key=None) -> str:
    """Return a PEM CSR (EC P-256 by default)."""
    key = key or ec.generate_private_key(ec.SECP256R1())
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "evil-chosen-name")]))
           .sign(key, hashes.SHA256()))
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def test_version_is_read_from_the_version_file():
    assert __version__.count(".") == 2 and "unknown" not in __version__


def test_settings_precedence(tmp_path):
    ini = tmp_path / "master.ini"
    ini.write_text("[server]\nweb_port = 9443\ntls_extra_names = a.lan, 10.0.0.1\n[log]\nlog_json = no\n")
    s = load_settings(ini, environ={"RSD__SERVER__WEB_PORT": "7443"})
    assert s.web_port == 7443  # environment wins over the file
    assert s.tls_extra_names == ["a.lan", "10.0.0.1"]
    assert s.log_json is False
    with pytest.raises(ValueError):
        load_settings(ini, environ={"RSD__SERVER__AGENT_PORT": "abc"})


def test_audit_chain_detects_tampering(tmp_path):
    db = Database(tmp_path / "t.db")
    db.init()
    db.audit("admin", "settings.update", "", {"x": [1, 2]})
    db.audit("admin", "agent.shutdown", "id-1")
    assert db.verify_audit()
    with db.connect() as conn:
        conn.execute("UPDATE audit SET actor = 'mallory' WHERE id = 1")
    assert not db.verify_audit()


def test_tokens_are_single_use_and_expire(tmp_path):
    db = Database(tmp_path / "t.db")
    db.init()
    db.create_token("h1", "one", ttl_seconds=60, uses=1)
    db.create_token("h2", "expired", ttl_seconds=-1, uses=5)
    assert db.consume_token("h1")
    assert not db.consume_token("h1")
    assert not db.consume_token("h2")
    assert [t["label"] for t in db.list_tokens()] == []


def test_pki_issues_constrained_certificates(tmp_path):
    pki = PKI(tmp_path / "pki")
    pki.ensure(["master.test", "192.0.2.10"])
    ca = pki.ca_cert()
    server = x509.load_pem_x509_certificate(pki.server_cert_path.read_bytes())
    san = server.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "master.test" in san.get_values_for_type(x509.DNSName)
    assert server.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value == \
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH])
    assert (pki.ca_key_path.stat().st_mode & 0o777) == 0o600

    cert = pki.sign_agent_csr(make_csr(), "agent-uuid")
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "agent-uuid"
    assert cert.issuer == ca.subject
    assert cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value == \
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH])

    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    with pytest.raises(PKIError):
        pki.sign_agent_csr(make_csr(weak), "x")
    with pytest.raises(PKIError):
        pki.sign_agent_csr("not a csr", "x")

    # A second start keeps the CA and the server certificate.
    fingerprint = pki.ca_fingerprint()
    before = pki.server_cert_path.read_bytes()
    pki.ensure(["master.test", "192.0.2.10"])
    assert pki.ca_fingerprint() == fingerprint and pki.server_cert_path.read_bytes() == before
    # A new address triggers a new server certificate, signed by the same CA.
    pki.ensure(["master.test", "192.0.2.10", "198.51.100.7"])
    assert pki.server_cert_path.read_bytes() != before and pki.ca_fingerprint() == fingerprint


def test_sessions_expire_and_renew():
    sm = SessionManager(b"k" * 48, idle_minutes=30, max_hours=12)
    token = sm.issue("admin", 3, False)
    claims = sm.decode(token)
    assert claims["sub"] == "admin" and claims["tv"] == 3
    assert not sm.needs_renewal(claims)
    assert sm.decode(token + "x") is None
    old = sm.issue("admin", 3, False, auth_time=time.time() - 13 * 3600)
    assert sm.decode(old) is None  # beyond the absolute lifetime


def test_rate_limiter_blocks_after_failures():
    rl = RateLimiter(max_failures=3, window_seconds=60)
    for _ in range(3):
        assert not rl.blocked("1.2.3.4")
        rl.failure("1.2.3.4")
    assert rl.blocked("1.2.3.4") and not rl.blocked("5.6.7.8")
    rl.reset("1.2.3.4")
    assert not rl.blocked("1.2.3.4")


def test_password_rules():
    assert password_problem("short", "admin") == "error.password_too_short"
    assert password_problem("administrator"[:5] * 2, "admin") is None
    assert password_problem("Admin" + "admin", "adminadmin") == "error.password_too_common"
    assert password_problem("a-long-passphrase", "admin") is None


def test_effective_limit():
    assert effective_limit({"limit_mode": "inherit"}, 90) == 90
    assert effective_limit({"limit_mode": "custom", "limit_minutes": 30}, 90) == 30
    assert effective_limit({"limit_mode": "unlimited", "limit_minutes": 30}, 90) == 0


class FakeHub:
    """Hub double recording the messages."""

    def __init__(self):
        self.sent = []
        self.messages = []

    def is_up(self, agent_id):
        return True

    async def send(self, agent_id, message):
        self.sent.append((agent_id, message["type"]))
        self.messages.append(message)
        return True


def test_policy_warns_then_shuts_down_once_per_boot(tmp_path):
    db = Database(tmp_path / "t.db")
    db.init()
    db.create_agent("a1", "pc", "0A", time.time() + 1e6, "10.0.0.2")
    db.set_settings({"default_limit_minutes": 60, "warning_minutes": 5, "shutdown_delay_seconds": 30})
    now = 1_000_000.0
    db.update_agent_info("a1", boot_time=now - 56 * 60)  # 56 minutes of uptime
    hub = FakeHub()
    engine = PolicyEngine(db, hub)
    asyncio.run(engine.tick(now))
    assert hub.sent == [("a1", "MESSAGE")]
    asyncio.run(engine.tick(now + 4 * 60))  # 60 minutes: shutdown
    asyncio.run(engine.tick(now + 4 * 60 + 15))  # not repeated
    assert hub.sent == [("a1", "MESSAGE"), ("a1", "SHUTDOWN")]
    # The agents render these texts in the language of the computer from key + params.
    assert hub.messages[0]["key"] == "policy.warning" and hub.messages[0]["params"] == {"minutes": 4}
    assert hub.messages[1]["key"] == "policy.shutdown" and hub.messages[1]["params"] == {"seconds": 30}
    assert db.list_audit()[0]["actor"] == "policy"
    # The infinite override disables the policy.
    db.update_agent_admin("a1", "pc", "unlimited", 0)
    asyncio.run(engine.tick(now + 3600))
    assert len(hub.sent) == 2


def test_certificate_watch_requests_a_restart(ctx, monkeypatch):
    from types import SimpleNamespace

    from rsd_master import server

    monkeypatch.setattr(server, "CERT_CHECK_INTERVAL", 0)
    monkeypatch.setattr(ctx.pki, "ensure", lambda names: True)  # e.g. the DHCP address changed
    web = SimpleNamespace(should_exit=False)
    state = {"restart": False}
    asyncio.run(asyncio.wait_for(server.watch_certificate(ctx, web, state), 5))
    assert web.should_exit and state["restart"]


def test_certificates_follow_the_strict_x509_profile(tmp_path):
    """Python 3.13+ (Debian 13, Ubuntu 26.04) verifies with VERIFY_X509_STRICT by default."""
    pki = PKI(tmp_path / "pki")
    pki.ensure([])
    server = x509.load_pem_x509_certificate(pki.server_cert_path.read_bytes())
    agent = pki.sign_agent_csr(make_csr(), "agent-uuid")
    ca_ski = pki.ca_cert().extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
    for cert in (server, agent):
        aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
        assert aki.key_identifier == ca_ski
        cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    # A server certificate issued without AKI by an older release is re-issued at start-up.
    assert not pki._server_needs_renewal(*__import__("rsd_master.pki", fromlist=["x"]).local_addresses())
