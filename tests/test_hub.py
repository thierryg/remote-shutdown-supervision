# =============================================================================
# Remote Shutdown - LAN parental control and machine management (master/agent)
# -----------------------------------------------------------------------------
# File    : tests/test_hub.py
# Purpose : Agent hub tests over real mutual TLS: identity, protocol, revocation, discovery
# Author  : Thierry Gayet <thierry.gayet@labworks.fr>
# Project : remote-shutdown (version: VERSION)
# Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
# =============================================================================
"""End-to-end tests of the agent hub on 127.0.0.1 with a Python TLS client."""

import asyncio
import json
import ssl
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from rsd_master.discovery import start_discovery
from rsd_master.hub import MAX_MESSAGE_BYTES
from rsd_master.pki import cert_pem, not_after, serial_hex
from rsd_master.server import discovery_answer
from test_core import make_csr


def enroll(ctx, tmp_path, name="pc"):
    """Issue an agent certificate directly through the PKI and register the agent."""
    key = ec.generate_private_key(ec.SECP256R1())
    cert = ctx.pki.sign_agent_csr(make_csr(key), f"agent-{name}")
    ctx.db.create_agent(f"agent-{name}", name, serial_hex(cert), not_after(cert).timestamp(), "127.0.0.1")
    key_path, cert_path = tmp_path / f"{name}.key", tmp_path / f"{name}.crt"
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    cert_path.write_text(cert_pem(cert))
    client = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ctx.pki.ca_cert_path))
    client.check_hostname = False
    client.load_cert_chain(str(cert_path), str(key_path))
    return client


async def readmsg(reader):
    """Read one JSON line."""
    return json.loads(await asyncio.wait_for(reader.readline(), 5))


async def scenario(ctx, tmp_path):
    """Connect an agent, exchange messages, then revoke it."""
    server = await asyncio.start_server(ctx.hub.handle_stream, "127.0.0.1", 0, ssl=ctx.hub.ssl_context(),
                                        limit=MAX_MESSAGE_BYTES)
    port = server.sockets[0].getsockname()[1]
    tls = enroll(ctx, tmp_path)
    reader, writer = await asyncio.open_connection("127.0.0.1", port, ssl=tls)
    welcome = await readmsg(reader)
    assert welcome["type"] == "WELCOME" and welcome["agent_id"] == "agent-pc"
    declare = {"type": "DECLARE", "hostname": "pc\x07", "os": "Linux", "arch": "amd64", "version": "t",
               "boot_time": time.time() - 100,
               "interfaces": [{"name": "eth0", "ipv4": "192.0.2.5", "ipv6": [], "mac": "aa:bb"}]}
    writer.write((json.dumps(declare) + "\n").encode())
    writer.write(b'{"type": "KEEPALIVE", "uptime": 100}\n')
    await writer.drain()
    assert (await readmsg(reader))["type"] == "PONG"
    assert ctx.hub.is_up("agent-pc")
    agent = ctx.db.get_agent("agent-pc")
    assert agent["hostname"] == "pc" and agent["interfaces"][0]["ipv4"] == ["192.0.2.5"]

    assert await ctx.hub.send("agent-pc", {"type": "SHUTDOWN", "delay": 60, "message": "bye"})
    order = await readmsg(reader)
    assert order["type"] == "SHUTDOWN" and order["ref"]
    writer.write(b'{"type": "CHAT", "text": "please wait", "user": "kid"}\n')
    writer.write(b'{"type": "STATE", "shutdown_at": 123}\n')
    await writer.drain()
    await asyncio.sleep(0.2)
    assert ctx.db.list_chat("agent-pc")[0]["text"] == "please wait"
    assert ctx.hub.live("agent-pc")["shutdown_at"] == 123

    # Revocation: the agent row is deleted, the next connection is refused.
    ctx.db.delete_agent("agent-pc")
    await ctx.hub.disconnect("agent-pc")
    assert await asyncio.wait_for(reader.read(), 5) == b""
    reader, writer = await asyncio.open_connection("127.0.0.1", port, ssl=tls)
    refused = await readmsg(reader)
    assert refused["type"] == "ERROR" and refused["fatal"] is True
    writer.close()

    # A client without certificate cannot even finish the TLS handshake.
    anon = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ctx.pki.ca_cert_path))
    anon.check_hostname = False
    try:
        r, _ = await asyncio.open_connection("127.0.0.1", port, ssl=anon)
        assert await asyncio.wait_for(r.read(), 5) == b""
    except (ssl.SSLError, ConnectionResetError):
        pass
    server.close()


def test_agent_session_over_mutual_tls(ctx, tmp_path):
    asyncio.run(scenario(ctx, tmp_path))


async def discover(ctx):
    """Send DISCOVER to the responder and return the answer."""
    transport = await start_discovery("127.0.0.1", 0, lambda: discovery_answer(ctx))
    port = transport.get_extra_info("sockname")[1]
    loop = asyncio.get_running_loop()
    answer = loop.create_future()

    class Client(asyncio.DatagramProtocol):
        def datagram_received(self, data, addr):
            answer.set_result(json.loads(data))

    client, _ = await loop.create_datagram_endpoint(Client, remote_addr=("127.0.0.1", port))
    client.sendto(b'{"type": "IGNORED"}')
    client.sendto(b'{"type": "DISCOVER"}')
    try:
        return await asyncio.wait_for(answer, 5)
    finally:
        client.close()
        transport.close()


def test_discovery_answers_with_ports_and_fingerprint(ctx):
    answer = asyncio.run(discover(ctx))
    assert answer["type"] == "MASTER" and answer["agent_port"] == 8444
    assert answer["ca_fingerprint"] == ctx.pki.ca_fingerprint()
