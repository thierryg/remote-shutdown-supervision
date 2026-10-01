# =============================================================================
# Remote Shutdown - LAN parental control and machine management (master/agent)
# -----------------------------------------------------------------------------
# File    : master/rsd_master/pki.py
# Purpose : Local certificate authority: CA, server certificate, agent CSR signing (mTLS)
# Author  : Thierry Gayet <thierry.gayet@labworks.fr>
# Project : remote-shutdown (version: VERSION)
# Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
# =============================================================================
"""Private PKI of the master, built with ``cryptography`` (no openssl subprocess).

Files in ``<data_dir>/pki`` (keys are 0600, owned by the service account)::

    ca.key / ca.crt          "Remote Shutdown Local CA", ECDSA P-384, 10 years
    server.key / server.crt  ECDSA P-256, serverAuth only, SAN = host names and LAN IPs

Agent certificates are issued from a CSR sent at enrollment: only the public key of the CSR
is used. The subject is chosen by the master (``CN=<agent uuid>``, ``O=rsd-agent``) and the
extended key usage is clientAuth only, so an agent certificate can never impersonate the
master and an agent cannot choose its identity.

Agents verify the master by chain (pinned CA, serverAuth EKU) and not by host name, so a
DHCP address change of the master never breaks them. Browsers do check the SAN: the server
certificate is re-issued automatically, at startup and every hour (see
:func:`rsd_master.server.watch_certificate`), when a local address is missing or when it
expires within 30 days.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import logging
import os
import socket
import uuid
from pathlib import Path
from typing import Iterable, List, Set, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

log = logging.getLogger(__name__)

CA_NAME = "Remote Shutdown Local CA"
AGENT_ORG = "rsd-agent"
RENEW_BEFORE = dt.timedelta(days=30)


class PKIError(Exception):
    """Invalid CSR or PKI file."""


def _utcnow() -> dt.datetime:
    """Return the current time as an aware UTC datetime."""
    return dt.datetime.now(dt.timezone.utc)


def not_after(cert: x509.Certificate) -> dt.datetime:
    """Return the expiry of a certificate as an aware UTC datetime.

    Works with old ``cryptography`` (naive ``not_valid_after``) and new (``*_utc``) releases.

    Args:
        cert: The certificate.
    """
    value = getattr(cert, "not_valid_after_utc", None)
    if value is None:
        value = cert.not_valid_after.replace(tzinfo=dt.timezone.utc)
    return value


def fingerprint(cert: x509.Certificate) -> str:
    """Return the SHA-256 fingerprint (lowercase hex, no separator) of a certificate.

    Args:
        cert: The certificate.
    """
    return cert.fingerprint(hashes.SHA256()).hex()


def _write_private(path: Path, data: bytes) -> None:
    """Write a private key with mode 0600 from the start (no permission race).

    Args:
        path: Destination.
        data: PEM bytes.
    """
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def _key_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    """Serialize a private key as unencrypted PKCS#8 PEM.

    Args:
        key: The private key.
    """
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def local_addresses() -> Tuple[Set[str], Set[str]]:
    """Return the host names and IP addresses the master is reachable at.

    Returns:
        A tuple (DNS names, IP addresses as strings). Loopback addresses are included so that
        ``https://localhost:8443`` works on the master itself.
    """
    names = {"localhost"}
    host = socket.gethostname()
    if host:
        names.add(host)
        short = host.split(".")[0]
        names.add(short)
        names.add(f"{short}.local")
        try:
            names.add(socket.getfqdn())
        except OSError:
            pass
    ips = {"127.0.0.1", "::1"}
    try:
        for info in socket.getaddrinfo(host, None):
            ips.add(info[4][0])
    except OSError:
        pass
    # The address used to reach the LAN (no packet is sent by a UDP connect).
    for target in ("192.0.2.1", "10.255.255.255"):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect((target, 9))
                ips.add(sock.getsockname()[0])
        except OSError:
            pass
    ips.update(_linux_interface_ips())
    clean_ips = set()
    for ip in ips:
        try:
            parsed = ipaddress.ip_address(ip.split("%")[0])
        except ValueError:
            continue
        if not parsed.is_link_local and not parsed.is_unspecified:
            clean_ips.add(str(parsed))
    return {n for n in names if n and n != "localhost.localdomain"}, clean_ips


def _linux_interface_ips() -> Set[str]:
    """Return the IPv4 and IPv6 addresses of every interface (Linux only, best effort)."""
    ips: Set[str] = set()
    try:
        with open("/proc/net/if_inet6", encoding="ascii") as fh:
            for line in fh:
                raw = line.split()[0]
                ips.add(str(ipaddress.IPv6Address(bytes.fromhex(raw))))
    except (OSError, ValueError):
        pass
    try:
        import fcntl
        import struct

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            for _, name in socket.if_nameindex():
                try:
                    packed = fcntl.ioctl(sock.fileno(), 0x8915, struct.pack("256s", name.encode()[:15]))  # SIOCGIFADDR
                    ips.add(socket.inet_ntoa(packed[20:24]))
                except OSError:
                    continue
    except (ImportError, OSError):
        pass
    return ips


class PKI:
    """Certificate authority of the master."""

    def __init__(self, directory: Path, server_days: int = 397, agent_days: int = 365) -> None:
        """Bind the PKI to its directory.

        Args:
            directory: Directory holding the CA and server material.
            server_days: Validity of the server certificate.
            agent_days: Validity of the agent certificates.
        """
        self.dir = Path(directory)
        self.server_days = server_days
        self.agent_days = agent_days

    # --- paths ---------------------------------------------------------------
    @property
    def ca_key_path(self) -> Path:
        """CA private key."""
        return self.dir / "ca.key"

    @property
    def ca_cert_path(self) -> Path:
        """CA certificate (public, downloadable from the console)."""
        return self.dir / "ca.crt"

    @property
    def server_key_path(self) -> Path:
        """Server private key."""
        return self.dir / "server.key"

    @property
    def server_cert_path(self) -> Path:
        """Server certificate."""
        return self.dir / "server.crt"

    # --- loading -------------------------------------------------------------
    def ca_cert(self) -> x509.Certificate:
        """Load the CA certificate."""
        return x509.load_pem_x509_certificate(self.ca_cert_path.read_bytes())

    def ca_pem(self) -> str:
        """Return the CA certificate as PEM text."""
        return self.ca_cert_path.read_text(encoding="ascii")

    def ca_fingerprint(self) -> str:
        """Return the SHA-256 fingerprint of the CA (pinned by the agents at enrollment)."""
        return fingerprint(self.ca_cert())

    def _authority_key_id(self) -> x509.AuthorityKeyIdentifier:
        """Return the Authority Key Identifier of the certificates issued by this CA.

        Required by RFC 5280 profiles and enforced by the strict X.509 verification that Python
        3.13+ enables by default (``ssl.VERIFY_X509_STRICT``, Debian 13 / Ubuntu 26.04).
        """
        ca = self.ca_cert()
        try:
            ski = ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
            return x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski)
        except x509.ExtensionNotFound:  # CA created elsewhere without SKI
            return x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.public_key())

    def _ca_key(self) -> ec.EllipticCurvePrivateKey:
        """Load the CA private key."""
        key = serialization.load_pem_private_key(self.ca_key_path.read_bytes(), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise PKIError("the CA key is not an EC key")
        return key

    # --- creation ------------------------------------------------------------
    def ensure(self, extra_names: Iterable[str] = ()) -> bool:
        """Create the CA if needed, then (re)issue the server certificate when required.

        Args:
            extra_names: Additional DNS names or IP addresses for the server certificate.

        Returns:
            True when a new server certificate was issued.
        """
        self.dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.dir, 0o700)
        if not (self.ca_key_path.exists() and self.ca_cert_path.exists()):
            self._create_ca()
        names, ips = local_addresses()
        for item in extra_names:
            try:
                ips.add(str(ipaddress.ip_address(item)))
            except ValueError:
                names.add(item)
        if self._server_needs_renewal(names, ips):
            self._issue_server(names, ips)
            return True
        return False

    def _create_ca(self) -> None:
        """Generate the CA key pair and the self-signed CA certificate."""
        key = ec.generate_private_key(ec.SECP384R1())
        subject = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Remote Shutdown"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"{CA_NAME} {uuid.uuid4().hex[:8]}"),
        ])
        now = _utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                         crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA384())
        )
        _write_private(self.ca_key_path, _key_pem(key))
        self.ca_cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        log.info("local CA created", extra={"fingerprint": fingerprint(cert)})

    def _server_needs_renewal(self, names: Set[str], ips: Set[str]) -> bool:
        """Tell whether the server certificate is missing, expiring, foreign or incomplete.

        Args:
            names: DNS names that must be present.
            ips: IP addresses that must be present.
        """
        if not (self.server_cert_path.exists() and self.server_key_path.exists()):
            return True
        try:
            cert = x509.load_pem_x509_certificate(self.server_cert_path.read_bytes())
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        except (ValueError, x509.ExtensionNotFound):
            return True
        if cert.issuer != self.ca_cert().subject or not_after(cert) - _utcnow() < RENEW_BEFORE:
            return True
        try:  # certificates of the first releases lack it: strict TLS clients (Python 3.13+) refuse them
            cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        except x509.ExtensionNotFound:
            return True
        have_names = set(san.get_values_for_type(x509.DNSName))
        have_ips = {str(ip) for ip in san.get_values_for_type(x509.IPAddress)}
        return not (names <= have_names and ips <= have_ips)

    def _issue_server(self, names: Set[str], ips: Set[str]) -> None:
        """Issue the server certificate for the given names and addresses.

        Args:
            names: DNS names.
            ips: IP addresses.
        """
        key = ec.generate_private_key(ec.SECP256R1())
        alt: List[x509.GeneralName] = [x509.DNSName(n) for n in sorted(names)]
        alt += [x509.IPAddress(ipaddress.ip_address(i)) for i in sorted(ips)]
        primary = sorted(names - {"localhost"})[0] if names - {"localhost"} else "localhost"
        now = _utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Remote Shutdown"),
                x509.NameAttribute(NameOID.COMMON_NAME, primary),
            ]))
            .issuer_name(self.ca_cert().subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=self.server_days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                         crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(self._authority_key_id(), critical=False)
            .add_extension(x509.SubjectAlternativeName(alt), critical=False)
            .sign(self._ca_key(), hashes.SHA256())
        )
        _write_private(self.server_key_path, _key_pem(key))
        # Leaf first, then the CA: browsers and agents receive the full chain.
        self.server_cert_path.write_bytes(
            cert.public_bytes(serialization.Encoding.PEM) + self.ca_cert().public_bytes(serialization.Encoding.PEM)
        )
        log.info("server certificate issued", extra={"names": sorted(names), "ips": sorted(ips)})

    # --- agents --------------------------------------------------------------
    def sign_agent_csr(self, csr_pem: str, agent_id: str) -> x509.Certificate:
        """Issue an agent (client) certificate from a CSR.

        Args:
            csr_pem: PEM-encoded PKCS#10 request generated by the agent.
            agent_id: UUID chosen by the master, written in the CN.

        Returns:
            The signed certificate.

        Raises:
            PKIError: When the CSR is malformed, badly signed or uses a weak key.
        """
        try:
            csr = x509.load_pem_x509_csr(csr_pem.encode("ascii"))
        except (ValueError, UnicodeEncodeError) as exc:
            raise PKIError("malformed CSR") from exc
        if not csr.is_signature_valid:
            raise PKIError("invalid CSR signature")
        public_key = csr.public_key()
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            if public_key.curve.key_size < 256:
                raise PKIError("EC key too small")
        else:
            key_size = getattr(public_key, "key_size", 0)
            if key_size < 2048:
                raise PKIError("unsupported or weak key")
        now = _utcnow()
        return (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, AGENT_ORG),
                x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
            ]))
            .issuer_name(self.ca_cert().subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=self.agent_days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                         crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
            .add_extension(self._authority_key_id(), critical=False)
            .sign(self._ca_key(), hashes.SHA256())
        )


def cert_pem(cert: x509.Certificate) -> str:
    """Return a certificate as PEM text.

    Args:
        cert: The certificate.
    """
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def serial_hex(cert: x509.Certificate) -> str:
    """Return the serial number in the uppercase hex form used by ``ssl.getpeercert()``.

    Args:
        cert: The certificate.
    """
    return format(cert.serial_number, "X")
