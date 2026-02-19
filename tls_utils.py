"""
tls_utils – TLS 1.3 transport helpers.

Generates self-signed certificates for development and provides
``ssl.SSLContext`` factories for both the server and the client.
In production, replace the auto-generated certs with real ones.
"""

import os
import ssl
import datetime
from typing import Tuple

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    generate_private_key,
)

from config import CERTS_DIR


def _ca_paths(cert_dir: str) -> Tuple[str, str]:
    return (
        os.path.join(cert_dir, "ca.pem"),
        os.path.join(cert_dir, "ca.key"),
    )


def _srv_paths(cert_dir: str) -> Tuple[str, str, str]:
    return (
        os.path.join(cert_dir, "server.pem"),
        os.path.join(cert_dir, "server.key"),
        os.path.join(cert_dir, "ca.pem"),
    )


def ensure_certs(cert_dir: str = CERTS_DIR) -> None:
    """
    Generate a self-signed CA and server certificate if they don't exist.

    Produces ``ca.pem``, ``ca.key``, ``server.pem``, ``server.key``
    inside *cert_dir*.
    """
    os.makedirs(cert_dir, exist_ok=True)
    ca_cert_path, ca_key_path = _ca_paths(cert_dir)
    srv_cert_path, srv_key_path, _ = _srv_paths(cert_dir)

    if all(os.path.isfile(p) for p in (ca_cert_path, ca_key_path,
                                        srv_cert_path, srv_key_path)):
        return  # already generated

    now = datetime.datetime.now(datetime.timezone.utc)
    one_year = datetime.timedelta(days=365)

    # ── CA key + self-signed cert ─────────────────────────────────────────
    ca_key = generate_private_key(SECP256R1())
    ca_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "IoT-Auth-PQ-Dev-CA"),
    ])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + one_year)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    _write_pem(ca_cert_path, ca_cert.public_bytes(serialization.Encoding.PEM))
    _write_key(ca_key_path, ca_key)

    # ── Server key + CA-signed cert ──────────────────────────────────────
    srv_key = generate_private_key(SECP256R1())
    srv_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    srv_cert = (
        x509.CertificateBuilder()
        .subject_name(srv_name)
        .issuer_name(ca_name)
        .public_key(srv_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + one_year)
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(
                    __import__("ipaddress").IPv4Address("127.0.0.1")
                ),
            ]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    _write_pem(srv_cert_path, srv_cert.public_bytes(serialization.Encoding.PEM))
    _write_key(srv_key_path, srv_key)


def _write_pem(path: str, data: bytes) -> None:
    with open(path, "wb") as f:
        f.write(data)


def _write_key(path: str, key) -> None:
    with open(path, "wb") as f:
        f.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )


def get_server_ssl_context(cert_dir: str = CERTS_DIR) -> ssl.SSLContext:
    """
    Build a TLS 1.3 server SSL context using the generated certs.
    """
    ensure_certs(cert_dir)
    srv_cert, srv_key, _ = _srv_paths(cert_dir)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile=srv_cert, keyfile=srv_key)
    return ctx


def get_client_ssl_context(cert_dir: str = CERTS_DIR) -> ssl.SSLContext:
    """
    Build a TLS 1.3 client SSL context that trusts the dev CA.
    """
    ensure_certs(cert_dir)
    ca_cert, _ = _ca_paths(cert_dir)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(cafile=ca_cert)
    return ctx
