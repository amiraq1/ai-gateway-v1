"""Shared helpers for tests that need a real HTTPS listener or a streaming provider stub.

Everything here runs on 127.0.0.1 inside the test process. Certificates and keys
are created at runtime in a temporary directory and are never committed.
"""

from __future__ import annotations

import datetime
import ipaddress
import json
import socket
import ssl
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.config import GatewayConfig, GatewaySettings, ModelConfig, ProviderConfig
from app.database import Database
from app.main import create_app


def write_tls_material(directory: Path, dns_name: str, ip_address: str | None = None) -> tuple[Path, Path, Path]:
    """Create a throwaway CA and one leaf certificate. Returns (ca_pem, cert_pem, key_pem)."""
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic test ca")])
    ca_cert = (
        x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
        .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    sans: list[x509.GeneralName] = [x509.DNSName(dns_name)]
    if ip_address is not None:
        sans.append(x509.IPAddress(ipaddress.ip_address(ip_address)))
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, dns_name)]))
        .issuer_name(ca_name).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    ca_path = directory / "ca.pem"
    cert_path = directory / f"{dns_name}.crt"
    key_path = directory / f"{dns_name}.key"
    ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(leaf_cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                serialization.NoEncryption()))
    return ca_path, cert_path, key_path


def build_gateway_app(tmp_path: Path, providers: list[ProviderConfig] | None = None, **settings: Any):
    """Create the gateway app with a fresh database under tmp_path."""
    gateway_settings = GatewaySettings("127.0.0.1", 8000, str(tmp_path / "gateway.sqlite3"), 10.0,
                                       1_048_576, 30, **settings)
    cfg = GatewayConfig(gateway_settings, {"fast": ModelConfig("fast", True, tuple(providers or ()))})
    database = Database(gateway_settings.database_path)
    return create_app(cfg, database), database


@contextmanager
def serve_https(app, directory: Path) -> Iterator[tuple[str, ssl.SSLContext]]:
    """Run the app with uvicorn on 127.0.0.1 over TLS, in a thread. Yields (base_url, client_ssl_context)."""
    directory.mkdir(parents=True, exist_ok=True)
    ca_path, cert_path, key_path = write_tls_material(directory, "localhost", ip_address="127.0.0.1")
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    config = uvicorn.Config(app, host="127.0.0.1", port=port, ssl_certfile=str(cert_path),
                            ssl_keyfile=str(key_path), log_level="warning", access_log=False, lifespan="off")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 15
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.02)
    if not server.started:
        server.should_exit = True
        raise RuntimeError("live test server did not start")
    client_context = ssl.create_default_context(cafile=str(ca_path))
    try:
        yield f"https://127.0.0.1:{port}", client_context
    finally:
        server.should_exit = True
        thread.join(timeout=15)


class _SlowProviderHandler(BaseHTTPRequestHandler):
    """OpenAI-style SSE stub that sends ten chunks, 100 ms apart."""

    def do_POST(self) -> None:  # noqa: N802 - http.server naming
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        for index in range(10):
            time.sleep(0.1)
            chunk = {"choices": [{"index": 0, "delta": {"content": f"part-{index} "}}]}
            self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode("utf-8"))
            self.wfile.flush()
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()

    def log_message(self, *args: object) -> None:
        return


@contextmanager
def serve_slow_provider() -> Iterator[int]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _SlowProviderHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
