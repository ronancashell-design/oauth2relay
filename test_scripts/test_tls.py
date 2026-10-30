# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Fijomi Systems SL

"""
Tests for HTTPS on the relay port.
"""
import os
import shutil
import socket
import ssl
import subprocess
import tempfile

import pytest
import requests

from utils import OAuth2RelayServer, create_basic_config, create_test_config


@pytest.fixture
def certificate():
    """A self-signed certificate for localhost, made with openssl."""
    if shutil.which("openssl") is None:
        pytest.skip("openssl is not installed")
    directory = tempfile.mkdtemp()
    cert, key = os.path.join(directory, "tls.crt"), os.path.join(directory, "tls.key")
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
        "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=localhost",
        "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
    ], check=True, capture_output=True)
    yield cert, key
    shutil.rmtree(directory)


class TestTLS:
    def test_https_relay(self, certificate, mock_servers):
        cert, key = certificate
        config = create_basic_config()
        config["tls"] = {"cert_file": cert, "key_file": key, "min_version": "1.3"}
        config_file = create_test_config(config)
        try:
            with OAuth2RelayServer(config_file) as server:
                url = f"https://localhost:{server.port}"
                response = requests.get(url + "/api/test", verify=cert)
                assert response.status_code == 200
                assert requests.get(url + "/readyz", verify=cert).json()["status"] == "ready"
                metrics = requests.get(url + "/metrics", verify=cert).text
                assert "oauth2relay_tls_certificate_expiry_timestamp_seconds" in metrics

                # Plain HTTP is answered with 400 and never relayed.
                relayed = len(mock_servers.api_server.get_requests_log())
                plain = requests.get(f"http://localhost:{server.port}/api/test", timeout=5)
                assert plain.status_code == 400
                assert len(mock_servers.api_server.get_requests_log()) == relayed

                # With min_version 1.3 a TLS 1.2 client is refused.
                old = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                old.load_verify_locations(cert)
                old.maximum_version = ssl.TLSVersion.TLSv1_2
                with pytest.raises(ssl.SSLError):
                    with socket.create_connection(("localhost", server.port), timeout=5) as sock:
                        with old.wrap_socket(sock, server_hostname="localhost"):
                            pass
        finally:
            os.unlink(config_file)

    def test_missing_certificate_stops_startup(self, mock_servers):
        config = create_basic_config()
        config["tls"] = {"cert_file": "/nonexistent/tls.crt", "key_file": "/nonexistent/tls.key"}
        config_file = create_test_config(config)
        try:
            with pytest.raises(RuntimeError, match="TLS"):
                with OAuth2RelayServer(config_file):
                    pass
        finally:
            os.unlink(config_file)
