# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Fijomi Systems SL

"""
Tests for the health, readiness and metrics endpoints, the admin port,
JSON logging and request ID forwarding.
"""
import json
import os

import requests

from utils import OAuth2RelayServer, create_basic_config, create_test_config, find_free_port


def run_relay(config):
    """Start a relay with config; the caller uses it as a context manager."""
    config_file = create_test_config(config)
    return config_file, OAuth2RelayServer(config_file)


class TestHealthAndMetrics:
    """Operational endpoints on the relay port."""

    def test_endpoints_need_no_api_key(self, mock_servers):
        config = create_basic_config(api_key="test-api-key-12345")
        config_file, relay = run_relay(config)
        try:
            with relay as server:
                live = requests.get(server.get_url("/healthz"))
                assert live.status_code == 200
                assert live.json() == {"status": "ok"}

                ready = requests.get(server.get_url("/readyz"))
                assert ready.status_code == 200
                body = ready.json()
                assert body["status"] == "ready"
                assert body["token"]["state"] == "valid"
                assert body["token"]["expires_in_seconds"] > 0

                metrics = requests.get(server.get_url("/metrics"))
                assert metrics.status_code == 200
                assert "oauth2relay_build_info" in metrics.text
                assert "oauth2relay_token_expires_in_seconds" in metrics.text

                # Health checks are answered by the relay, not the upstream.
                assert mock_servers.api_server.get_requests_log() == []

                # Everything else still needs the API key.
                assert requests.get(server.get_url("/api/test")).status_code == 401
        finally:
            os.unlink(config_file)

    def test_metrics_count_requests_and_logins(self, mock_servers):
        config = create_basic_config()
        config_file, relay = run_relay(config)
        try:
            with relay as server:
                for _ in range(3):
                    assert requests.get(server.get_url("/api/test")).status_code == 200
                text = requests.get(server.get_url("/metrics")).text

                def value(prefix):
                    for line in text.splitlines():
                        if line.startswith(prefix):
                            return float(line.rsplit(" ", 1)[1])
                    raise AssertionError(f"{prefix} not found in metrics:\n{text}")

                assert value('oauth2relay_requests_total{code="200",upstream_host="127.0.0.1:9998"}') == 3
                assert value('oauth2relay_token_renewals_total{result="success",type="login"}') == 1
                assert value("oauth2relay_request_duration_seconds_count") == 3
        finally:
            os.unlink(config_file)

    def test_custom_paths_and_disabled_metrics(self, mock_servers):
        config = create_basic_config()
        config["health"] = {"liveness_path": "/-/live", "readiness_path": "/-/ready"}
        config["metrics"] = {"enabled": False}
        config_file, relay = run_relay(config)
        try:
            with relay as server:
                assert requests.get(server.get_url("/-/live")).status_code == 200
                assert requests.get(server.get_url("/-/ready")).status_code == 200
                # The default paths and /metrics now go to the upstream.
                requests.get(server.get_url("/metrics"))
                paths = [r["path"] for r in mock_servers.api_server.get_requests_log()]
                assert any(p.endswith("/metrics") for p in paths)
        finally:
            os.unlink(config_file)


class TestAdminPort:
    """Operational endpoints on a separate admin port."""

    def test_admin_port_serves_endpoints(self, mock_servers):
        config = create_basic_config()
        admin_port = find_free_port()
        config["admin_port"] = admin_port
        config_file, relay = run_relay(config)
        try:
            with relay as server:
                admin = f"http://{server.host}:{admin_port}"
                assert requests.get(admin + "/healthz").status_code == 200
                assert requests.get(admin + "/readyz").json()["status"] == "ready"
                assert "oauth2relay_build_info" in requests.get(admin + "/metrics").text

                # On the relay port /healthz is relayed like any other path.
                assert requests.get(server.get_url("/healthz")).status_code == 200
                paths = [r["path"] for r in mock_servers.api_server.get_requests_log()]
                assert any(p.endswith("/healthz") for p in paths)
        finally:
            os.unlink(config_file)

    def test_admin_port_must_differ(self):
        config = create_basic_config()
        config["admin_port"] = config["port"]
        config_file, relay = run_relay(config)
        try:
            try:
                with relay:
                    raise AssertionError("relay started with admin_port equal to port")
            except RuntimeError as e:
                assert "admin_port must differ" in str(e)
        finally:
            os.unlink(config_file)


class TestStructuredLogging:
    """log_format json and the access log."""

    def test_json_access_log_and_request_id(self, mock_servers):
        config = create_basic_config(debug=False)
        config["log_format"] = "json"
        config_file, relay = run_relay(config)
        try:
            with relay as server:
                response = requests.get(server.get_url("/api/test"), headers={"X-Request-ID": "trace-42"})
                assert response.status_code == 200
                assert response.headers["X-Request-ID"] == "trace-42"
                upstream = mock_servers.api_server.get_requests_log()[-1]
                assert upstream["headers"].get("X-Request-Id") == "trace-42"

                lines = [json.loads(l) for l in server.read_output().splitlines() if l.startswith("{")]
                access = [l for l in lines if l.get("msg") == "request" and l.get("request_id") == "trace-42"]
                assert len(access) == 1, server.read_output()
                assert access[0]["status"] == 200
                assert access[0]["level"] == "INFO"
                # Nothing secret reaches the log.
                assert "test_secret" not in server.read_output()
        finally:
            os.unlink(config_file)
