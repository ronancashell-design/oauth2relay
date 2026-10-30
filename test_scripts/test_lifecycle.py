# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Fijomi Systems SL

"""
Tests for the command line, configuration checks and background token
refresh.
"""
import json
import os
import subprocess
import time

import requests

from utils import OAuth2RelayServer, create_basic_config, create_test_config

BINARY = "../oauth2relay"


def run_binary(*args):
    return subprocess.run([BINARY, *args], capture_output=True, text=True, timeout=10)


def metric_value(text, prefix):
    for line in text.splitlines():
        if line.startswith(prefix):
            return float(line.rsplit(" ", 1)[1])
    return 0.0


class TestCommandLine:
    """Flags and --check-config."""

    def test_check_config_valid(self):
        config_file = create_test_config(create_basic_config())
        try:
            result = run_binary("--check-config", "--config", config_file)
            assert result.returncode == 0, result.stderr
            assert "configuration is valid" in result.stdout
        finally:
            os.unlink(config_file)

    def test_check_config_after_file(self):
        config_file = create_test_config(create_basic_config())
        try:
            result = run_binary(config_file, "--check-config")
            assert result.returncode == 0, result.stderr
        finally:
            os.unlink(config_file)

    def test_check_config_rejects_unknown_field(self):
        config = create_basic_config()
        config["login"]["retry_atempts"] = 3
        config_file = create_test_config(config)
        try:
            result = run_binary("--check-config", config_file)
            assert result.returncode == 1
            assert 'unknown field "retry_atempts"' in result.stderr
        finally:
            os.unlink(config_file)

    def test_check_config_rejects_bad_grant(self):
        config = create_basic_config()
        config["login"]["grant_type"] = "authorization_code"
        config_file = create_test_config(config)
        try:
            result = run_binary("--check-config", config_file)
            assert result.returncode == 1
            assert "grant_type" in result.stderr
        finally:
            os.unlink(config_file)

    def test_unknown_flag(self):
        result = run_binary("--no-such-flag")
        assert result.returncode == 2
        assert "Usage:" in result.stderr

    def test_version_and_help(self):
        assert "OAUTH2Relay version" in run_binary("--version").stdout
        assert "--check-config" in run_binary("--help").stdout

    def test_log_format_flag(self, mock_servers):
        config_file = create_test_config(create_basic_config(debug=False))
        try:
            with OAuth2RelayServer(config_file, extra_args=["--log-format", "json"]) as server:
                assert requests.get(server.get_url("/api/test")).status_code == 200
                lines = [l for l in server.read_output().splitlines() if l.strip()]
                assert lines and all(l.startswith("{") for l in lines), lines
                json.loads(lines[0])
        finally:
            os.unlink(config_file)


class TestBackgroundRefresh:
    """The token is renewed before it expires, without any traffic."""

    def _config(self, background):
        config = create_basic_config(debug=False)
        # The mock IdP always says 3600 seconds; ignore that so the
        # 2 second default lifetime applies.
        config["login"]["parameters"] = {"AccessToken": "access_token", "RefreshToken": "refresh_token"}
        config["refresh"]["parameters"] = {"AccessToken": "access_token", "RefreshToken": "refresh_token"}
        config["token"] = {"default_lifetime": 2, "refresh_at": 0.5, "background_refresh": background}
        return config

    def _renewals(self, server):
        text = requests.get(server.get_url("/metrics")).text
        return sum(metric_value(text, f'oauth2relay_token_renewals_total{{result="success",type="{kind}"}}')
                   for kind in ("login", "refresh"))

    def test_renews_without_traffic(self, mock_servers):
        config_file = create_test_config(self._config(True))
        try:
            with OAuth2RelayServer(config_file) as server:
                time.sleep(3.5)
                assert self._renewals(server) >= 3
                ready = requests.get(server.get_url("/readyz")).json()
                assert ready["token"]["state"] == "valid"
        finally:
            os.unlink(config_file)

    def test_disabled(self, mock_servers):
        config_file = create_test_config(self._config(False))
        try:
            with OAuth2RelayServer(config_file) as server:
                time.sleep(2.5)
                assert self._renewals(server) == 1
                ready = requests.get(server.get_url("/readyz")).json()
                assert ready["token"]["state"] == "expired"
                # A request still renews the expired token.
                assert requests.get(server.get_url("/api/test")).status_code == 200
                assert self._renewals(server) == 2
        finally:
            os.unlink(config_file)
