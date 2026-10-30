# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Fijomi Systems SL

"""
Tests for the relay modes: single, passthrough and parameter
"""
import os
import pytest
import requests
from utils import OAuth2RelayServer, create_test_config

MOCK_API = "http://127.0.0.1:9998"


def run_relay(config):
    """Write the config to a temp file and return (path, server context manager)."""
    config_file = create_test_config(config)
    return config_file, OAuth2RelayServer(config_file)


@pytest.mark.integration
class TestSingleMode:
    """Every request goes to relay.url; the incoming path is ignored."""

    def test_path_is_ignored(self, client_credentials_config, mock_servers):
        config = client_credentials_config
        config["relay"]["mode"] = "single"
        config["relay"]["url"] = f"{MOCK_API}/api/get_statuses"
        config_file, relay = run_relay(config)
        try:
            with relay as server:
                for path in ["/", "/my_profile", "/anything/else"]:
                    mock_servers.api_server.clear_requests_log()
                    response = requests.get(server.get_url(path), params={"page": 2})
                    assert response.status_code == 200

                    last_request = mock_servers.api_server.get_requests_log()[-1]
                    assert last_request['path'] == '/get_statuses'
                    assert last_request['query_params']['page'] == '2'
        finally:
            os.unlink(config_file)

    def test_mode_is_case_insensitive(self, client_credentials_config, mock_servers):
        config = client_credentials_config
        config["relay"]["mode"] = "SINGLE"
        config["relay"]["url"] = f"{MOCK_API}/api/get_statuses"
        config_file, relay = run_relay(config)
        try:
            with relay as server:
                response = requests.get(server.get_url("/my_profile"))
                assert response.status_code == 200
                assert mock_servers.api_server.get_requests_log()[-1]['path'] == '/get_statuses'
        finally:
            os.unlink(config_file)


@pytest.mark.integration
class TestPassthroughMode:
    """The incoming path is appended to relay.url."""

    def test_path_is_appended(self, client_credentials_config, mock_servers):
        config = client_credentials_config
        config["relay"]["mode"] = "Passthrough"
        config_file, relay = run_relay(config)
        try:
            with relay as server:
                for path in ["/get_statuses", "/my_profile"]:
                    mock_servers.api_server.clear_requests_log()
                    response = requests.get(server.get_url(path))
                    assert response.status_code == 200
                    assert mock_servers.api_server.get_requests_log()[-1]['path'] == path
        finally:
            os.unlink(config_file)

    def test_passthrough_is_default(self, client_credentials_config, mock_servers):
        config = client_credentials_config
        config["relay"].pop("mode", None)
        config_file, relay = run_relay(config)
        try:
            with relay as server:
                response = requests.get(server.get_url("/my_profile"))
                assert response.status_code == 200
                assert mock_servers.api_server.get_requests_log()[-1]['path'] == '/my_profile'
        finally:
            os.unlink(config_file)


@pytest.mark.integration
class TestParameterMode:
    """The target URL comes from an incoming parameter that is never sent on."""

    @pytest.fixture
    def parameter_config(self, client_credentials_config):
        config = client_credentials_config
        config["relay"]["mode"] = "parameter"
        config["relay"]["allowed_hosts"] = ["127.0.0.1"]
        # The mock API is on loopback, which parameter mode blocks by default.
        config["relay"]["allowed_networks"] = ["127.0.0.0/8"]
        config["relay"].pop("url", None)
        return config

    def test_loopback_blocked_by_default(self, parameter_config, mock_servers):
        del parameter_config["relay"]["allowed_networks"]
        config_file, relay = run_relay(parameter_config)
        try:
            with relay as server:
                response = requests.get(server.get_url("/"), params={
                    "external_url": f"{MOCK_API}/api/my_profile",
                })
                assert response.status_code == 403
                assert response.json()["error"] == "destination_blocked"
                assert mock_servers.api_server.get_requests_log() == []
        finally:
            os.unlink(config_file)

    def test_get_uses_and_strips_external_url(self, parameter_config, mock_servers):
        config_file, relay = run_relay(parameter_config)
        try:
            with relay as server:
                response = requests.get(server.get_url("/ignored"), params={
                    "external_url": f"{MOCK_API}/api/my_profile?id=7",
                    "page": 1,
                })
                assert response.status_code == 200

                last_request = mock_servers.api_server.get_requests_log()[-1]
                assert last_request['path'] == '/my_profile'
                assert last_request['query_params']['id'] == '7'
                assert last_request['query_params']['page'] == '1'
                assert 'external_url' not in last_request['query_params']
        finally:
            os.unlink(config_file)

    def test_post_json_strips_external_url(self, parameter_config, mock_servers):
        parameter_config["relay"]["method"] = "POST"
        config_file, relay = run_relay(parameter_config)
        try:
            with relay as server:
                response = requests.post(server.get_url("/"), json={
                    "external_url": f"{MOCK_API}/api/my_profile",
                    "name": "John Doe",
                })
                assert response.status_code == 200

                last_request = mock_servers.api_server.get_requests_log()[-1]
                assert last_request['path'] == '/my_profile'
                assert 'John Doe' in last_request['body']
                assert 'external_url' not in last_request['body']
        finally:
            os.unlink(config_file)

    def test_custom_parameter_name(self, parameter_config, mock_servers):
        parameter_config["relay"]["url_param"] = "relay_to"
        config_file, relay = run_relay(parameter_config)
        try:
            with relay as server:
                response = requests.get(server.get_url("/"), params={
                    "relay_to": f"{MOCK_API}/api/my_profile",
                    "external_url": "belongs-to-the-3rd-party",
                })
                assert response.status_code == 200

                last_request = mock_servers.api_server.get_requests_log()[-1]
                assert last_request['path'] == '/my_profile'
                assert last_request['query_params']['external_url'] == 'belongs-to-the-3rd-party'
                assert 'relay_to' not in last_request['query_params']
        finally:
            os.unlink(config_file)

    def test_missing_external_url_is_400(self, parameter_config, mock_servers):
        config_file, relay = run_relay(parameter_config)
        try:
            with relay as server:
                response = requests.get(server.get_url("/my_profile"))
                assert response.status_code == 400
                assert mock_servers.api_server.get_requests_log() == []
        finally:
            os.unlink(config_file)

    def test_disallowed_host_is_403(self, parameter_config, mock_servers):
        parameter_config["relay"]["allowed_hosts"] = ["api.example.com"]
        config_file, relay = run_relay(parameter_config)
        try:
            with relay as server:
                response = requests.get(server.get_url("/"), params={
                    "external_url": f"{MOCK_API}/api/my_profile",
                })
                assert response.status_code == 403
                assert mock_servers.api_server.get_requests_log() == []
        finally:
            os.unlink(config_file)


@pytest.mark.unit
class TestRelayModeValidation:
    """Invalid relay mode configuration must stop the server from starting."""

    @pytest.mark.parametrize("relay_overrides", [
        {"mode": "singel"},
        {"mode": "dynamic"},
        {"mode": "single", "url": ""},
        {"mode": "parameter"},
        {"mode": "parameter", "allowed_hosts": []},
    ])
    def test_invalid_mode_config_fails_to_start(self, basic_config, relay_overrides):
        basic_config["relay"].update(relay_overrides)
        config_file = create_test_config(basic_config)
        try:
            with pytest.raises(RuntimeError) as excinfo:
                with OAuth2RelayServer(config_file):
                    pass
            assert "invalid relay configuration" in str(excinfo.value)
        finally:
            os.unlink(config_file)
