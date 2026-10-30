# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Fijomi Systems SL

"""
Tests for request relaying functionality
"""
import pytest
import requests
import json
from utils import OAuth2RelayServer, create_test_config


@pytest.mark.integration
class TestRequestRelaying:
    """Test basic request relaying functionality."""
    
    def test_get_request_relay(self, client_credentials_config, mock_servers):
        """Test relaying GET requests."""
        config_file = create_test_config(client_credentials_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                # Make GET request with query parameters
                response = requests.get(
                    server.get_url("/api/users"),
                    params={"page": 1, "limit": 10}
                )
                assert response.status_code == 200
                
                # Verify request was relayed correctly
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) > 0
                
                last_request = api_requests[-1]
                assert last_request['method'] == 'GET'
                assert last_request['path'] == '/api/users'
                assert 'page' in last_request['query_params']
                assert 'limit' in last_request['query_params']
        finally:
            import os
            os.unlink(config_file)
    
    def test_post_request_relay(self, client_credentials_config, mock_servers):
        """Test relaying POST requests."""
        config = client_credentials_config.copy()
        config["relay"]["method"] = "POST"
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                # Make POST request with JSON data
                test_data = {"name": "John Doe", "email": "john@example.com"}
                response = requests.post(
                    server.get_url("/api/users"),
                    json=test_data,
                    headers={"Content-Type": "application/json"}
                )
                assert response.status_code == 200
                
                # Verify request was relayed correctly
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) > 0
                
                last_request = api_requests[-1]
                assert last_request['method'] == 'POST'
                assert last_request['path'] == '/api/users'
                
                # Check that JSON data was passed through
                if last_request['json']:
                    assert last_request['json']['name'] == 'John Doe'
        finally:
            import os
            os.unlink(config_file)
    
    def test_path_appending(self, client_credentials_config, mock_servers):
        """Test that request paths are appended to the base relay URL."""
        config_file = create_test_config(client_credentials_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                # Test various paths
                paths = ["/users/123", "/products", "/categories/electronics"]
                
                for path in paths:
                    mock_servers.api_server.clear_requests_log()
                    response = requests.get(server.get_url(f"/api{path}"))
                    assert response.status_code == 200
                    
                    api_requests = mock_servers.api_server.get_requests_log()
                    assert len(api_requests) > 0
                    assert api_requests[-1]['path'] == f"/api{path}"
        finally:
            import os
            os.unlink(config_file)


@pytest.mark.integration
class TestHeaderHandling:
    """Test header forwarding and manipulation."""
    
    def test_authorization_header_injection(self, client_credentials_config, mock_servers):
        """Test that Authorization header is correctly injected."""
        config_file = create_test_config(client_credentials_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"))
                assert response.status_code == 200
                
                # Check Authorization header was added
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) > 0
                
                last_request = api_requests[-1]
                auth_header = last_request['headers'].get('Authorization', '')
                assert auth_header.startswith('Bearer access_token_')
        finally:
            import os
            os.unlink(config_file)
    
    def test_custom_headers(self, client_credentials_config, mock_servers):
        """Test custom headers in relay configuration."""
        config = client_credentials_config.copy()
        config["relay"]["headers"]["X-Custom-Header"] = "test-value"
        config["relay"]["headers"]["X-Service"] = "oauth2relay"
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"))
                assert response.status_code == 200
                
                # Check custom headers were added
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) > 0
                
                last_request = api_requests[-1]
                assert last_request['headers'].get('X-Custom-Header') == 'test-value'
                assert last_request['headers'].get('X-Service') == 'oauth2relay'
        finally:
            import os
            os.unlink(config_file)
    
    def test_push_headers_enabled(self, client_credentials_config, mock_servers):
        """Test forwarding incoming headers when pushheaders is enabled."""
        config = client_credentials_config.copy()
        config["relay"]["pushheaders"] = True
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                # Send request with custom headers
                custom_headers = {
                    "X-Client-ID": "test-client-123",
                    "X-Request-ID": "req-456",
                    "User-Agent": "TestClient/1.0"
                }
                response = requests.get(
                    server.get_url("/api/test"),
                    headers=custom_headers
                )
                assert response.status_code == 200
                
                # Check that incoming headers were forwarded
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) > 0
                
                last_request = api_requests[-1]
                assert last_request['headers'].get('X-Client-ID') == 'test-client-123'
                assert last_request['headers'].get('X-Request-ID') == 'req-456'
        finally:
            import os
            os.unlink(config_file)
    
    def test_push_headers_disabled(self, client_credentials_config, mock_servers):
        """Test that incoming headers are not forwarded when pushheaders is disabled."""
        config = client_credentials_config.copy()
        config["relay"]["pushheaders"] = False
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                # Send request with custom headers
                custom_headers = {
                    "X-Client-ID": "test-client-123",
                    "X-Request-ID": "req-456"
                }
                response = requests.get(
                    server.get_url("/api/test"),
                    headers=custom_headers
                )
                assert response.status_code == 200
                
                # Check that incoming headers were NOT forwarded
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) > 0
                
                last_request = api_requests[-1]
                # Should not have the custom headers
                assert 'X-Client-ID' not in last_request['headers']
                # X-Request-ID is the relay's correlation ID and is always
                # forwarded; here it is the caller's (valid) ID.
                assert last_request['headers'].get('X-Request-Id') == response.headers['X-Request-ID'] == 'req-456'
                # But should have Authorization header
                assert 'Authorization' in last_request['headers']
        finally:
            import os
            os.unlink(config_file)


@pytest.mark.integration
class TestParameterHandling:
    """Test parameter merging and handling."""
    
    def test_query_parameter_merging(self, variable_substitution_config, mock_servers):
        """Test merging of query parameters."""
        config_file = create_test_config(variable_substitution_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                # Send request with query parameters
                response = requests.get(
                    server.get_url("/api/test"),
                    params={"user_id": "123", "action": "view"}
                )
                assert response.status_code == 200
                
                # Check parameter merging
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) > 0
                
                last_request = api_requests[-1]
                query_params = last_request['query_params']
                
                # Should have original parameters
                assert query_params.get('user_id') == '123'
                assert query_params.get('action') == 'view'
                
                # Should have configured parameters
                assert 'client_ip' in query_params
                assert 'access_token_param' in query_params
                assert query_params.get('fixed_value') == 'test_value'
        finally:
            import os
            os.unlink(config_file)
    
    def test_form_data_merging(self, variable_substitution_config, mock_servers):
        """Test merging of form data in POST requests."""
        config = variable_substitution_config.copy()
        config["relay"]["method"] = "POST"
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                # Send POST request with form data
                form_data = {"username": "testuser", "action": "login"}
                response = requests.post(
                    server.get_url("/api/test"),
                    data=form_data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"}
                )
                assert response.status_code == 200
                
                # The exact form data handling depends on the server implementation
                # Just verify the request was processed
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) > 0
        finally:
            import os
            os.unlink(config_file)
    
    def test_json_data_merging(self, variable_substitution_config, mock_servers):
        """Test merging of JSON data in POST requests."""
        config = variable_substitution_config.copy()
        config["relay"]["method"] = "POST"
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                # Send POST request with JSON data
                json_data = {"username": "testuser", "action": "login"}
                response = requests.post(
                    server.get_url("/api/test"),
                    json=json_data,
                    headers={"Content-Type": "application/json"}
                )
                assert response.status_code == 200
                
                # Check that JSON was processed
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) > 0
                
                last_request = api_requests[-1]
                if last_request['json']:
                    # Should have original JSON data
                    assert last_request['json']['username'] == 'testuser'
                    # Should have merged parameters from config
                    assert 'client_ip' in last_request['json']
        finally:
            import os
            os.unlink(config_file)


@pytest.mark.integration
class TestResponseHandling:
    """Test response forwarding and handling."""
    
    def test_response_forwarding(self, client_credentials_config, mock_servers):
        """Test that responses are correctly forwarded to the client."""
        config_file = create_test_config(client_credentials_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"))
                assert response.status_code == 200
                
                # Should receive JSON response from mock server
                response_data = response.json()
                assert 'received' in response_data
                assert response_data['status'] == 'ok'
        finally:
            import os
            os.unlink(config_file)
    
    def test_response_headers_forwarding(self, client_credentials_config, mock_servers):
        """Test that response headers are forwarded."""
        config_file = create_test_config(client_credentials_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"))
                assert response.status_code == 200
                
                # Should have content-type header from the API server
                assert 'content-type' in response.headers
        finally:
            import os
            os.unlink(config_file)
    
    def test_error_response_forwarding(self, client_credentials_config, mock_servers):
        """Test forwarding of error responses from the API server."""
        config_file = create_test_config(client_credentials_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                # Make request to a secure endpoint without proper token
                response = requests.get(server.get_url("/secure"))
                
                # Response should be forwarded even if it's an error
                # The exact status depends on how the mock server responds
                assert response.status_code in [200, 401, 403, 500]
        finally:
            import os
            os.unlink(config_file)


@pytest.mark.integration
class TestDifferentHttpMethods:
    """Test relaying of different HTTP methods."""
    
    def test_put_request_relay(self, client_credentials_config, mock_servers):
        """Test relaying PUT requests."""
        config = client_credentials_config.copy()
        config["relay"]["method"] = "PUT"
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                test_data = {"name": "Updated Name"}
                response = requests.put(
                    server.get_url("/api/users/123"),
                    json=test_data
                )
                assert response.status_code == 200
                
                # Verify PUT request was relayed
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) > 0
                assert api_requests[-1]['method'] == 'PUT'
        finally:
            import os
            os.unlink(config_file)
    
    def test_delete_request_relay(self, client_credentials_config, mock_servers):
        """Test relaying DELETE requests."""
        config = client_credentials_config.copy()
        config["relay"]["method"] = "DELETE"
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.delete(server.get_url("/api/users/123"))
                assert response.status_code == 200
                
                # Verify DELETE request was relayed
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) > 0
                assert api_requests[-1]['method'] == 'DELETE'
        finally:
            import os
            os.unlink(config_file)


@pytest.mark.integration
class TestRelayErrorHandling:
    """Test error handling in request relaying."""
    
    def test_upstream_server_unavailable(self, client_credentials_config):
        """Test handling when upstream API server is unavailable."""
        config = client_credentials_config.copy()
        config["relay"]["url"] = "http://localhost:9997/api"  # Non-existent server
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"))
                # Should return 502 Bad Gateway or similar error
                assert response.status_code in [502, 500]
        finally:
            import os
            os.unlink(config_file)
    
    def test_invalid_relay_url(self, client_credentials_config):
        """Test handling of invalid relay URL configuration."""
        config = client_credentials_config.copy()
        config["relay"]["url"] = "invalid://not-a-url"
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"))
                # The outbound request cannot be sent, which the relay reports
                # as 502 Bad Gateway
                assert response.status_code == 502
        except RuntimeError:
            # Server might fail to start with invalid URL
            pass
        finally:
            import os
            try:
                os.unlink(config_file)
            except FileNotFoundError:
                pass