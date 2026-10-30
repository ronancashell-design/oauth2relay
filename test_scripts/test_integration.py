# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Fijomi Systems SL

"""
End-to-end integration tests for OAuth2Relay
"""
import pytest
import requests
import time
import json
import concurrent.futures
from utils import OAuth2RelayServer, create_test_config


@pytest.mark.integration
@pytest.mark.slow
class TestEndToEndIntegration:
    """Comprehensive end-to-end integration tests."""
    
    def test_complete_oauth2_flow(self, client_credentials_config, mock_servers):
        """Test complete OAuth2 authentication and request relaying flow."""
        config_file = create_test_config(client_credentials_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                # Clear any existing requests
                mock_servers.api_server.clear_requests_log()
                
                # Make authenticated request
                response = requests.get(
                    server.get_url("/api/users/123"),
                    params={"include": "profile,settings"}
                )
                
                assert response.status_code == 200
                response_data = response.json()
                assert response_data['status'] == 'ok'
                
                # Verify the complete flow
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) == 1
                
                request_data = api_requests[0]
                assert request_data['method'] == 'GET'
                assert request_data['path'] == '/api/users/123'
                assert 'Authorization' in request_data['headers']
                assert request_data['headers']['Authorization'].startswith('Bearer access_token_')
                assert request_data['query_params']['include'] == 'profile,settings'
        finally:
            import os
            os.unlink(config_file)
    
    def test_multiple_request_types(self, client_credentials_config, mock_servers):
        """Test handling of different HTTP methods and content types."""
        config_file = create_test_config(client_credentials_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                mock_servers.api_server.clear_requests_log()
                
                # GET request
                get_response = requests.get(
                    server.get_url("/api/users"),
                    params={"page": 1}
                )
                assert get_response.status_code == 200
                
                # POST with JSON
                post_data = {"name": "John Doe", "email": "john@example.com"}
                post_response = requests.post(
                    server.get_url("/api/users"),
                    json=post_data
                )
                assert post_response.status_code == 200
                
                # POST with form data
                form_data = {"username": "johndoe", "action": "login"}
                form_response = requests.post(
                    server.get_url("/api/auth"),
                    data=form_data
                )
                assert form_response.status_code == 200
                
                # Verify all requests were processed
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) == 3
                
                # The outbound method is always relay.method (GET in this
                # config), whatever method the caller used
                methods = [req['method'] for req in api_requests]
                assert methods == ['GET', 'GET', 'GET']
        finally:
            import os
            os.unlink(config_file)
    
    def test_concurrent_requests(self, client_credentials_config, mock_servers):
        """Test handling of concurrent requests."""
        config_file = create_test_config(client_credentials_config)
        
        def make_request(server_url, path):
            try:
                response = requests.get(f"{server_url}/api/{path}", timeout=10)
                return {
                    'status_code': response.status_code,
                    'path': path,
                    'success': response.status_code == 200
                }
            except Exception as e:
                return {
                    'status_code': -1,
                    'path': path,
                    'success': False,
                    'error': str(e)
                }
        
        try:
            with OAuth2RelayServer(config_file) as server:
                mock_servers.api_server.clear_requests_log()
                
                # Make 10 concurrent requests
                with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                    futures = [
                        executor.submit(make_request, server.get_url(), f"test{i}")
                        for i in range(10)
                    ]
                    
                    results = [future.result() for future in concurrent.futures.as_completed(futures)]
                
                # Check results
                successful_requests = [r for r in results if r['success']]
                assert len(successful_requests) >= 8  # Allow for some timing issues
                
                # Verify requests reached the API server
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) >= 8
        finally:
            import os
            os.unlink(config_file)


@pytest.mark.integration
class TestErrorScenarios:
    """Test various error scenarios in integration context."""
    
    def test_oauth_server_unavailable(self, client_credentials_config):
        """Test behavior when OAuth2 server is unavailable."""
        config = client_credentials_config.copy()
        config["login"]["url"] = "http://localhost:9900/token"  # Non-existent
        
        config_file = create_test_config(config)
        
        try:
            # Server should fail to start or authenticate
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"))
                assert response.status_code in [500, 502]
        except RuntimeError:
            # Expected - OAuth2 server unavailable
            pass
        finally:
            import os
            try:
                os.unlink(config_file)
            except FileNotFoundError:
                pass
    
    def test_api_server_unavailable(self, client_credentials_config):
        """Test behavior when API server is unavailable."""
        config = client_credentials_config.copy()
        config["relay"]["url"] = "http://localhost:9997/api"  # Non-existent
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"))
                # Should return bad gateway or similar
                assert response.status_code in [502, 500]
        finally:
            import os
            os.unlink(config_file)
    
    def test_invalid_configuration(self, basic_config):
        """Test handling of invalid configuration."""
        config = basic_config.copy()
        # Remove required field
        del config["login"]["url"]
        
        config_file = create_test_config(config)
        
        try:
            # Server should fail to start with invalid config
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"))
                assert response.status_code == 500
        except RuntimeError:
            # Expected - invalid configuration
            pass
        finally:
            import os
            try:
                os.unlink(config_file)
            except FileNotFoundError:
                pass


@pytest.mark.integration
class TestComplexScenarios:
    """Test complex real-world scenarios."""
    
    def test_api_key_plus_oauth(self, mock_servers):
        """Test API key authentication combined with OAuth2."""
        from utils import create_basic_config
        
        config = create_basic_config()
        config["apiKey"] = "test-api-key-12345"
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                # Request with API key should work
                headers = {"X-API-Key": "test-api-key-12345"}
                response = requests.get(server.get_url("/api/test"), headers=headers)
                assert response.status_code == 200
                
                # Request without API key should fail
                response_no_key = requests.get(server.get_url("/api/test"))
                assert response_no_key.status_code == 401
                
                # Verify only authorized request reached API server
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) == 1
        finally:
            import os
            os.unlink(config_file)
    
    def test_custom_headers_and_parameters(self, mock_servers):
        """Test complex header and parameter manipulation."""
        from utils import create_basic_config
        
        config = create_basic_config()
        config["relay"]["pushheaders"] = True
        config["relay"]["headers"] = {
            "Authorization": "Bearer ${ACCESSTOKEN}",
            "X-Service": "oauth2relay",
            "X-Client-IP": "${IP}",
            "X-Timestamp": "2024-01-01T00:00:00Z"
        }
        config["relay"]["parameters"] = {
            "service": "oauth2relay",
            "client_ip": "${IP}",
            "token_hash": "${ACCESSTOKEN}",
            "version": "1.0"
        }
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                # Send request with custom headers
                custom_headers = {
                    "X-Request-ID": "req-123",
                    "User-Agent": "TestClient/1.0"
                }
                
                response = requests.get(
                    server.get_url("/api/complex"),
                    headers=custom_headers,
                    params={"user_id": "123", "action": "view"}
                )
                assert response.status_code == 200
                
                # Verify all headers and parameters
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) == 1
                
                request_data = api_requests[0]
                
                # Check configured headers
                assert request_data['headers'].get('X-Service') == 'oauth2relay'
                assert request_data['headers'].get('X-Timestamp') == '2024-01-01T00:00:00Z'
                assert 'Authorization' in request_data['headers']
                
                # Check forwarded headers (pushheaders enabled)
                assert request_data['headers'].get('X-Request-ID') == 'req-123'
                assert request_data['headers'].get('User-Agent') == 'TestClient/1.0'
                
                # Check parameters
                params = request_data['query_params']
                assert params.get('service') == 'oauth2relay'
                assert params.get('version') == '1.0'
                assert params.get('user_id') == '123'  # Original parameter
                assert params.get('action') == 'view'  # Original parameter
                assert 'client_ip' in params  # Should be substituted
        finally:
            import os
            os.unlink(config_file)
    
    def test_large_request_handling(self, client_credentials_config, mock_servers):
        """Test handling of large requests."""
        config = client_credentials_config.copy()
        config["relay"]["method"] = "POST"
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                # Create large JSON payload
                large_data = {
                    "users": [
                        {
                            "id": i,
                            "name": f"User {i}",
                            "email": f"user{i}@example.com",
                            "data": "x" * 1000  # 1KB per user
                        }
                        for i in range(100)  # ~100KB total
                    ]
                }
                
                response = requests.post(
                    server.get_url("/api/bulk_create"),
                    json=large_data
                )
                assert response.status_code == 200
                
                # Verify request was processed
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) == 1
                
                request_data = api_requests[0]
                assert request_data['method'] == 'POST'
                # Verify some data was received (exact content may vary due to processing)
                assert len(request_data['body']) > 1000
        finally:
            import os
            os.unlink(config_file)


@pytest.mark.integration
@pytest.mark.slow
class TestLongRunningScenarios:
    """Test long-running scenarios and edge cases."""
    
    def test_token_refresh_during_operation(self, client_credentials_config, mock_servers):
        """Test token refresh during long-running operation."""
        config_file = create_test_config(client_credentials_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                mock_servers.api_server.clear_requests_log()
                
                # Make requests over time to potentially trigger refresh
                for i in range(5):
                    response = requests.get(server.get_url(f"/api/test{i}"))
                    assert response.status_code == 200
                    
                    if i < 4:  # Don't sleep after the last request
                        time.sleep(1)
                
                # All requests should succeed
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) == 5
                
                # Check that all requests had valid authorization
                for request in api_requests:
                    auth_header = request['headers'].get('Authorization', '')
                    assert auth_header.startswith('Bearer ')
        finally:
            import os
            os.unlink(config_file)
    
    def test_server_restart_recovery(self, client_credentials_config, mock_servers):
        """Test recovery after server restart."""
        config_file = create_test_config(client_credentials_config)
        
        try:
            # Start server, make request, stop server
            with OAuth2RelayServer(config_file) as server1:
                response1 = requests.get(server1.get_url("/api/test1"))
                assert response1.status_code == 200
            
            # Start server again and make another request
            with OAuth2RelayServer(config_file) as server2:
                response2 = requests.get(server2.get_url("/api/test2"))
                assert response2.status_code == 200
            
            # Both requests should have succeeded
            api_requests = mock_servers.api_server.get_requests_log()
            assert len(api_requests) == 2
        finally:
            import os
            os.unlink(config_file)


@pytest.mark.integration
class TestRealWorldUseCases:
    """Test realistic usage scenarios."""
    
    def test_api_gateway_scenario(self, mock_servers):
        """Test OAuth2Relay as an API gateway."""
        from utils import create_basic_config
        
        config = create_basic_config()
        config["apiKey"] = "gateway-key-123"
        config["relay"]["pushheaders"] = True
        config["relay"]["headers"] = {
            "Authorization": "Bearer ${ACCESSTOKEN}",
            "X-Gateway": "oauth2relay",
            "X-Forwarded-For": "${IP}"
        }
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                # Simulate different client requests
                clients = [
                    {"path": "/api/users", "headers": {"User-Agent": "WebApp/1.0"}},
                    {"path": "/api/orders", "headers": {"User-Agent": "MobileApp/2.0"}},
                    {"path": "/api/products", "headers": {"User-Agent": "CLI/3.0"}}
                ]
                
                mock_servers.api_server.clear_requests_log()
                
                for client in clients:
                    headers = client["headers"].copy()
                    headers["X-API-Key"] = "gateway-key-123"
                    
                    response = requests.get(
                        server.get_url(client["path"]),
                        headers=headers
                    )
                    assert response.status_code == 200
                
                # Verify all requests were processed correctly
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) == 3
                
                # Check that gateway headers were added
                for request in api_requests:
                    assert request['headers'].get('X-Gateway') == 'oauth2relay'
                    assert 'Authorization' in request['headers']
                    assert 'X-Forwarded-For' in request['headers']
        finally:
            import os
            os.unlink(config_file)
    
    def test_microservices_authentication(self, client_credentials_config, mock_servers):
        """Test OAuth2Relay for microservices authentication."""
        config_file = create_test_config(client_credentials_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                # Simulate calls to different microservices
                services = ["users", "orders", "inventory", "billing"]
                
                mock_servers.api_server.clear_requests_log()
                
                for service in services:
                    response = requests.get(
                        server.get_url(f"/api/{service}/health"),
                        params={"service": service}
                    )
                    assert response.status_code == 200
                
                # All services should receive authenticated requests
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) == 4
                
                # Each request should have proper authentication
                for request in api_requests:
                    assert 'Authorization' in request['headers']
                    auth_header = request['headers']['Authorization']
                    assert auth_header.startswith('Bearer access_token_')
        finally:
            import os
            os.unlink(config_file)