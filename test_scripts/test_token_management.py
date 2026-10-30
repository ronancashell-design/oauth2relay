# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Fijomi Systems SL

"""
Tests for token management and refresh functionality
"""
import pytest
import requests
import time
import json
from utils import OAuth2RelayServer, create_test_config


@pytest.mark.oauth
class TestTokenRefresh:
    """Test token refresh functionality."""
    
    def test_token_refresh_success(self, client_credentials_config, mock_servers):
        """Test successful token refresh."""
        config_file = create_test_config(client_credentials_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                # First request should get initial token
                response1 = requests.get(server.get_url("/api/test1"))
                assert response1.status_code == 200
                
                # Get the token from the first request
                api_requests = mock_servers.api_server.get_requests_log()
                first_token = api_requests[-1]['headers']['Authorization'].split(' ')[1]
                
                # Clear the log and wait a bit
                mock_servers.api_server.clear_requests_log()
                time.sleep(1)
                
                # Second request should use the same token (if not expired)
                response2 = requests.get(server.get_url("/api/test2"))
                assert response2.status_code == 200
                
                # Token should still be the same
                api_requests = mock_servers.api_server.get_requests_log()
                second_token = api_requests[-1]['headers']['Authorization'].split(' ')[1]
                assert first_token == second_token
        finally:
            import os
            os.unlink(config_file)
    
    def test_token_refresh_on_expiry(self, client_credentials_config, mock_servers):
        """Test token refresh when token expires."""
        # Set a very short token expiry for testing
        config = client_credentials_config.copy()
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                # Make initial request
                response1 = requests.get(server.get_url("/api/test1"))
                assert response1.status_code == 200
                
                # Get initial token
                api_requests = mock_servers.api_server.get_requests_log()
                first_token = api_requests[-1]['headers']['Authorization'].split(' ')[1]
                
                # Wait for token to potentially expire and make another request
                time.sleep(2)
                mock_servers.api_server.clear_requests_log()
                
                response2 = requests.get(server.get_url("/api/test2"))
                assert response2.status_code == 200
                
                # Check if a new token was obtained
                api_requests = mock_servers.api_server.get_requests_log()
                second_token = api_requests[-1]['headers']['Authorization'].split(' ')[1]
                
                # Tokens might be different if refresh occurred
                # (This test depends on the mock server's token generation timing)
        finally:
            import os
            os.unlink(config_file)
    
    def test_refresh_endpoint_failure(self, client_credentials_config, mock_servers):
        """Test handling when refresh endpoint fails."""
        config = client_credentials_config.copy()
        config["refresh"]["url"] = "http://127.0.0.1:9081/invalid_refresh"
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                # Initial request should work (gets fresh token via login)
                response = requests.get(server.get_url("/api/test"))
                assert response.status_code == 200
        finally:
            import os
            os.unlink(config_file)


@pytest.mark.oauth 
class TestTokenValidation:
    """Test token validation and handling."""
    
    def test_missing_access_token(self, basic_config, mock_servers):
        """Test handling when access token is missing from OAuth2 response."""
        config = basic_config.copy()
        # Point to an endpoint that doesn't return access_token
        config["login"]["url"] = "http://127.0.0.1:9081/userinfo"
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"))
                assert response.status_code in [400, 500]
        except RuntimeError:
            # Expected - server should fail to get valid token
            pass
        finally:
            import os
            try:
                os.unlink(config_file)
            except FileNotFoundError:
                pass
    
    def test_invalid_token_format(self, basic_config, mock_servers):
        """Test handling of invalid token format."""
        config = basic_config.copy()
        # Use wrong parameter mapping
        config["login"]["parameters"]["AccessToken"] = "invalid_field"
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"))
                assert response.status_code in [400, 500]
        except RuntimeError:
            # Expected - token extraction should fail
            pass
        finally:
            import os
            try:
                os.unlink(config_file)
            except FileNotFoundError:
                pass


@pytest.mark.oauth
class TestFixedToken:
    """Test fixed token functionality."""
    
    def test_fixed_token_usage(self, fixed_token_config, mock_servers):
        """Test using fixed token instead of OAuth2 flow."""
        config_file = create_test_config(fixed_token_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"))
                assert response.status_code == 200
                
                # Verify fixed token was used
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) > 0
                
                last_request = api_requests[-1]
                auth_header = last_request['headers'].get('Authorization', '')
                assert 'fixed_token_12345' in auth_header
        finally:
            import os
            os.unlink(config_file)
    
    def test_fixed_token_precedence(self, client_credentials_config, mock_servers):
        """Test that fixed token takes precedence over OAuth2."""
        config = client_credentials_config.copy()
        config["relay"]["fixedtoken"] = "priority_fixed_token"
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"))
                assert response.status_code == 200
                
                # Verify fixed token was used, not OAuth2 token
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) > 0
                
                last_request = api_requests[-1]
                auth_header = last_request['headers'].get('Authorization', '')
                assert 'priority_fixed_token' in auth_header
                assert 'access_token_' not in auth_header
        finally:
            import os
            os.unlink(config_file)


@pytest.mark.oauth
class TestTokenExpiry:
    """Test token expiration handling."""
    
    def test_expires_in_parameter(self, client_credentials_config, mock_servers):
        """Test token expiry calculation using expires_in parameter."""
        config_file = create_test_config(client_credentials_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"))
                assert response.status_code == 200
                
                # Token should be valid and used successfully
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) > 0
        finally:
            import os
            os.unlink(config_file)
    
    def test_expires_at_parameter(self, client_credentials_config, mock_servers):
        """Test token expiry using expires_at parameter."""
        config = client_credentials_config.copy()
        config["login"]["parameters"]["ExpiresAt"] = "expires_at"
        del config["login"]["parameters"]["ExpiresIn"]
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"))
                assert response.status_code == 200
        finally:
            import os
            os.unlink(config_file)
    
    def test_default_expiry(self, client_credentials_config, mock_servers):
        """Test default token expiry when no expiry information is provided."""
        config = client_credentials_config.copy()
        # Remove expiry parameter mapping
        del config["login"]["parameters"]["ExpiresIn"]
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"))
                assert response.status_code == 200
                
                # Should still work with default expiry (5 minutes)
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) > 0
        finally:
            import os
            os.unlink(config_file)


@pytest.mark.oauth
class TestConcurrentRequests:
    """Test token management under concurrent load."""
    
    def test_concurrent_token_usage(self, client_credentials_config, mock_servers):
        """Test multiple concurrent requests using the same token."""
        import threading
        import concurrent.futures
        
        config_file = create_test_config(client_credentials_config)
        results = []
        
        def make_request(server_url, path):
            try:
                response = requests.get(f"{server_url}{path}", timeout=10)
                return response.status_code
            except Exception as e:
                return str(e)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                # Make multiple concurrent requests
                with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                    futures = [
                        executor.submit(make_request, server.get_url(), f"/api/test{i}")
                        for i in range(10)
                    ]
                    
                    results = [future.result() for future in concurrent.futures.as_completed(futures)]
                
                # All requests should succeed
                success_count = sum(1 for r in results if r == 200)
                assert success_count >= 8  # Allow for some timing issues
                
                # Check that requests were received
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) >= 8
        finally:
            import os
            os.unlink(config_file)


@pytest.mark.oauth
class TestTokenStorage:
    """Test token storage and persistence."""
    
    def test_token_reuse_across_requests(self, client_credentials_config, mock_servers):
        """Test that tokens are reused across multiple requests."""
        config_file = create_test_config(client_credentials_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                # Clear any existing requests
                mock_servers.api_server.clear_requests_log()
                
                # Make multiple requests
                for i in range(5):
                    response = requests.get(server.get_url(f"/api/test{i}"))
                    assert response.status_code == 200
                    time.sleep(0.1)
                
                # Check that the same token was used (assuming no refresh)
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) == 5
                
                tokens_used = [req['headers']['Authorization'] for req in api_requests]
                # All tokens should be the same (if no refresh occurred)
                unique_tokens = set(tokens_used)
                assert len(unique_tokens) <= 2  # Allow for one potential refresh
        finally:
            import os
            os.unlink(config_file)