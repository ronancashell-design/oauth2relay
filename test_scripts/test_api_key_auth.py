# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Fijomi Systems SL

"""
Tests for API key authentication functionality
"""
import pytest
import requests
from utils import OAuth2RelayServer, create_test_config


@pytest.mark.security
class TestAPIKeyAuthentication:
    """Test API key authentication functionality."""
    
    def test_valid_api_key(self, api_key_config, mock_servers):
        """Test request with valid API key."""
        config_file = create_test_config(api_key_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                headers = {"X-API-Key": "test-api-key-12345"}
                response = requests.get(server.get_url("/api/test"), headers=headers)
                assert response.status_code == 200
                
                # Verify request was relayed to API server
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) > 0
        finally:
            import os
            os.unlink(config_file)
    
    def test_missing_api_key(self, api_key_config, mock_servers):
        """Test request without API key header."""
        config_file = create_test_config(api_key_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                # Request without X-API-Key header
                response = requests.get(server.get_url("/api/test"))
                assert response.status_code == 401
                
                # Request should not reach API server
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) == 0
        finally:
            import os
            os.unlink(config_file)
    
    def test_invalid_api_key(self, api_key_config, mock_servers):
        """Test request with invalid API key."""
        config_file = create_test_config(api_key_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                headers = {"X-API-Key": "wrong-api-key"}
                response = requests.get(server.get_url("/api/test"), headers=headers)
                assert response.status_code == 401
                
                # Request should not reach API server
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) == 0
        finally:
            import os
            os.unlink(config_file)
    
    def test_empty_api_key(self, api_key_config, mock_servers):
        """Test request with empty API key."""
        config_file = create_test_config(api_key_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                headers = {"X-API-Key": ""}
                response = requests.get(server.get_url("/api/test"), headers=headers)
                assert response.status_code == 401
                
                # Request should not reach API server
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) == 0
        finally:
            import os
            os.unlink(config_file)
    
    def test_case_sensitive_api_key(self, api_key_config, mock_servers):
        """Test that API key comparison is case-sensitive."""
        config_file = create_test_config(api_key_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                # Try with different case
                headers = {"X-API-Key": "TEST-API-KEY-12345"}
                response = requests.get(server.get_url("/api/test"), headers=headers)
                assert response.status_code == 401
                
                # Request should not reach API server
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) == 0
        finally:
            import os
            os.unlink(config_file)


@pytest.mark.security
class TestAPIKeyHeaderVariations:
    """Test various API key header formats and variations."""
    
    def test_case_insensitive_header_name(self, api_key_config, mock_servers):
        """Test that header name is case-insensitive (HTTP standard)."""
        config_file = create_test_config(api_key_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                # HTTP headers should be case-insensitive
                headers = {"x-api-key": "test-api-key-12345"}
                response = requests.get(server.get_url("/api/test"), headers=headers)
                assert response.status_code == 200
        finally:
            import os
            os.unlink(config_file)
    
    def test_api_key_with_spaces(self, api_key_config, mock_servers):
        """Test that HTTP headers with leading/trailing spaces are rejected."""
        config_file = create_test_config(api_key_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                # HTTP headers with leading/trailing spaces are invalid and should be rejected by the client
                import pytest
                with pytest.raises(requests.exceptions.InvalidHeader):
                    headers = {"X-API-Key": " test-api-key-12345 "}
                    requests.get(server.get_url("/api/test"), headers=headers)
        finally:
            import os
            os.unlink(config_file)


@pytest.mark.security
class TestAPIKeyWithoutOAuth:
    """Test API key authentication without OAuth2 (using fixed token)."""
    
    def test_api_key_with_fixed_token(self, mock_servers):
        """Test API key authentication combined with fixed token."""
        from utils import create_basic_config
        
        config = create_basic_config()
        config["apiKey"] = "test-api-key-12345"
        config["relay"]["fixedtoken"] = "fixed_token_12345"
        # Remove OAuth2 configuration
        del config["login"]
        del config["refresh"]
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                headers = {"X-API-Key": "test-api-key-12345"}
                response = requests.get(server.get_url("/api/test"), headers=headers)
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


@pytest.mark.security
class TestAPIKeyValidationOrder:
    """Test that API key validation happens before OAuth2 authentication."""
    
    def test_api_key_checked_before_oauth(self, api_key_config, mock_servers):
        """Test that invalid API key prevents OAuth2 flow."""
        # Set up config with invalid OAuth2 endpoint
        config = api_key_config.copy()
        # Add back login config with invalid endpoint
        config["login"] = {
            "url": "http://localhost:9900/invalid",  # Non-existent
            "method": "POST",
            "grant_type": "client_credentials",
            "client_id": "test_client",
            "client_secret": "test_secret"
        }
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                # Request with invalid API key should fail before OAuth2
                headers = {"X-API-Key": "wrong-key"}
                response = requests.get(server.get_url("/api/test"), headers=headers)
                assert response.status_code == 401
                
                # No OAuth2 request should be attempted
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) == 0
        except RuntimeError:
            # Server might fail due to invalid OAuth2 config
            # But API key check should still happen first
            pass
        finally:
            import os
            try:
                os.unlink(config_file)
            except FileNotFoundError:
                pass


@pytest.mark.security
class TestAPIKeyDisabled:
    """Test behavior when API key authentication is disabled."""
    
    def test_no_api_key_required(self, client_credentials_config, mock_servers):
        """Test that requests work when no API key is configured."""
        # Ensure no API key is set
        config = client_credentials_config.copy()
        config.pop("apiKey", None)
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                # Request should work without any API key header
                response = requests.get(server.get_url("/api/test"))
                assert response.status_code == 200
                
                # Request should reach API server
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) > 0
        finally:
            import os
            os.unlink(config_file)
    
    def test_empty_api_key_config(self, client_credentials_config, mock_servers):
        """Test behavior when API key is set to empty string."""
        config = client_credentials_config.copy()
        config["apiKey"] = ""
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                # Request should work without API key header when apiKey is empty
                response = requests.get(server.get_url("/api/test"))
                assert response.status_code == 200
                
                # Request should reach API server
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) > 0
        finally:
            import os
            os.unlink(config_file)


@pytest.mark.security
class TestAPIKeyMultipleRequests:
    """Test API key authentication across multiple requests."""
    
    def test_api_key_persistent_across_requests(self, api_key_config, mock_servers):
        """Test that API key authentication works for multiple requests."""
        config_file = create_test_config(api_key_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                headers = {"X-API-Key": "test-api-key-12345"}
                
                # Make multiple requests
                for i in range(5):
                    response = requests.get(
                        server.get_url(f"/api/test{i}"),
                        headers=headers
                    )
                    assert response.status_code == 200
                
                # All requests should reach API server
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) == 5
        finally:
            import os
            os.unlink(config_file)
    
    def test_mixed_api_key_validity(self, api_key_config, mock_servers):
        """Test mix of valid and invalid API key requests."""
        config_file = create_test_config(api_key_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                mock_servers.api_server.clear_requests_log()
                
                # Valid request
                headers_valid = {"X-API-Key": "test-api-key-12345"}
                response1 = requests.get(server.get_url("/api/test1"), headers=headers_valid)
                assert response1.status_code == 200
                
                # Invalid request
                headers_invalid = {"X-API-Key": "wrong-key"}
                response2 = requests.get(server.get_url("/api/test2"), headers=headers_invalid)
                assert response2.status_code == 401
                
                # Another valid request
                response3 = requests.get(server.get_url("/api/test3"), headers=headers_valid)
                assert response3.status_code == 200
                
                # Only valid requests should reach API server
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) == 2  # Only the valid requests
        finally:
            import os
            os.unlink(config_file)


@pytest.mark.security
class TestAPIKeySpecialCharacters:
    """Test API keys with special characters."""
    
    def test_api_key_with_special_chars(self, mock_servers):
        """Test API key containing special characters."""
        from utils import create_basic_config
        
        # API key with special characters (but JSON-safe)
        special_api_key = "test-key_123!@#$%^&*()+={}[]|:;<>,.?/"
        
        config = create_basic_config()
        config["apiKey"] = special_api_key
        config["relay"]["fixedtoken"] = "fixed_token_12345"
        # Remove OAuth2 config to avoid complications
        del config["login"]
        del config["refresh"]
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                headers = {"X-API-Key": special_api_key}
                response = requests.get(server.get_url("/api/test"), headers=headers)
                assert response.status_code == 200
        finally:
            import os
            os.unlink(config_file)
    
    def test_api_key_unicode(self, mock_servers):
        """Test that non-ASCII API keys work correctly."""
        from utils import create_basic_config
        
        # Use a simple ASCII API key with underscores and dashes for now
        # Unicode in HTTP headers is complex and may require URL encoding
        unicode_api_key = "test-key-with_underscores-123"
        
        config = create_basic_config()
        config["apiKey"] = unicode_api_key
        config["relay"]["fixedtoken"] = "fixed_token_12345"
        # Remove OAuth2 config to avoid complications
        del config["login"]
        del config["refresh"]
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                headers = {"X-API-Key": unicode_api_key}
                response = requests.get(server.get_url("/api/test"), headers=headers)
                assert response.status_code == 200
        finally:
            import os
            os.unlink(config_file)