# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Fijomi Systems SL

"""
Tests for OAuth2 authentication flows
"""
import pytest
import requests
import json
import time
from utils import OAuth2RelayServer, create_test_config, make_request_with_retries, assert_valid_token_response


@pytest.mark.oauth
class TestClientCredentialsFlow:
    """Test client credentials grant flow."""
    
    def test_client_credentials_success(self, client_credentials_config, mock_servers):
        """Test successful client credentials authentication."""
        config_file = create_test_config(client_credentials_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                # Make a request that should trigger authentication
                response = requests.get(server.get_url("/api/test"))
                assert response.status_code == 200
                
                # Check that the mock API server received the request with Bearer token
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) > 0
                
                last_request = api_requests[-1]
                auth_header = last_request['headers'].get('Authorization', '')
                assert auth_header.startswith('Bearer access_token_')
        finally:
            import os
            os.unlink(config_file)
    
    def test_client_credentials_invalid_client(self, client_credentials_config, mock_servers):
        """Test client credentials with invalid client credentials."""
        client_credentials_config["login"]["client_secret"] = "wrong_secret"
        config_file = create_test_config(client_credentials_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"))
                # Should fail to authenticate and return an error
                assert response.status_code in [401, 500]
        except RuntimeError:
            # Server might fail to start due to authentication failure
            pass
        finally:
            import os
            try:
                os.unlink(config_file)
            except FileNotFoundError:
                pass
    
    def test_client_credentials_missing_parameters(self, basic_config, mock_servers):
        """Test client credentials with missing required parameters."""
        config = basic_config.copy()
        config["login"]["grant_type"] = "client_credentials"
        del config["login"]["client_id"]  # Remove required parameter
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"))
                assert response.status_code in [400, 500]
        except RuntimeError:
            # Expected - server should fail to start or authenticate
            pass
        finally:
            import os
            try:
                os.unlink(config_file)
            except FileNotFoundError:
                pass


@pytest.mark.oauth
class TestGrantParameters:
    """scope, audience, resource, client_auth and login.headers for the standard grants."""

    def _token_request(self, mock_servers, config):
        """Start the relay with config, send one request through it and return
        the last request the identity provider received."""
        config_file = create_test_config(config)
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"))
                assert response.status_code == 200
        finally:
            import os
            os.unlink(config_file)
        token_requests = mock_servers.oauth_server.token_requests_log
        assert token_requests, "the identity provider received no token request"
        return token_requests[-1]

    def test_client_credentials_sends_scope_audience_resource(self, client_credentials_config, mock_servers):
        login = client_credentials_config["login"]
        login["scope"] = "api://relay-test/.default"
        login["audience"] = "https://api.example.com"
        login["resource"] = "https://api.example.com/v1"
        received = self._token_request(mock_servers, client_credentials_config)
        assert received['form'] == {
            'grant_type': 'client_credentials',
            'client_id': 'test_client',
            'client_secret': 'test_secret',
            'scope': 'api://relay-test/.default',
            'audience': 'https://api.example.com',
            'resource': 'https://api.example.com/v1',
        }

    def test_client_credentials_without_parameters_unchanged(self, client_credentials_config, mock_servers):
        received = self._token_request(mock_servers, client_credentials_config)
        assert received['form'] == {
            'grant_type': 'client_credentials',
            'client_id': 'test_client',
            'client_secret': 'test_secret',
        }
        assert 'Authorization' not in received['headers']

    def test_client_credentials_basic_auth(self, client_credentials_config, mock_servers):
        import base64
        client_credentials_config["login"]["client_auth"] = "basic"
        client_credentials_config["login"]["scope"] = "read write"
        received = self._token_request(mock_servers, client_credentials_config)
        assert received['form'] == {'grant_type': 'client_credentials', 'scope': 'read write'}
        expected = base64.b64encode(b"test_client:test_secret").decode()
        assert received['headers']['Authorization'] == f"Basic {expected}"

    def test_password_grant_basic_auth_and_scope(self, password_grant_config, mock_servers):
        password_grant_config["login"]["client_auth"] = "basic"
        password_grant_config["login"]["scope"] = "openid"
        received = self._token_request(mock_servers, password_grant_config)
        assert received['form'] == {
            'grant_type': 'password', 'username': 'testuser', 'password': 'testpass', 'scope': 'openid',
        }
        assert received['headers']['Authorization'].startswith('Basic ')

    def test_jwt_grant_sends_scope_parameter(self, jwt_grant_config, mock_servers):
        jwt_grant_config["login"]["scope"] = "reports.read"
        received = self._token_request(mock_servers, jwt_grant_config)
        assert received['form']['scope'] == 'reports.read'
        assert 'assertion' in received['form']
        assert 'client_id' not in received['form']

    def test_login_headers_sent_with_standard_grant(self, client_credentials_config, mock_servers):
        client_credentials_config["login"]["headers"] = {
            "X-Gateway-Key": "gw-123",
            "content-type": "text/plain",
        }
        received = self._token_request(mock_servers, client_credentials_config)
        assert received['headers']['X-Gateway-Key'] == 'gw-123'
        assert received['headers']['Content-Type'] == 'application/x-www-form-urlencoded'

    def test_scope_rejected_for_custom_grant(self, custom_grant_config, mock_servers):
        custom_grant_config["login"]["scope"] = "read"
        config_file = create_test_config(custom_grant_config)
        try:
            with pytest.raises(RuntimeError) as excinfo:
                with OAuth2RelayServer(config_file):
                    pass
            assert "login.scope applies only to" in str(excinfo.value)
        finally:
            import os
            os.unlink(config_file)

    def test_unknown_client_auth_rejected(self, client_credentials_config, mock_servers):
        client_credentials_config["login"]["client_auth"] = "private_key_jwt"
        config_file = create_test_config(client_credentials_config)
        try:
            with pytest.raises(RuntimeError) as excinfo:
                with OAuth2RelayServer(config_file):
                    pass
            assert 'private_key_jwt' in str(excinfo.value) and 'is not supported (valid: post, basic)' in str(excinfo.value)
        finally:
            import os
            os.unlink(config_file)


@pytest.mark.oauth
class TestPasswordGrantFlow:
    """Test resource owner password credentials grant flow."""
    
    def test_password_grant_success(self, password_grant_config, mock_servers):
        """Test successful password grant authentication."""
        config_file = create_test_config(password_grant_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"))
                assert response.status_code == 200
                
                # Verify Bearer token was used
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) > 0
                
                last_request = api_requests[-1]
                auth_header = last_request['headers'].get('Authorization', '')
                assert auth_header.startswith('Bearer access_token_')
        finally:
            import os
            os.unlink(config_file)
    
    def test_password_grant_invalid_credentials(self, password_grant_config, mock_servers):
        """Test password grant with invalid user credentials."""
        password_grant_config["login"]["password"] = "wrong_password"
        config_file = create_test_config(password_grant_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"))
                assert response.status_code in [401, 500]
        except RuntimeError:
            # Expected authentication failure
            pass
        finally:
            import os
            try:
                os.unlink(config_file)
            except FileNotFoundError:
                pass


@pytest.mark.oauth
class TestJWTGrantFlow:
    """Test JWT bearer grant flow."""
    
    def test_jwt_grant_success(self, jwt_grant_config, mock_servers):
        """Test successful JWT grant authentication."""
        config_file = create_test_config(jwt_grant_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"))
                assert response.status_code == 200
                
                # Verify Bearer token was used
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) > 0
                
                last_request = api_requests[-1]
                auth_header = last_request['headers'].get('Authorization', '')
                assert auth_header.startswith('Bearer access_token_')
        finally:
            import os
            os.unlink(config_file)
    
    def test_jwt_grant_missing_key(self, jwt_grant_config, mock_servers):
        """Test JWT grant with missing JWT key."""
        del jwt_grant_config["login"]["jwt_key"]
        config_file = create_test_config(jwt_grant_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"))
                assert response.status_code in [400, 500]
        except RuntimeError:
            # Expected - missing required parameter
            pass
        finally:
            import os
            try:
                os.unlink(config_file)
            except FileNotFoundError:
                pass


@pytest.mark.oauth
class TestCustomGrantFlow:
    """Test custom/legacy authentication flow."""
    
    def test_custom_grant_success(self, custom_grant_config, mock_servers):
        """Test successful custom grant authentication."""
        config_file = create_test_config(custom_grant_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"))
                assert response.status_code == 200
                
                # Verify Bearer token was used
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) > 0
                
                last_request = api_requests[-1]
                auth_header = last_request['headers'].get('Authorization', '')
                assert auth_header.startswith('Bearer custom_access_token_')
        finally:
            import os
            os.unlink(config_file)
    
    def test_custom_grant_with_authstring(self, custom_grant_config, mock_servers):
        """Test custom grant with explicit auth string."""
        import base64
        auth_string = base64.b64encode(b"testuser:testpass").decode()
        custom_grant_config["login"]["authstring"] = auth_string
        
        config_file = create_test_config(custom_grant_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"))
                assert response.status_code == 200
        finally:
            import os
            os.unlink(config_file)


@pytest.mark.oauth
class TestEnvironmentVariables:
    """Test environment variable substitution in OAuth2 flows."""
    
    def test_environment_variable_substitution(self, password_grant_config, mock_servers):
        """Test that environment variables are substituted in login configuration.

        Only login.user, login.password and login.authstring are expanded, and
        only when the value starts with "$".
        """
        import os
        
        # Set environment variables
        os.environ["TEST_USER"] = "testuser"
        os.environ["TEST_PASSWORD"] = "testpass"
        
        try:
            # Use environment variables in config
            password_grant_config["login"]["user"] = "$TEST_USER"
            password_grant_config["login"]["password"] = "$TEST_PASSWORD"
            
            config_file = create_test_config(password_grant_config)
            
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"))
                assert response.status_code == 200
            
            os.unlink(config_file)
            
        finally:
            # Clean up environment variables
            os.environ.pop("TEST_USER", None)
            os.environ.pop("TEST_PASSWORD", None)


@pytest.mark.oauth
class TestOAuth2ErrorHandling:
    """Test OAuth2 error handling scenarios."""
    
    def test_invalid_oauth_endpoint(self, client_credentials_config, mock_servers):
        """Test handling of invalid OAuth2 endpoint."""
        client_credentials_config["login"]["url"] = "http://127.0.0.1:9081/nonexistent"
        config_file = create_test_config(client_credentials_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"))
                assert response.status_code in [404, 500]
        except RuntimeError:
            # Expected - OAuth2 server should return 404
            pass
        finally:
            import os
            try:
                os.unlink(config_file)
            except FileNotFoundError:
                pass
    
    def test_oauth_server_unavailable(self, client_credentials_config):
        """Test handling when OAuth2 server is unavailable."""
        # Point to non-existent server
        client_credentials_config["login"]["url"] = "http://localhost:9900/token"
        config_file = create_test_config(client_credentials_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"))
                assert response.status_code == 500
        except RuntimeError:
            # Expected - connection should fail
            pass
        finally:
            import os
            try:
                os.unlink(config_file)
            except FileNotFoundError:
                pass
    
    def test_malformed_oauth_response(self, client_credentials_config, mock_servers):
        """Test handling of malformed OAuth2 response."""
        # This would require modifying the mock server to return malformed JSON
        # For now, we test the parameter mapping
        client_credentials_config["login"]["parameters"]["AccessToken"] = "nonexistent_field"
        config_file = create_test_config(client_credentials_config)
        
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
class TestTokenParameterMapping:
    """Test token parameter mapping from OAuth2 responses."""
    
    def test_custom_parameter_mapping(self, client_credentials_config, mock_servers):
        """Test custom parameter mapping in OAuth2 response."""
        # Use different field names
        client_credentials_config["login"]["parameters"] = {
            "AccessToken": "access_token",
            "RefreshToken": "refresh_token",
            "ExpiresIn": "expires_in"
        }
        
        config_file = create_test_config(client_credentials_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"))
                assert response.status_code == 200
        finally:
            import os
            os.unlink(config_file)
    
    def test_missing_required_parameter(self, client_credentials_config, mock_servers):
        """Test handling when required token parameter is missing."""
        # Remove access_token mapping
        del client_credentials_config["login"]["parameters"]["AccessToken"]
        config_file = create_test_config(client_credentials_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"))
                assert response.status_code in [400, 500]
        except RuntimeError:
            # Expected - access token mapping is required
            pass
        finally:
            import os
            try:
                os.unlink(config_file)
            except FileNotFoundError:
                pass