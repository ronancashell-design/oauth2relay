# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Fijomi Systems SL

"""
Tests for variable substitution functionality
"""
import pytest
import requests
import re
from utils import OAuth2RelayServer, create_test_config


@pytest.mark.unit
class TestVariableSubstitution:
    """Test variable substitution in various configuration contexts."""
    
    def test_access_token_substitution(self, variable_substitution_config, mock_servers):
        """Test ${ACCESSTOKEN} variable substitution."""
        config_file = create_test_config(variable_substitution_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"))
                assert response.status_code == 200
                
                # Check that access token was substituted
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) > 0
                
                last_request = api_requests[-1]
                
                # Check header substitution
                auth_header = last_request['headers'].get('Authorization', '')
                assert auth_header.startswith('Bearer access_token_')
                
                # Check custom header substitution
                custom_header = last_request['headers'].get('X-Custom', '')
                assert custom_header.startswith('Bearer access_token_')
                
                # Check parameter substitution
                access_token_param = last_request['query_params'].get('access_token_param', '')
                assert access_token_param.startswith('access_token_')
        finally:
            import os
            os.unlink(config_file)
    
    def test_client_ip_substitution(self, variable_substitution_config, mock_servers):
        """Test ${IP} variable substitution."""
        config_file = create_test_config(variable_substitution_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"))
                assert response.status_code == 200
                
                # Check that client IP was substituted
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) > 0
                
                last_request = api_requests[-1]
                
                # Check parameter substitution
                client_ip = last_request['query_params'].get('client_ip', '')
                assert client_ip != '${IP}'  # Should be substituted
                assert re.match(r'^\d+\.\d+\.\d+\.\d+$', client_ip) or client_ip == '127.0.0.1'
                
                # Check header substitution
                ip_header = last_request['headers'].get('X-Client-IP', '')
                assert ip_header != '${IP}'
                assert re.match(r'^\d+\.\d+\.\d+\.\d+$', ip_header) or ip_header == '127.0.0.1'
        finally:
            import os
            os.unlink(config_file)
    
    def test_fixed_token_substitution(self, mock_servers):
        """Test ${FIXEDTOKEN} variable substitution."""
        from utils import create_basic_config
        
        config = create_basic_config()
        config["relay"]["fixedtoken"] = "my_fixed_token_123"
        config["relay"]["headers"]["X-Token"] = "${FIXEDTOKEN}"
        config["relay"]["parameters"]["token_param"] = "${FIXEDTOKEN}"
        # Remove OAuth2 config since we're using fixed token
        del config["login"]
        del config["refresh"]
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"))
                assert response.status_code == 200
                
                # Check that fixed token was substituted
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) > 0
                
                last_request = api_requests[-1]
                
                # Check header substitution
                token_header = last_request['headers'].get('X-Token', '')
                assert token_header == 'my_fixed_token_123'
                
                # Check parameter substitution
                token_param = last_request['query_params'].get('token_param', '')
                assert token_param == 'my_fixed_token_123'
        finally:
            import os
            os.unlink(config_file)
    
    def test_multiple_variable_substitution(self, mock_servers):
        """Test multiple variables in the same string."""
        from utils import create_basic_config
        
        config = create_basic_config()
        config["relay"]["fixedtoken"] = "fixed123"
        config["relay"]["headers"]["X-Combined"] = "Token: ${FIXEDTOKEN}, IP: ${IP}"
        config["relay"]["parameters"]["combined_param"] = "${FIXEDTOKEN}_${IP}"
        # Remove OAuth2 config
        del config["login"]
        del config["refresh"]
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"))
                assert response.status_code == 200
                
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) > 0
                
                last_request = api_requests[-1]
                
                # Check multiple substitutions in header
                combined_header = last_request['headers'].get('X-Combined', '')
                assert 'Token: fixed123' in combined_header
                assert 'IP: ' in combined_header
                assert combined_header != 'Token: ${FIXEDTOKEN}, IP: ${IP}'
                
                # Check multiple substitutions in parameter
                combined_param = last_request['query_params'].get('combined_param', '')
                assert combined_param.startswith('fixed123_')
                assert combined_param != '${FIXEDTOKEN}_${IP}'
        finally:
            import os
            os.unlink(config_file)
    
    def test_undefined_variable_handling(self, mock_servers):
        """Test handling of undefined variables."""
        from utils import create_basic_config
        
        config = create_basic_config()
        config["relay"]["headers"]["X-Undefined"] = "${UNDEFINED_VAR}"
        config["relay"]["parameters"]["undefined_param"] = "${NOT_DEFINED}"
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"))
                assert response.status_code == 200
                
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) > 0
                
                last_request = api_requests[-1]
                
                # Undefined variables should remain unchanged
                undefined_header = last_request['headers'].get('X-Undefined', '')
                assert undefined_header == '${UNDEFINED_VAR}'
                
                undefined_param = last_request['query_params'].get('undefined_param', '')
                assert undefined_param == '${NOT_DEFINED}'
        finally:
            import os
            os.unlink(config_file)


@pytest.mark.unit
class TestEnvironmentPlaceholders:
    """${env:NAME} placeholders, resolved from the relay's environment at startup."""

    def test_client_secret_from_environment(self, client_credentials_config, mock_servers):
        config = client_credentials_config
        config["login"]["client_secret"] = "${env:O2R_IT_CLIENT_SECRET}"
        config["relay"]["headers"]["X-From-Env"] = "team-${env:O2R_IT_TEAM}"
        config_file = create_test_config(config)
        try:
            env = {"O2R_IT_CLIENT_SECRET": "test_secret", "O2R_IT_TEAM": "payments"}
            # The mock identity provider only accepts client_secret=test_secret,
            # so the relay starts only if the placeholder was resolved.
            with OAuth2RelayServer(config_file, env=env) as server:
                response = requests.get(server.get_url("/api/test"))
                assert response.status_code == 200
                last_request = mock_servers.api_server.get_requests_log()[-1]
                assert last_request['headers'].get('X-From-Env') == 'team-payments'
        finally:
            import os
            os.unlink(config_file)

    def test_unset_variable_stops_startup(self, client_credentials_config, mock_servers):
        config = client_credentials_config
        config["login"]["client_secret"] = "${env:O2R_IT_NOT_SET}"
        config_file = create_test_config(config)
        try:
            with pytest.raises(RuntimeError) as excinfo:
                with OAuth2RelayServer(config_file):
                    pass
            assert "environment variable O2R_IT_NOT_SET is not set" in str(excinfo.value)
        finally:
            import os
            os.unlink(config_file)


@pytest.mark.unit
class TestOAuth2VariableSubstitution:
    """Test variable substitution in OAuth2 contexts."""
    
    def test_login_variable_substitution(self, custom_grant_config, mock_servers):
        """Test variable substitution in login configuration."""
        import base64
        
        config_file = create_test_config(custom_grant_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"))
                assert response.status_code == 200
                
                # The login should have used variable substitution
                # Check that we got a token (indicates login worked)
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) > 0
                
                last_request = api_requests[-1]
                auth_header = last_request['headers'].get('Authorization', '')
                assert 'custom_access_token_' in auth_header
        finally:
            import os
            os.unlink(config_file)
    
    def test_refresh_variable_substitution(self, client_credentials_config, mock_servers):
        """Test variable substitution in refresh configuration."""
        config = client_credentials_config.copy()
        config["refresh"]["headers"]["X-Refresh-Token"] = "${REFRESHTOKEN}"
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"))
                assert response.status_code == 200
                
                # Verify that initial login worked
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) > 0
        finally:
            import os
            os.unlink(config_file)


@pytest.mark.unit
class TestVariableSubstitutionEdgeCases:
    """Test edge cases for variable substitution."""
    
    def test_empty_variable_value(self, mock_servers):
        """Test substitution when variable value is empty."""
        from utils import create_basic_config
        
        config = create_basic_config()
        # No fixed token, so ${FIXEDTOKEN} is an empty string. Login is kept so
        # the relay can still obtain an access token and start.
        config["relay"]["fixedtoken"] = ""
        config["relay"]["headers"]["X-Empty"] = "Value: ${FIXEDTOKEN}"
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"))
                assert response.status_code == 200
                
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) > 0
                
                last_request = api_requests[-1]
                empty_header = last_request['headers'].get('X-Empty', '')
                # Empty substitution; HTTP drops the trailing space from header values
                assert empty_header == 'Value:'
        finally:
            import os
            os.unlink(config_file)
    
    def test_nested_variable_patterns(self, mock_servers):
        """Test handling of nested or malformed variable patterns."""
        from utils import create_basic_config
        
        config = create_basic_config()
        config["relay"]["fixedtoken"] = "test"
        config["relay"]["headers"]["X-Nested"] = "${${FIXEDTOKEN}}"  # Nested
        config["relay"]["headers"]["X-Malformed"] = "${INCOMPLETE"   # Malformed
        config["relay"]["headers"]["X-Multiple"] = "${FIXEDTOKEN} ${FIXEDTOKEN}"
        del config["login"]
        del config["refresh"]
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"))
                assert response.status_code == 200
                
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) > 0
                
                last_request = api_requests[-1]
                
                # Nested patterns should not be processed
                nested_header = last_request['headers'].get('X-Nested', '')
                assert nested_header == '${${FIXEDTOKEN}}'  # Left unchanged
                
                # Malformed patterns should remain unchanged
                malformed_header = last_request['headers'].get('X-Malformed', '')
                assert malformed_header == '${INCOMPLETE'
                
                # Multiple substitutions should work
                multiple_header = last_request['headers'].get('X-Multiple', '')
                assert multiple_header == 'test test'
        finally:
            import os
            os.unlink(config_file)
    
    def test_case_sensitive_variables(self, mock_servers):
        """Test that variable names are case-sensitive."""
        from utils import create_basic_config
        
        config = create_basic_config()
        config["relay"]["fixedtoken"] = "test_token"
        config["relay"]["headers"]["X-Lower"] = "${fixedtoken}"      # Wrong case
        config["relay"]["headers"]["X-Upper"] = "${FIXEDTOKEN}"      # Correct case
        config["relay"]["headers"]["X-Mixed"] = "${FixedToken}"      # Wrong case
        del config["login"]
        del config["refresh"]
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"))
                assert response.status_code == 200
                
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) > 0
                
                last_request = api_requests[-1]
                
                # Wrong case should not be substituted
                lower_header = last_request['headers'].get('X-Lower', '')
                assert lower_header == '${fixedtoken}'
                
                # Correct case should be substituted
                upper_header = last_request['headers'].get('X-Upper', '')
                assert upper_header == 'test_token'
                
                # Wrong case should not be substituted
                mixed_header = last_request['headers'].get('X-Mixed', '')
                assert mixed_header == '${FixedToken}'
        finally:
            import os
            os.unlink(config_file)


@pytest.mark.integration
class TestVariableSubstitutionIntegration:
    """Integration tests for variable substitution across the entire flow."""
    
    def test_end_to_end_variable_flow(self, mock_servers):
        """Test variable substitution from OAuth2 through to relay."""
        from utils import create_basic_config
        
        config = create_basic_config()
        # Custom login with variable substitution
        config["login"] = {
            "url": "http://127.0.0.1:9081/login",
            "method": "GET",
            "user": "testuser",
            "password": "testpass",
            "headers": {
                "Authorization": "Basic ${AUTHSTRING}",
                "X-Client": "oauth2relay"
            },
            "parameters": {
                "AccessToken": "AccessToken",
                "RefreshToken": "RefreshToken",
                "ExpiresIn": "ExpiresIn"
            }
        }
        # Relay with multiple variable substitutions
        config["relay"]["headers"] = {
            "Authorization": "Bearer ${ACCESSTOKEN}",
            "X-Client-IP": "${IP}",
            "X-Service": "oauth2relay"
        }
        config["relay"]["parameters"] = {
            "client_ip": "${IP}",
            "token": "${ACCESSTOKEN}",
            "service": "oauth2relay"
        }
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/complex"))
                assert response.status_code == 200
                
                # Verify all substitutions worked
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) > 0
                
                last_request = api_requests[-1]
                
                # Check authorization header
                auth_header = last_request['headers'].get('Authorization', '')
                assert auth_header.startswith('Bearer custom_access_token_')
                
                # Check IP substitution in header
                ip_header = last_request['headers'].get('X-Client-IP', '')
                assert ip_header != '${IP}'
                
                # Check IP substitution in parameters
                ip_param = last_request['query_params'].get('client_ip', '')
                assert ip_param != '${IP}'
                
                # Check token substitution in parameters
                token_param = last_request['query_params'].get('token', '')
                assert token_param.startswith('custom_access_token_')
                
                # Check static values
                assert last_request['headers'].get('X-Service') == 'oauth2relay'
                assert last_request['query_params'].get('service') == 'oauth2relay'
        finally:
            import os
            os.unlink(config_file)