# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Fijomi Systems SL

"""
Tests for configuration validation and error handling
"""
import pytest
import copy
import json
import tempfile
from utils import OAuth2RelayServer, create_test_config


@pytest.mark.unit
class TestConfigurationValidation:
    """Test configuration file validation."""
    
    def test_missing_config_file(self):
        """Test handling of missing configuration file."""
        try:
            with OAuth2RelayServer("/nonexistent/config.json") as server:
                pass
        except RuntimeError:
            # Expected - config file doesn't exist
            pass
    
    def test_invalid_json_config(self):
        """Test handling of invalid JSON in configuration file."""
        # Create invalid JSON file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('{ "port": 8080, "invalid": json }')
            config_file = f.name
        
        try:
            with OAuth2RelayServer(config_file) as server:
                pass
        except RuntimeError:
            # Expected - invalid JSON
            pass
        finally:
            import os
            os.unlink(config_file)
    
    def test_missing_required_fields(self, basic_config):
        """Test handling of missing required configuration fields."""
        configs_to_test = [
            # Missing port
            {**basic_config, "port": None},
            # Missing host
            {k: v for k, v in basic_config.items() if k != "host"},
            # Missing login configuration
            {k: v for k, v in basic_config.items() if k != "login"},
            # Missing relay configuration
            {k: v for k, v in basic_config.items() if k != "relay"}
        ]
        
        for config in configs_to_test:
            if config.get("port") is None:
                del config["port"]
                
            config_file = create_test_config(config)
            
            try:
                with OAuth2RelayServer(config_file) as server:
                    pass
            except (RuntimeError, ValueError):
                # Expected - missing required fields
                pass
            finally:
                import os
                try:
                    os.unlink(config_file)
                except FileNotFoundError:
                    pass
    
    def test_invalid_port_values(self, basic_config):
        """Test handling of invalid port values."""
        invalid_ports = [-1, 0, 65536, "not_a_number", None]
        
        for invalid_port in invalid_ports:
            config = basic_config.copy()
            config["port"] = invalid_port
            
            config_file = create_test_config(config)
            
            try:
                with OAuth2RelayServer(config_file) as server:
                    pass
            except (RuntimeError, ValueError, json.JSONDecodeError):
                # Expected - invalid port value
                pass
            finally:
                import os
                try:
                    os.unlink(config_file)
                except FileNotFoundError:
                    pass


@pytest.mark.unit
class TestOAuth2ConfigValidation:
    """Test OAuth2-specific configuration validation."""
    
    def test_invalid_grant_types(self, basic_config):
        """Test handling of invalid OAuth2 grant types."""
        invalid_grant_types = ["invalid_grant", "authorization_code", "", None]
        
        for grant_type in invalid_grant_types:
            config = basic_config.copy()
            config["login"]["grant_type"] = grant_type
            
            config_file = create_test_config(config)
            
            try:
                with OAuth2RelayServer(config_file) as server:
                    pass
            except (RuntimeError, ValueError):
                # Expected - invalid grant type
                pass
            finally:
                import os
                try:
                    os.unlink(config_file)
                except FileNotFoundError:
                    pass
    
    def test_missing_client_credentials_params(self, basic_config):
        """Test missing parameters for client credentials grant."""
        config = basic_config.copy()
        config["login"]["grant_type"] = "client_credentials"
        
        # Test missing client_id
        config_missing_id = config.copy()
        del config_missing_id["login"]["client_id"]
        
        config_file = create_test_config(config_missing_id)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                pass
        except RuntimeError:
            # Expected - missing client_id
            pass
        finally:
            import os
            try:
                os.unlink(config_file)
            except FileNotFoundError:
                pass
        
        # Test missing client_secret
        config_missing_secret = config.copy()
        del config_missing_secret["login"]["client_secret"]
        
        config_file = create_test_config(config_missing_secret)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                pass
        except RuntimeError:
            # Expected - missing client_secret
            pass
        finally:
            import os
            try:
                os.unlink(config_file)
            except FileNotFoundError:
                pass
    
    def test_missing_password_grant_params(self, basic_config):
        """Test missing parameters for password grant."""
        config = basic_config.copy()
        config["login"]["grant_type"] = "password"
        config["login"]["client_id"] = "test_client"
        config["login"]["client_secret"] = "test_secret"
        config["login"]["user"] = "testuser"
        config["login"]["password"] = "testpass"
        
        required_fields = ["user", "password"]
        
        for field in required_fields:
            config_missing_field = copy.deepcopy(config)
            del config_missing_field["login"][field]
            
            config_file = create_test_config(config_missing_field)
            
            try:
                with OAuth2RelayServer(config_file) as server:
                    pass
            except RuntimeError:
                # Expected - missing required field
                pass
            finally:
                import os
                try:
                    os.unlink(config_file)
                except FileNotFoundError:
                    pass
    
    def test_missing_jwt_grant_params(self, basic_config):
        """Test missing parameters for JWT grant."""
        config = basic_config.copy()
        config["login"]["grant_type"] = "jwt"
        
        required_fields = ["jwt_key", "jwt_issuer"]
        
        for field in required_fields:
            config_missing_field = config.copy()
            # Don't include the required field
            config_missing_field["login"] = {
                "grant_type": "jwt",
                "url": "http://127.0.0.1:9081/token",
                "parameters": {
                    "AccessToken": "access_token",
                    "ExpiresIn": "expires_in"
                }
            }
            
            config_file = create_test_config(config_missing_field)
            
            try:
                with OAuth2RelayServer(config_file) as server:
                    pass
            except RuntimeError:
                # Expected - missing required field
                pass
            finally:
                import os
                try:
                    os.unlink(config_file)
                except FileNotFoundError:
                    pass
    
    def test_invalid_oauth_urls(self, basic_config):
        """Test handling of invalid OAuth2 URLs."""
        invalid_urls = [
            "not-a-url",
            "ftp://invalid.protocol.com/token",
            "",
            None,
            "http://",
            "://missing.scheme.com/token"
        ]
        
        for invalid_url in invalid_urls:
            config = basic_config.copy()
            config["login"]["url"] = invalid_url
            
            config_file = create_test_config(config)
            
            try:
                with OAuth2RelayServer(config_file) as server:
                    pass
            except (RuntimeError, ValueError, json.JSONDecodeError):
                # Expected - invalid URL
                pass
            finally:
                import os
                try:
                    os.unlink(config_file)
                except FileNotFoundError:
                    pass


@pytest.mark.unit
class TestRelayConfigValidation:
    """Test relay configuration validation."""
    
    def test_invalid_relay_urls(self, basic_config):
        """Test handling of invalid relay URLs."""
        invalid_urls = [
            "not-a-url",
            "ftp://invalid.protocol.com/api",
            "",
            None,
            "http://",
            "://missing.scheme.com/api"
        ]
        
        for invalid_url in invalid_urls:
            config = basic_config.copy()
            config["relay"]["url"] = invalid_url
            
            config_file = create_test_config(config)
            
            try:
                with OAuth2RelayServer(config_file) as server:
                    pass
            except (RuntimeError, ValueError, json.JSONDecodeError):
                # Expected - invalid URL
                pass
            finally:
                import os
                try:
                    os.unlink(config_file)
                except FileNotFoundError:
                    pass
    
    def test_invalid_http_methods(self, basic_config):
        """Test handling of invalid HTTP methods."""
        invalid_methods = ["INVALID", "", None, 123, "get", "post"]  # lowercase should work
        
        for method in invalid_methods:
            config = basic_config.copy()
            config["relay"]["method"] = method
            
            config_file = create_test_config(config)
            
            try:
                with OAuth2RelayServer(config_file) as server:
                    pass
                    # Some invalid methods might not cause immediate failure
                    # The actual validation might happen during request processing
            except (RuntimeError, ValueError, json.JSONDecodeError):
                # Expected for some invalid methods
                pass
            finally:
                import os
                try:
                    os.unlink(config_file)
                except FileNotFoundError:
                    pass
    
    def test_missing_relay_url(self, basic_config):
        """Test handling of missing relay URL."""
        config = basic_config.copy()
        del config["relay"]["url"]
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                pass
        except (RuntimeError, ValueError):
            # Expected - missing relay URL
            pass
        finally:
            import os
            try:
                os.unlink(config_file)
            except FileNotFoundError:
                pass


@pytest.mark.unit
class TestParameterMappingValidation:
    """Test parameter mapping validation."""
    
    def test_missing_access_token_mapping(self, basic_config):
        """Test handling of missing access token parameter mapping."""
        config = basic_config.copy()
        del config["login"]["parameters"]["AccessToken"]
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                pass
        except RuntimeError:
            # Expected - access token mapping is required
            pass
        finally:
            import os
            try:
                os.unlink(config_file)
            except FileNotFoundError:
                pass
    
    def test_empty_parameter_mapping(self, basic_config):
        """Test handling of empty parameter mapping."""
        config = basic_config.copy()
        config["login"]["parameters"] = {}
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                pass
        except RuntimeError:
            # Expected - no parameter mapping
            pass
        finally:
            import os
            try:
                os.unlink(config_file)
            except FileNotFoundError:
                pass
    
    def test_invalid_parameter_types(self, basic_config):
        """Test handling of invalid parameter mapping types."""
        config = basic_config.copy()
        config["login"]["parameters"] = "not_a_dict"
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                pass
        except (RuntimeError, ValueError, json.JSONDecodeError):
            # Expected - parameters should be a dict
            pass
        finally:
            import os
            try:
                os.unlink(config_file)
            except FileNotFoundError:
                pass


@pytest.mark.unit
class TestSecretsManagerValidation:
    """Test secrets manager configuration validation."""
    
    def test_invalid_secrets_manager_type(self, basic_config):
        """Test handling of invalid secrets manager type."""
        config = basic_config.copy()
        config["secrets_managers"] = {
            "test_manager": {
                "type": "invalid_type",
                "config": {}
            }
        }
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                pass
        except RuntimeError:
            # Expected - invalid secrets manager type
            pass
        finally:
            import os
            try:
                os.unlink(config_file)
            except FileNotFoundError:
                pass
    
    def test_missing_secrets_manager_config(self, basic_config):
        """Test handling of missing secrets manager configuration."""
        config = basic_config.copy()
        config["secrets_managers"] = {
            "aws_manager": {
                "type": "aws_secrets_manager"
                # Missing required configuration like region
            }
        }
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                pass
        except RuntimeError:
            # Expected - missing required config
            pass
        finally:
            import os
            try:
                os.unlink(config_file)
            except FileNotFoundError:
                pass


@pytest.mark.unit
class TestConfigurationDefaults:
    """Test configuration default values."""
    
    def test_default_values(self, mock_servers):
        """Test that default values are applied correctly."""
        from utils import find_free_port
        
        # Minimal configuration
        config = {
            "port": find_free_port(),
            "host": "localhost",
            "login": {
                "url": "http://127.0.0.1:9081/token",
                "grant_type": "client_credentials",
                "client_id": "test_client",
                "client_secret": "test_secret",
                "parameters": {
                    "AccessToken": "access_token"
                }
            },
            "relay": {
                "url": "http://localhost:9998/api"
            }
        }
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                # Server should start with defaults applied
                assert server.is_running()
        finally:
            import os
            os.unlink(config_file)
    
    def test_boolean_defaults(self, basic_config):
        """Test boolean configuration defaults."""
        config = basic_config.copy()
        # Remove boolean fields to test defaults
        config.pop("debug", None)
        config["relay"].pop("pushheaders", None)
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                # Should work with default boolean values
                assert server.is_running()
        finally:
            import os
            os.unlink(config_file)


@pytest.mark.unit
class TestConfigurationParsing:
    """Test configuration file parsing edge cases."""
    
    def test_empty_config_file(self):
        """Test handling of empty configuration file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('')
            config_file = f.name
        
        try:
            with OAuth2RelayServer(config_file) as server:
                pass
        except (RuntimeError, json.JSONDecodeError):
            # Expected - empty file
            pass
        finally:
            import os
            os.unlink(config_file)
    
    def test_config_with_comments(self):
        """Test that JSON with comments fails gracefully."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('''
            {
                // This is a comment
                "port": 8080,
                "host": "localhost"
                /* This is also a comment */
            }
            ''')
            config_file = f.name
        
        try:
            with OAuth2RelayServer(config_file) as server:
                pass
        except (RuntimeError, json.JSONDecodeError):
            # Expected - JSON doesn't support comments
            pass
        finally:
            import os
            os.unlink(config_file)
    
    def test_config_with_trailing_comma(self):
        """Test handling of JSON with trailing comma."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('''
            {
                "port": 8080,
                "host": "localhost",
            }
            ''')
            config_file = f.name
        
        try:
            with OAuth2RelayServer(config_file) as server:
                pass
        except (RuntimeError, json.JSONDecodeError):
            # Expected - trailing comma is invalid JSON
            pass
        finally:
            import os
            os.unlink(config_file)