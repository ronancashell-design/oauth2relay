# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Fijomi Systems SL

"""
PyTest configuration and shared fixtures for OAuth2Relay tests
"""
import os
import pytest
import tempfile
from typing import Dict, Any

from mock_servers import MockServerManager
from utils import OAuth2RelayServer, create_test_config, create_basic_config, cleanup_temp_files


@pytest.fixture(scope="session")
def mock_servers():
    """Start mock OAuth2 and API servers for the test session."""
    with MockServerManager() as servers:
        yield servers


@pytest.fixture(autouse=True)
def clear_mock_server_logs(mock_servers):
    """Clear mock server request logs before each test."""
    mock_servers.api_server.clear_requests_log()
    mock_servers.oauth_server.token_requests_log.clear()
    yield
    # Optionally clear after test as well
    mock_servers.api_server.clear_requests_log()


@pytest.fixture
def basic_config():
    """Create a basic test configuration."""
    return create_basic_config()


@pytest.fixture
def config_file(basic_config):
    """Create a temporary configuration file."""
    config_path = create_test_config(basic_config)
    yield config_path
    cleanup_temp_files(config_path)


@pytest.fixture
def oauth2relay_server(config_file, mock_servers):
    """Start OAuth2Relay server with test configuration."""
    with OAuth2RelayServer(config_file) as server:
        yield server


@pytest.fixture
def client_credentials_config():
    """Configuration for client credentials grant testing."""
    config = create_basic_config()
    config["login"]["grant_type"] = "client_credentials"
    config["login"]["client_id"] = "test_client"
    config["login"]["client_secret"] = "test_secret"
    return config


@pytest.fixture
def password_grant_config():
    """Configuration for password grant testing."""
    config = create_basic_config()
    config["login"]["grant_type"] = "password"
    config["login"]["client_id"] = "test_client"
    config["login"]["client_secret"] = "test_secret"
    config["login"]["user"] = "testuser"
    config["login"]["password"] = "testpass"
    return config


@pytest.fixture
def jwt_grant_config():
    """Configuration for JWT grant testing."""
    config = create_basic_config()
    config["login"]["grant_type"] = "jwt"
    config["login"]["jwt_key"] = "test_jwt_secret_with_at_least_32_bytes"
    config["login"]["jwt_issuer"] = "test_issuer"
    config["login"]["jwt_audience"] = "test_audience"
    return config


@pytest.fixture
def custom_grant_config():
    """Configuration for custom/legacy grant testing."""
    config = create_basic_config()
    config["login"] = {
        "url": "http://127.0.0.1:9081/login",
        "method": "GET",
        "user": "testuser",
        "password": "testpass",
        "headers": {
            "Authorization": "Basic ${AUTHSTRING}"
        },
        "parameters": {
            "AccessToken": "AccessToken",
            "RefreshToken": "RefreshToken",
            "ExpiresIn": "ExpiresIn"
        }
    }
    return config


@pytest.fixture
def api_key_config():
    """Configuration with API key authentication."""
    config = create_basic_config()
    config["apiKey"] = "test-api-key-12345"
    config["relay"]["fixedtoken"] = "fixed_token_12345"
    # Remove login config since we're using fixed token
    del config["login"]
    del config["refresh"]
    return config


@pytest.fixture
def fixed_token_config():
    """Configuration using fixed token instead of OAuth2."""
    config = create_basic_config()
    config["relay"]["fixedtoken"] = "fixed_token_12345"
    # Remove login config since we're using fixed token
    del config["login"]
    del config["refresh"]
    return config


@pytest.fixture
def debug_config():
    """Configuration with debug mode enabled."""
    config = create_basic_config()
    config["debug"] = True
    return config


@pytest.fixture
def variable_substitution_config():
    """Configuration to test variable substitution."""
    config = create_basic_config()
    config["relay"]["parameters"] = {
        "client_ip": "${IP}",
        "access_token_param": "${ACCESSTOKEN}",
        "fixed_value": "test_value"
    }
    config["relay"]["headers"]["X-Client-IP"] = "${IP}"
    config["relay"]["headers"]["X-Custom"] = "Bearer ${ACCESSTOKEN}"
    return config


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    # Cleanup handled by tempfile


# @pytest.fixture(autouse=True)
# def cleanup_processes():
#     """Ensure all processes are cleaned up after tests."""
#     yield
#     # This runs after each test
#     from utils import kill_process_on_port
#     import logging
#     log = logging.getLogger(__name__)
#     
#     # Kill any processes that might be left on test ports
#     test_ports = [8080, 9081, 8082, 9998]
#     log.info("Cleaning up processes on ports: %s", test_ports)
#     for port in test_ports:
#         try:
#             kill_process_on_port(port)
#             log.info(f"Successfully cleaned up process on port {port}")
#         except Exception as e:
#             log.error(f"Error cleaning up process on port {port}: {e}")


@pytest.fixture
def secrets_manager_config():
    """Configuration with secrets manager (mocked)."""
    config = create_basic_config()
    config["secrets_managers"] = {
        "test_aws": {
            "type": "aws_secrets_manager",
            "region": "us-east-1",
            "profile": "default"
        }
    }
    # Use secret placeholder in client_secret
    config["login"]["client_secret"] = "${test_aws:test/client_secret}"
    return config


@pytest.fixture
def error_config():
    """Configuration that will cause errors for testing error handling."""
    config = create_basic_config()
    # Invalid OAuth2 endpoint
    config["login"]["url"] = "http://127.0.0.1:9081/invalid_endpoint"
    return config


@pytest.fixture
def performance_config():
    """Configuration for performance testing."""
    config = create_basic_config()
    config["relay"]["pushheaders"] = True
    config["relay"]["parameters"] = {
        f"param_{i}": f"value_{i}" for i in range(10)  # Multiple parameters
    }
    return config


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """Add test result information for better reporting."""
    outcome = yield
    rep = outcome.get_result()
    
    # Add custom information to test reports
    if rep.when == "call":
        setattr(item, "rep_" + rep.when, rep)


def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line("markers", "integration: mark test as integration test")
    config.addinivalue_line("markers", "slow: mark test as slow running")
    config.addinivalue_line("markers", "unit: mark test as unit test")
    config.addinivalue_line("markers", "oauth: mark test as OAuth2 related")
    config.addinivalue_line("markers", "security: mark test as security related")


def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers automatically."""
    for item in items:
        # Add integration marker to integration tests
        if "integration" in item.nodeid:
            item.add_marker(pytest.mark.integration)
        
        # Add oauth marker to OAuth tests
        if "oauth" in item.nodeid or "token" in item.nodeid:
            item.add_marker(pytest.mark.oauth)
        
        # Add security marker to security tests
        if "security" in item.nodeid or "auth" in item.nodeid:
            item.add_marker(pytest.mark.security)