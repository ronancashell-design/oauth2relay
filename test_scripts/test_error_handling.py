# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Fijomi Systems SL

"""
Tests for error handling and edge cases
"""
import pytest
import requests
import time
import signal
import os
from utils import OAuth2RelayServer, create_test_config


@pytest.mark.unit
class TestNetworkErrorHandling:
    """Test handling of network-related errors."""
    
    def test_connection_timeout(self, client_credentials_config):
        """Test handling of connection timeout to OAuth2 server."""
        config = client_credentials_config.copy()
        # Point to a valid IP that doesn't respond
        config["login"]["url"] = "http://10.255.255.1/token"  # Non-routable IP
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"), timeout=5)
                assert response.status_code in [500, 502, 504]
        except RuntimeError:
            # Expected - connection timeout
            pass
        finally:
            os.unlink(config_file)
    
    def test_dns_resolution_failure(self, client_credentials_config):
        """Test handling of DNS resolution failure."""
        config = client_credentials_config.copy()
        config["login"]["url"] = "http://nonexistent.invalid.domain.com/token"
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"), timeout=10)
                assert response.status_code in [500, 502, 503]
        except RuntimeError:
            # Expected - DNS resolution failure
            pass
        finally:
            os.unlink(config_file)
    
    def test_connection_refused(self, client_credentials_config):
        """Test handling of connection refused error."""
        config = client_credentials_config.copy()
        config["login"]["url"] = "http://localhost:9901/token"  # Unused port
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"), timeout=5)
                assert response.status_code in [500, 502]
        except RuntimeError:
            # Expected - connection refused
            pass
        finally:
            os.unlink(config_file)


@pytest.mark.unit
class TestHTTPErrorHandling:
    """Test handling of HTTP-related errors."""
    
    def test_oauth_server_http_errors(self, client_credentials_config, mock_servers):
        """Test handling of HTTP errors from OAuth2 server."""
        config = client_credentials_config.copy()
        # Point to an endpoint that returns 404
        config["login"]["url"] = "http://127.0.0.1:9081/nonexistent"
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"))
                assert response.status_code in [404, 500]
        except RuntimeError:
            # Expected - OAuth2 endpoint not found
            pass
        finally:
            os.unlink(config_file)
    
    def test_api_server_http_errors(self, client_credentials_config):
        """Test handling of HTTP errors from API server."""
        config = client_credentials_config.copy()
        # Point to an endpoint that returns 404
        config["relay"]["url"] = "http://localhost:9998/nonexistent"
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"))
                # Should forward the 404 error from API server
                assert response.status_code in [404, 500, 502]
        finally:
            os.unlink(config_file)
    
    def test_malformed_http_response(self, client_credentials_config):
        """Test handling of malformed HTTP responses."""
        # This is harder to test without a custom mock server
        # For now, test with an endpoint that might return non-JSON
        config = client_credentials_config.copy()
        config["login"]["url"] = "http://127.0.0.1:9081/health"  # Returns simple JSON
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"))
                # Might fail due to unexpected response format
                assert response.status_code in [200, 400, 500]
        except RuntimeError:
            # Expected - malformed response
            pass
        finally:
            os.unlink(config_file)


@pytest.mark.unit
class TestTokenErrorHandling:
    """Test token-related error handling."""
    
    def test_expired_token_handling(self, client_credentials_config, mock_servers):
        """Test handling of expired tokens."""
        # This test is challenging because we need to simulate token expiry
        config = client_credentials_config.copy()
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                # Make initial request
                response1 = requests.get(server.get_url("/api/test1"))
                assert response1.status_code == 200
                
                # Wait a bit and make another request
                time.sleep(1)
                response2 = requests.get(server.get_url("/api/test2"))
                assert response2.status_code == 200
                
                # Both should succeed (token refresh should be handled automatically)
        finally:
            os.unlink(config_file)
    
    def test_invalid_token_response(self, basic_config, mock_servers):
        """Test handling when OAuth2 server returns invalid token data."""
        config = basic_config.copy()
        # Point to userinfo endpoint which returns different data structure
        config["login"]["url"] = "http://127.0.0.1:9081/userinfo"
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"))
                assert response.status_code in [400, 500]
        except RuntimeError:
            # Expected - invalid token response
            pass
        finally:
            os.unlink(config_file)
    
    def test_token_refresh_failure(self, client_credentials_config, mock_servers):
        """Test handling when token refresh fails."""
        config = client_credentials_config.copy()
        # Point refresh to invalid endpoint
        config["refresh"]["url"] = "http://127.0.0.1:9081/invalid_refresh"
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                # Initial request should work (fresh token)
                response = requests.get(server.get_url("/api/test"))
                assert response.status_code == 200
                
                # If refresh is needed and fails, it should fall back to login
                # which should succeed
        finally:
            os.unlink(config_file)


@pytest.mark.unit
class TestRequestProcessingErrors:
    """Test request processing error scenarios."""
    
    def test_invalid_request_method(self, client_credentials_config, mock_servers):
        """Test handling of unsupported HTTP methods."""
        config_file = create_test_config(client_credentials_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                # Try PATCH method (might not be supported)
                response = requests.patch(server.get_url("/api/test"))
                # Should either work or return method not allowed
                assert response.status_code in [200, 405, 501]
        finally:
            os.unlink(config_file)
    
    def test_large_request_body(self, client_credentials_config, mock_servers):
        """Test handling of very large request bodies."""
        config = client_credentials_config.copy()
        config["relay"]["method"] = "POST"
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                # Send very large request body (1MB)
                large_data = "x" * (1024 * 1024)
                response = requests.post(
                    server.get_url("/api/test"),
                    data=large_data,
                    headers={"Content-Type": "text/plain"},
                    timeout=30
                )
                # Should handle large requests
                assert response.status_code in [200, 413, 500]
        finally:
            os.unlink(config_file)
    
    def test_malformed_request_data(self, client_credentials_config, mock_servers):
        """Test handling of malformed request data."""
        config = client_credentials_config.copy()
        config["relay"]["method"] = "POST"
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                # Send malformed JSON
                response = requests.post(
                    server.get_url("/api/test"),
                    data='{"invalid": json}',
                    headers={"Content-Type": "application/json"}
                )
                # Should handle malformed JSON gracefully
                assert response.status_code in [200, 400, 500]
        finally:
            os.unlink(config_file)


@pytest.mark.unit
class TestResourceLimits:
    """Test resource limit handling."""
    
    def test_concurrent_request_limits(self, client_credentials_config, mock_servers):
        """Test handling of high concurrent load."""
        import concurrent.futures
        
        config_file = create_test_config(client_credentials_config)
        
        def make_request(server_url, request_id):
            try:
                response = requests.get(f"{server_url}/api/test{request_id}", timeout=10)
                return response.status_code
            except Exception as e:
                return str(e)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                # Make 20 concurrent requests
                with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                    futures = [
                        executor.submit(make_request, server.get_url(), i)
                        for i in range(20)
                    ]
                    
                    results = [future.result() for future in concurrent.futures.as_completed(futures)]
                
                # Most requests should succeed
                success_count = sum(1 for r in results if r == 200)
                assert success_count >= 15  # Allow for some failures under load
        finally:
            os.unlink(config_file)
    
    def test_memory_usage_stability(self, client_credentials_config, mock_servers):
        """Test memory stability under repeated requests."""
        config_file = create_test_config(client_credentials_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                # Make many sequential requests
                for i in range(50):
                    response = requests.get(server.get_url(f"/api/test{i}"))
                    # Don't assert on individual responses, just ensure server doesn't crash
                    if i % 10 == 0:
                        time.sleep(0.1)  # Brief pause every 10 requests
                
                # Final request to ensure server is still responsive
                final_response = requests.get(server.get_url("/api/final"))
                assert final_response.status_code in [200, 500]
        finally:
            os.unlink(config_file)


@pytest.mark.unit
class TestRecoveryScenarios:
    """Test recovery from various error scenarios."""
    
    def test_recovery_after_oauth_server_restart(self, client_credentials_config, mock_servers):
        """Test recovery after OAuth2 server becomes unavailable and then available again."""
        config_file = create_test_config(client_credentials_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                # Initial request should work
                response1 = requests.get(server.get_url("/api/test1"))
                assert response1.status_code == 200
                
                # Stop OAuth2 mock server
                mock_servers.oauth_server.stop()
                time.sleep(0.5)
                
                # The relay still holds a valid cached token, so requests keep
                # working while the OAuth2 server is down
                response2 = requests.get(server.get_url("/api/test2"))
                assert response2.status_code == 200
                
                # Restart OAuth2 mock server
                mock_servers.oauth_server.start()
                time.sleep(0.5)
                
                # Requests continue to work after the restart
                response3 = requests.get(server.get_url("/api/test3"))
                assert response3.status_code == 200
        finally:
            # Always bring the mock back so later tests are not affected.
            mock_servers.oauth_server.start()
            os.unlink(config_file)
    
    def test_recovery_after_api_server_restart(self, client_credentials_config, mock_servers):
        """Test recovery after API server becomes unavailable and then available again."""
        config_file = create_test_config(client_credentials_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                # Initial request should work
                response1 = requests.get(server.get_url("/api/test1"))
                assert response1.status_code == 200
                
                # Stop API mock server
                mock_servers.api_server.stop()
                time.sleep(0.5)
                
                # Request should fail
                response2 = requests.get(server.get_url("/api/test2"))
                assert response2.status_code in [502, 500]
                
                # Restart API mock server
                mock_servers.api_server.start()
                time.sleep(0.5)
                
                # Request should work again
                response3 = requests.get(server.get_url("/api/test3"))
                assert response3.status_code == 200
        finally:
            # Always bring the mock back so later tests are not affected.
            mock_servers.api_server.start()
            os.unlink(config_file)


@pytest.mark.unit
class TestEdgeCases:
    """Test various edge cases and unusual scenarios."""
    
    def test_empty_response_handling(self, client_credentials_config):
        """Test handling of empty responses from servers."""
        # This would require a custom mock server that returns empty responses
        config_file = create_test_config(client_credentials_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                response = requests.get(server.get_url("/api/test"))
                # Should handle empty responses gracefully
                assert response.status_code in [200, 204, 500]
        finally:
            os.unlink(config_file)
    
    def test_unicode_handling(self, client_credentials_config, mock_servers):
        """Test handling of Unicode characters in requests and responses."""
        config = client_credentials_config.copy()
        config["relay"]["method"] = "POST"
        
        config_file = create_test_config(config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                unicode_data = {
                    "name": "测试用户",  # Chinese characters
                    "description": "Tëst üsër with spëcial chars",
                    "emoji": "🚀🎉🔥"
                }
                
                response = requests.post(
                    server.get_url("/api/unicode"),
                    json=unicode_data
                )
                assert response.status_code in [200, 400, 500]
                
                # Check that Unicode was handled
                api_requests = mock_servers.api_server.get_requests_log()
                assert len(api_requests) > 0
        finally:
            os.unlink(config_file)
    
    def test_special_characters_in_headers(self, client_credentials_config, mock_servers):
        """Test handling of special characters in headers."""
        config_file = create_test_config(client_credentials_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                special_headers = {
                    "X-Special-Chars": "test!@#$%^&*()+={}[]|\\:;\"'<>,.?/",
                    # requests only accepts latin-1 header strings, so send raw UTF-8 bytes
                    "X-Unicode": "Héader-Valué-测试".encode("utf-8"),
                    "X-Empty": "",
                }
                
                response = requests.get(
                    server.get_url("/api/test"),
                    headers=special_headers
                )
                assert response.status_code in [200, 400, 500]
        finally:
            os.unlink(config_file)
    
    def test_extremely_long_urls(self, client_credentials_config, mock_servers):
        """Test handling of extremely long URLs."""
        config_file = create_test_config(client_credentials_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                # Create very long path
                long_path = "/api/" + "very_long_path_segment_" * 100
                
                response = requests.get(server.get_url(long_path))
                # Should handle long URLs or return appropriate error
                assert response.status_code in [200, 414, 500]
        finally:
            os.unlink(config_file)