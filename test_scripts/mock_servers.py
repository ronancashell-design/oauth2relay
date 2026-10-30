# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Fijomi Systems SL

"""
Mock servers for OAuth2Relay testing
"""
import base64
import json
import time
from urllib.parse import unquote_plus
from typing import Dict, Any, Optional
from flask import Flask, request, jsonify
from requests.structures import CaseInsensitiveDict
import threading
from werkzeug.serving import make_server
import jwt


class MockOAuth2Server:
    """Mock OAuth2 authentication server."""
    
    def __init__(self, host: str = "127.0.0.1", port: int = 9081):
        self.host = host
        self.port = port
        self.app = Flask(__name__)
        self.server = None
        self.thread = None
        self.tokens = {}  # Store issued tokens
        self.token_requests_log = []  # Requests received by /token
        self.setup_routes()

    def _client_credentials(self):
        """Return (client_id, client_secret) from an Authorization: Basic
        header (RFC 6749 section 2.3.1) or the form, or None when a request
        uses both."""
        auth = request.headers.get('Authorization', '')
        if auth.startswith('Basic '):
            if 'client_id' in request.form or 'client_secret' in request.form:
                return None
            decoded = base64.b64decode(auth[len('Basic '):]).decode()
            client_id, _, client_secret = decoded.partition(':')
            return unquote_plus(client_id), unquote_plus(client_secret)
        return request.form.get('client_id'), request.form.get('client_secret')

    def setup_routes(self):
        """Set up OAuth2 server routes."""
        
        @self.app.route('/token', methods=['POST'])
        def token_endpoint():
            """OAuth2 token endpoint supporting multiple grant types."""
            self.token_requests_log.append({
                'form': request.form.to_dict(),
                'headers': CaseInsensitiveDict(dict(request.headers)),
            })
            grant_type = request.form.get('grant_type')
            credentials = self._client_credentials()
            if credentials is None:
                return jsonify({'error': 'invalid_request',
                                'error_description': 'more than one client authentication method'}), 400
            
            if grant_type == 'client_credentials':
                client_id, client_secret = credentials
                
                if not client_id or not client_secret:
                    return jsonify({'error': 'invalid_request'}), 400
                
                if client_id != 'test_client' or client_secret != 'test_secret':
                    return jsonify({'error': 'invalid_client'}), 401
                
                return self._generate_token_response()
            
            elif grant_type == 'password':
                username = request.form.get('username')
                password = request.form.get('password')
                client_id, client_secret = credentials
                
                if not all([username, password, client_id, client_secret]):
                    return jsonify({'error': 'invalid_request'}), 400
                
                if (username != 'testuser' or password != 'testpass' or 
                    client_id != 'test_client' or client_secret != 'test_secret'):
                    return jsonify({'error': 'invalid_grant'}), 400
                
                return self._generate_token_response()
            
            elif grant_type in ('urn:ietf:params:oauth:grant-type:jwt-bearer', 'jwt-bearer'):
                assertion = request.form.get('assertion')
                if not assertion:
                    return jsonify({'error': 'invalid_request'}), 400
                
                try:
                    # Verify JWT
                    payload = jwt.decode(assertion, 'test_jwt_secret', algorithms=['HS256'],
                                         audience='test_audience')
                    return self._generate_token_response()
                except jwt.InvalidTokenError:
                    return jsonify({'error': 'invalid_grant'}), 400
            
            else:
                return jsonify({'error': 'unsupported_grant_type'}), 400
        
        @self.app.route('/refresh', methods=['POST'])
        def refresh_endpoint():
            """OAuth2 token refresh endpoint."""
            content_type = request.headers.get('Content-Type', '')
            
            if 'application/x-www-form-urlencoded' in content_type:
                refresh_token = request.form.get('refresh_token')
            else:
                # Handle JSON or other formats
                data = request.get_data(as_text=True)
                if 'refresh_token=' in data:
                    refresh_token = data.split('refresh_token=')[1].split('&')[0]
                else:
                    try:
                        json_data = json.loads(data)
                        refresh_token = json_data.get('token')
                    except:
                        refresh_token = None
            
            if not refresh_token or refresh_token not in self.tokens:
                return jsonify({'error': 'invalid_grant'}), 400
            
            return self._generate_token_response()
        
        @self.app.route('/login', methods=['GET'])
        def custom_login():
            """Custom login endpoint for legacy authentication."""
            auth_header = request.headers.get('Authorization', '')
            
            if not auth_header.startswith('Basic '):
                return jsonify({'error': 'unauthorized'}), 401
            
            # For testing, accept any basic auth
            return jsonify({
                'AccessToken': 'custom_access_token_' + str(int(time.time())),
                'RefreshToken': 'custom_refresh_token_' + str(int(time.time())),
                'ExpiresIn': 3600,
                'TokenType': 'Bearer'
            })
        
        @self.app.route('/userinfo', methods=['GET'])
        def userinfo_endpoint():
            """OAuth2 userinfo endpoint for testing."""
            auth_header = request.headers.get('Authorization', '')
            
            if not auth_header.startswith('Bearer '):
                return jsonify({'error': 'invalid_token'}), 401
            
            return jsonify({
                'sub': 'test_user',
                'name': 'Test User',
                'email': 'test@example.com'
            })
        
        @self.app.route('/health', methods=['GET'])
        def health_check():
            """Health check endpoint."""
            return jsonify({'status': 'ok'})
    
    def _generate_token_response(self) -> tuple:
        """Generate a standard OAuth2 token response."""
        access_token = f"access_token_{int(time.time())}"
        refresh_token = f"refresh_token_{int(time.time())}"
        
        # Store the tokens for validation
        self.tokens[refresh_token] = {
            'access_token': access_token,
            'issued_at': time.time()
        }
        
        response_data = {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'expires_in': 3600,
            'token_type': 'Bearer'
        }
        
        return jsonify(response_data), 200
    
    def start(self):
        """Start the mock OAuth2 server."""
        if self.thread and self.thread.is_alive():
            return
        
        self.server = make_server(self.host, self.port, self.app, threaded=True)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()
        
        # Wait a bit for server to start
        time.sleep(0.5)
    
    def stop(self):
        """Stop the mock OAuth2 server."""
        if self.server:
            self.server.shutdown()
            self.server = None
        if self.thread:
            self.thread.join(timeout=1)
            self.thread = None


class MockAPIServer:
    """Mock API server to receive relayed requests."""
    
    def __init__(self, host: str = "127.0.0.1", port: int = 9998):
        self.host = host
        self.port = port
        self.app = Flask(__name__)
        self.server = None
        self.thread = None
        self.requests_log = []  # Log of received requests
        self.setup_routes()
    
    def setup_routes(self):
        """Set up API server routes."""
        
        @self.app.route('/api', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE'])
        @self.app.route('/api/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
        def api_endpoint(path):
            """Generic API endpoint that logs all requests."""
            request_data = {
                'method': request.method,
                'path': '/' + path if path else '/',
                'headers': dict(request.headers),
                'query_params': dict(request.args),
                'body': request.get_data(as_text=True),
                'json': request.get_json(silent=True),
                'timestamp': time.time()
            }
            
            # Header names are case-insensitive (Go sends "X-Client-Id" for
            # "X-Client-ID"), so log them in a case-insensitive dict.
            self.requests_log.append({**request_data, 'headers': CaseInsensitiveDict(request_data['headers'])})
            
            # Return request details for verification
            return jsonify({
                'received': request_data,
                'status': 'ok'
            })
        
        @self.app.route('/secure', methods=['GET', 'POST'])
        def secure_endpoint():
            """Secure endpoint that requires valid authorization."""
            auth_header = request.headers.get('Authorization', '')
            
            if not auth_header.startswith('Bearer '):
                return jsonify({'error': 'unauthorized'}), 401
            
            token = auth_header.split(' ')[1]
            if not token.startswith('access_token_'):
                return jsonify({'error': 'invalid_token'}), 401
            
            return jsonify({
                'message': 'Access granted',
                'token_used': token,
                'client_ip': request.headers.get('X-Forwarded-For', request.remote_addr)
            })
        
        @self.app.route('/echo', methods=['GET', 'POST'])
        def echo_endpoint():
            """Echo endpoint that returns request details."""
            return jsonify({
                'method': request.method,
                'headers': dict(request.headers),
                'query_params': dict(request.args),
                'body': request.get_data(as_text=True),
                'json': request.get_json(silent=True)
            })
        
        @self.app.route('/health', methods=['GET'])
        def health_check():
            """Health check endpoint."""
            return jsonify({'status': 'ok'})
    
    def start(self):
        """Start the mock API server."""
        if self.thread and self.thread.is_alive():
            return
        
        self.server = make_server(self.host, self.port, self.app, threaded=True)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()
        
        # Wait a bit for server to start
        time.sleep(0.5)
    
    def stop(self):
        """Stop the mock API server."""
        if self.server:
            self.server.shutdown()
            self.server = None
        if self.thread:
            self.thread.join(timeout=1)
            self.thread = None
    
    def get_requests_log(self) -> list:
        """Get the log of received requests."""
        return self.requests_log.copy()
    
    def clear_requests_log(self):
        """Clear the requests log."""
        self.requests_log.clear()


class MockServerManager:
    """Manages multiple mock servers for testing."""
    
    def __init__(self):
        self.oauth_server = MockOAuth2Server()
        self.api_server = MockAPIServer()
    
    def start_all(self):
        """Start all mock servers."""
        self.oauth_server.start()
        self.api_server.start()
    
    def stop_all(self):
        """Stop all mock servers."""
        self.oauth_server.stop()
        self.api_server.stop()
    
    def __enter__(self):
        self.start_all()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop_all()


if __name__ == "__main__":
    # Test the mock servers
    import requests
    
    with MockServerManager() as servers:
        # Test OAuth2 server
        response = requests.post("http://127.0.0.1:9081/token", data={
            'grant_type': 'client_credentials',
            'client_id': 'test_client',
            'client_secret': 'test_secret'
        })
        print("OAuth2 Token Response:", response.json())
        
        # Test API server
        response = requests.get("http://127.0.0.1:9998/api/test")
        print("API Response:", response.json())
        
        print("Mock servers working correctly!")