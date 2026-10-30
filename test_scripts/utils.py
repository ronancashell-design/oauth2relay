# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Fijomi Systems SL

"""
Shared utilities for OAuth2Relay tests
"""
import json
import os
import signal
import subprocess
import tempfile
import time
from typing import Dict, Any, Optional
import requests
import psutil


def create_test_config(config_data: Dict[str, Any]) -> str:
    """Create a temporary configuration file with the given data."""
    # Disable login retries (default 5 attempts, 60s apart) so failure tests
    # fail fast, unless a test sets them explicitly.
    if isinstance(config_data.get("login"), dict):
        config_data["login"].setdefault("retry_attempts", 1)
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(config_data, f, indent=2)
        return f.name


def wait_for_server(host: str, port: int, timeout: int = 30, process=None) -> bool:
    """Wait for a server to accept TCP connections.

    A plain connect is used rather than an HTTP request so that waiting for the
    relay does not send a request through to the mock API server. If `process`
    is given, stop waiting as soon as it exits.
    """
    import socket
    start_time = time.time()

    while time.time() - start_time < timeout:
        if process is not None and process.poll() is not None:
            return False
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except (OSError, TypeError, ValueError, OverflowError):
            time.sleep(0.1)

    return False


def find_free_port() -> int:
    """Find an available port."""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        s.listen(1)
        port = s.getsockname()[1]
    return port


class OAuth2RelayServer:
    """Context manager for starting and stopping the OAuth2Relay server."""
    
    def __init__(self, config_file: str, binary_path: str = "../oauth2relay", extra_args=(), env=None):
        self.config_file = config_file
        self.binary_path = binary_path
        self.extra_args = list(extra_args)
        # Extra environment variables for the relay, added to this process's.
        self.env = env
        self.process = None
        self.output = None
        self.host = "localhost"
        self.port = None
        
    def __enter__(self):
        import logging
        log = logging.getLogger(__name__)
        # Load config to get port. If the file is missing or invalid, fall
        # back to defaults and let the relay itself reject it.
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)
        except (OSError, ValueError):
            config = {}
        self.port = config.get('port', 8080)
        self.host = config.get('host', 'localhost')
        
        # Start the server
        log.info(f"Starting OAuth2Relay server with config: {self.config_file}")
        # Send the relay's output to a file rather than a pipe: nothing reads
        # a pipe while tests run, and the relay would block once it filled.
        self.output = tempfile.TemporaryFile(mode="w+")
        self.process = subprocess.Popen(
            [self.binary_path, *self.extra_args, self.config_file],
            stdout=self.output,
            stderr=subprocess.STDOUT,
            text=True,
            env={**os.environ, **self.env} if self.env else None
        )
        
        # Wait for server to start
        log.info(f"Waiting for server to start on {self.host}:{self.port}")
        if not wait_for_server(self.host, self.port, timeout=10, process=self.process):
            # Make sure the process has exited, then capture its output
            if self.process.poll() is None:
                self.process.kill()
            self.process.wait()
            error_msg = f"OAuth2Relay server failed to start on {self.host}:{self.port}"
            output = self.read_output()
            if output:
                error_msg += f"\nOUTPUT: {output}"
            self.stop()
            raise RuntimeError(error_msg)
        
        log.info(f"OAuth2Relay server started successfully on {self.host}:{self.port}")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
    
    def stop(self):
        """Stop the server process."""
        import logging
        log = logging.getLogger(__name__)
        if self.process:
            log.info(f"Stopping OAuth2Relay server (PID: {self.process.pid})")
            # Try graceful shutdown first
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
                log.info(f"OAuth2Relay server (PID: {self.process.pid}) terminated gracefully.")
            except subprocess.TimeoutExpired:
                # Force kill if graceful shutdown fails
                log.warning(f"Graceful shutdown of OAuth2Relay server (PID: {self.process.pid}) timed out. Killing.")
                self.process.kill()
                self.process.wait()
                log.warning(f"OAuth2Relay server (PID: {self.process.pid}) killed.")
            self.process = None
        if self.output is not None:
            self.output.close()
            self.output = None
    
    def read_output(self) -> str:
        """Return everything the relay has logged so far."""
        if self.output is None:
            return ""
        self.output.flush()
        self.output.seek(0)
        return self.output.read()

    def get_url(self, path: str = "") -> str:
        """Get the full URL for a given path."""
        return f"http://{self.host}:{self.port}{path}"
    
    def is_running(self) -> bool:
        """Check if the server is running."""
        return self.process is not None and self.process.poll() is None


def create_basic_config(host: str = "localhost", port: Optional[int] = None, 
                       api_key: Optional[str] = None, debug: bool = True) -> Dict[str, Any]:
    """Create a basic configuration template."""
    if port is None:
        port = find_free_port()
    
    config = {
        "port": port,
        "host": host,
        "debug": debug,
        "login": {
            "url": "http://127.0.0.1:9081/token",
            "method": "POST",
            "grant_type": "client_credentials",
            "client_id": "test_client",
            "client_secret": "test_secret",
            "parameters": {
                "AccessToken": "access_token",
                "RefreshToken": "refresh_token",
                "ExpiresIn": "expires_in"
            }
        },
        "refresh": {
            "url": "http://127.0.0.1:9081/refresh",
            "method": "POST",
            "data": "refresh_token=${REFRESHTOKEN}",
            "headers": {
                "Content-Type": "application/x-www-form-urlencoded"
            }
        },
        "relay": {
            "url": "http://127.0.0.1:9998/api",
            "method": "GET",
            "pushheaders": True,
            "headers": {
                "Authorization": "Bearer ${ACCESSTOKEN}"
            },
            "parameters": {
                "client_ip": "${IP}"
            }
        }
    }
    
    if api_key:
        config["apiKey"] = api_key
    
    return config


def cleanup_temp_files(*files: str):
    """Clean up temporary files."""
    for file_path in files:
        try:
            os.unlink(file_path)
        except FileNotFoundError:
            pass


def generate_jwt_token(payload: Dict[str, Any], secret: str = "test_secret") -> str:
    """Generate a JWT token for testing."""
    import jwt
    return jwt.encode(payload, secret, algorithm="HS256")


def decode_jwt_token(token: str, secret: str = "test_secret") -> Dict[str, Any]:
    """Decode a JWT token for testing."""
    import jwt
    return jwt.decode(token, secret, algorithms=["HS256"])


def make_request_with_retries(url: str, method: str = "GET", max_retries: int = 3, 
                            delay: float = 0.5, **kwargs) -> requests.Response:
    """Make an HTTP request with retries."""
    for attempt in range(max_retries):
        try:
            response = requests.request(method, url, **kwargs)
            return response
        except requests.exceptions.ConnectionError as e:
            if attempt == max_retries - 1:
                raise
            time.sleep(delay)
    
    raise RuntimeError("Max retries exceeded")


def assert_valid_token_response(response_data: Dict[str, Any]):
    """Assert that a response contains valid token data."""
    assert "access_token" in response_data, "Response missing access_token"
    assert isinstance(response_data["access_token"], str), "access_token must be string"
    assert len(response_data["access_token"]) > 0, "access_token must not be empty"
    
    if "expires_in" in response_data:
        assert isinstance(response_data["expires_in"], (int, float)), "expires_in must be numeric"
        assert response_data["expires_in"] > 0, "expires_in must be positive"


def get_process_by_port(port: int) -> Optional[psutil.Process]:
    """Find process listening on a specific port."""
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            for conn in proc.connections():
                if conn.laddr.port == port:
                    return proc
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return None


def kill_process_on_port(port: int):
    """Kill any process listening on the specified port."""
    proc = get_process_by_port(port)
    if proc:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except (psutil.NoSuchProcess, psutil.TimeoutExpired):
            try:
                proc.kill()
            except psutil.NoSuchProcess:
                pass
