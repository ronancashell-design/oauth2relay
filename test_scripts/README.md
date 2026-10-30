# OAuth2Relay Test Scripts

This directory contains comprehensive test scripts for the OAuth2Relay server. The test suite includes unit tests, integration tests, and end-to-end scenarios covering all major functionality.

## Overview

The test suite validates:
- OAuth2 authentication flows (client_credentials, password, JWT, custom)
- Token management and refresh mechanisms
- Request relaying and header/parameter handling
- API key authentication
- Variable substitution in configurations
- Error handling and edge cases
- Configuration validation
- Performance under load

## Prerequisites

1. **Python 3.7+** - Required for running the test scripts
2. **Go 1.19+** - Required to build the oauth2relay binary
3. **Network access** - Tests use localhost ports 8080, 8082, 9081, 9998

## Setup Instructions

### 1. Install Python Dependencies

```bash
# From the test_scripts directory
pip install -r requirements.txt
```

Or using a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Build the OAuth2Relay Binary

```bash
# From the project root directory
cd ..
go build -o oauth2relay ./cmd/oauth2relay
cd test_scripts
```

### 3. Verify Setup

```bash
# Test that the binary works
../oauth2relay --version

# Test that Python dependencies are installed
python -c "import pytest, requests, flask; print('Dependencies OK')"
```

## Test Structure

| File | Description | Test Count |
|------|-------------|------------|
| `conftest.py` | PyTest configuration and shared fixtures | - |
| `utils.py` | Shared utilities for test execution | - |
| `mock_servers.py` | Mock OAuth2 and API servers | - |
| `test_oauth_flows.py` | OAuth2 authentication flow tests | ~25 tests |
| `test_token_management.py` | Token refresh and lifecycle tests | ~15 tests |
| `test_relay_functionality.py` | Request relaying and forwarding tests | ~20 tests |
| `test_api_key_auth.py` | API key authentication tests | ~15 tests |
| `test_variable_substitution.py` | Variable substitution tests | ~20 tests |
| `test_integration.py` | End-to-end integration tests | ~15 tests |
| `test_config_validation.py` | Configuration validation tests | ~25 tests |
| `test_error_handling.py` | Error scenarios and edge cases | ~20 tests |

## Running Tests

### Basic Test Execution

```bash
# Run all tests with verbose output
pytest -v

# Run all tests with minimal output
pytest -q

# Run tests with progress bar
pytest --tb=short
```

### Running Specific Test Categories

```bash
# OAuth2 authentication tests
pytest test_oauth_flows.py -v

# Token management tests
pytest test_token_management.py -v

# Request relaying tests
pytest test_relay_functionality.py -v

# API key authentication tests
pytest test_api_key_auth.py -v

# Variable substitution tests
pytest test_variable_substitution.py -v

# Integration tests
pytest test_integration.py -v

# Configuration validation tests
pytest test_config_validation.py -v

# Error handling tests
pytest test_error_handling.py -v
```

### Running Tests by Markers

```bash
# Run only unit tests
pytest -m unit -v

# Run only integration tests
pytest -m integration -v

# Run only OAuth2 related tests
pytest -m oauth -v

# Run only security related tests
pytest -m security -v

# Run all except slow tests
pytest -m "not slow" -v
```

### Running Specific Test Classes or Functions

```bash
# Run a specific test class
pytest test_oauth_flows.py::TestClientCredentialsFlow -v

# Run a specific test function
pytest test_oauth_flows.py::TestClientCredentialsFlow::test_client_credentials_success -v

# Run tests matching a pattern
pytest -k "oauth" -v
pytest -k "api_key" -v
pytest -k "error" -v
```

### Test Coverage

```bash
# Run tests with coverage report
pytest --cov=. --cov-report=term-missing

# Generate HTML coverage report
pytest --cov=. --cov-report=html
open htmlcov/index.html  # View in browser

# Generate XML coverage report (for CI/CD)
pytest --cov=. --cov-report=xml
```

### Parallel Test Execution

```bash
# Install pytest-xdist for parallel execution
pip install pytest-xdist

# Run tests in parallel
pytest -n auto  # Auto-detect CPU count
pytest -n 4     # Use 4 parallel workers
```

## Test Configuration

### Mock Servers

The test suite uses mock servers that simulate:
- **OAuth2 Server** (localhost:9081) - Handles token requests and refresh
- **API Server** (localhost:9998) - Receives relayed requests

These servers are automatically started and stopped during test execution.

### Test Data

Tests use temporary configuration files with various scenarios:
- Valid configurations for different OAuth2 grant types
- Invalid configurations to test error handling
- Edge case configurations for boundary testing

### Environment Variables

Some tests support environment variables for customization:

```bash
# Set custom test timeout (default: 30 seconds)
export TEST_TIMEOUT=60

# Enable debug logging in tests
export PYTEST_DEBUG=1

# Use custom ports for mock servers (if defaults conflict)
export MOCK_OAUTH_PORT=9081
export MOCK_API_PORT=9998
```

## Debugging Tests

### Verbose Output

```bash
# Maximum verbosity
pytest -vvv

# Show local variables in tracebacks
pytest --tb=long

# Show full diff for assertions
pytest --tb=short -vv
```

### Running Individual Tests

```bash
# Run a failing test in isolation
pytest test_oauth_flows.py::TestClientCredentialsFlow::test_client_credentials_success -vvv

# Stop on first failure
pytest -x

# Drop into debugger on failure
pytest --pdb
```

### Log Output

```bash
# Show print statements and log output
pytest -s

# Show live logs during test execution
pytest --log-cli-level=DEBUG

# Capture logs to file
pytest --log-file=tests.log
```

## Continuous Integration

### GitHub Actions Example

```yaml
name: Test OAuth2Relay
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - uses: actions/setup-go@v3
      with:
        go-version: '1.19'
    - uses: actions/setup-python@v3
      with:
        python-version: '3.9'
    - name: Build binary
      run: go build -o oauth2relay ./cmd/oauth2relay
    - name: Install dependencies
      run: |
        cd test_scripts
        pip install -r requirements.txt
    - name: Run tests
      run: |
        cd test_scripts
        pytest --cov=. --cov-report=xml
    - name: Upload coverage
      uses: codecov/codecov-action@v3
```

### Docker Testing

```dockerfile
FROM golang:1.27-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o oauth2relay ./cmd/oauth2relay

FROM python:3.9-alpine
RUN pip install pytest requests flask psutil pyjwt cryptography responses
WORKDIR /app
COPY --from=builder /app/oauth2relay .
COPY test_scripts/ test_scripts/
WORKDIR /app/test_scripts
CMD ["pytest", "-v"]
```

## Troubleshooting

### Common Issues

1. **Binary Not Found**
   ```bash
   # Error: oauth2relay binary not found
   # Solution: Build the binary first
   cd .. && make build && cd test_scripts
   ```

2. **Port Conflicts**
   ```bash
   # Error: Address already in use
   # Solution: Kill processes on test ports
   sudo lsof -ti:8080,9081,9998 | xargs kill -9
   ```

3. **Permission Denied**
   ```bash
   # Error: Permission denied when starting servers
   # Solution: Use unprivileged ports or run with appropriate permissions
   pytest -v  # Should work with default configuration
   ```

4. **Network Timeouts**
   ```bash
   # Error: Connection timeout in tests
   # Solution: Increase timeout or check firewall
   export TEST_TIMEOUT=60
   pytest -v
   ```

### Debug Mode

```bash
# Enable debug output in oauth2relay
export DEBUG=1
pytest test_integration.py -v -s

# Enable Python debugging
import pdb; pdb.set_trace()  # Add to test code
pytest --pdb
```

### Test Data Cleanup

```bash
# Clean up any leftover test files
find /tmp -name "tmp*.json" -delete 2>/dev/null || true

# Kill any leftover processes
pkill -f oauth2relay || true
```

## Contributing

When adding new tests:

1. **Follow naming conventions**: `test_*.py` for files, `test_*` for functions
2. **Use appropriate markers**: `@pytest.mark.unit`, `@pytest.mark.integration`, etc.
3. **Add docstrings**: Describe what each test validates
4. **Clean up resources**: Use fixtures and context managers
5. **Test both success and failure cases**
6. **Update this README** if adding new test categories

### Example Test Template

```python
import pytest
from utils import OAuth2RelayServer, create_test_config

@pytest.mark.unit
class TestNewFeature:
    """Test new feature functionality."""
    
    def test_feature_success(self, basic_config, mock_servers):
        """Test successful feature operation."""
        config_file = create_test_config(basic_config)
        
        try:
            with OAuth2RelayServer(config_file) as server:
                # Test implementation here
                assert True
        finally:
            import os
            os.unlink(config_file)
```

## Performance Benchmarking

```bash
# Run performance-sensitive tests only
pytest -m "not slow" --benchmark-only

# Profile test execution time
pytest --durations=10

# Memory usage profiling
pip install memory-profiler
pytest --profile
```

The test suite provides comprehensive coverage of OAuth2Relay functionality and should help ensure reliability and correctness of the application.