# OAUTH2Relay

OAUTH2Relay is a server that handles OAuth 2.0 authentication and token management, relaying authenticated requests to configured endpoints. It manages token refresh and authentication automatically.

Documentation and downloads: [oauth2relay.com](https://oauth2relay.com/) ([documentation](https://oauth2relay.com/docs.html), [operations guide](https://oauth2relay.com/operations.html)).

## Usage

```
oauth2relay [options] [config_file]

Options:
    --config FILE        Configuration file (default: config.json)
    --check-config       Check the configuration file and exit
    --log-level LEVEL    Override log_level: debug, info, warn or error
    --log-format FORMAT  Override log_format: text or json
    -h, --help           Show this help message
    -v, --version        Show version information

Arguments:
    config_file    Path to configuration file, instead of --config
```

Flags can be written with one or two dashes and can come before or after the config file.

`--check-config` reads and checks the whole configuration, prints `<file>: configuration is valid` and exits with status 0, or prints the problem and exits with status 1. It does not contact secrets managers or the identity provider, so it is safe to run in CI or before a deployment. When the configuration has no secret or `${env:...}` placeholders it also checks the JWT signing key; otherwise values that come from placeholders are checked when the relay starts, because the machine running the check may not have the relay's environment or secrets.

## Codebase Structure

The module is `oauth2relay.com/oauth2relay/v2`; the `/v2` suffix is required because releases are tagged v2.x. The command is a thin layer over packages that can also be imported as a library:

*   `cmd/oauth2relay`: The command: flags, `--check-config`, logging setup and signal handling.
*   `config`: The configuration file: its types, parsing (`config.Parse`), defaults, checks and warnings.
*   `token`: Obtains and renews the access token. A `token.Manager` per connection runs the grants (`client_credentials`, `password`, `jwt` and custom), refresh, login retries with backoff and background renewal. `token.Store` lets replicas share one token. `token.Exchanger` sends OAuth 2.0 Token Exchange (RFC 8693) requests for programs that exchange a caller's token per request; it does not cache.
*   `secrets`: Resolves `${alias:secret}` and `${env:NAME}` placeholders from AWS Secrets Manager, HashiCorp Vault, Azure Key Vault and the environment.
*   `relay`: The server. `relay.New` and `Server.Run` start the relay port and admin port, relay requests, serve health checks and metrics, reload the TLS certificate, re-fetch secrets and shut down gracefully. `relay.Options` adds behaviour without changing the core: middleware, admin routes, an audit sink, a token store and a router for several routes.
*   `egress`: Limits where outbound requests go: `egress.MatchHost` for host allow-lists, and a transport (`egress.NewTransport`) that refuses to connect to loopback, private, link-local and metadata addresses after DNS resolution, unless they are in its allowed networks.
*   `redact` and `logging`: Structured logging (`log/slog`) with secrets masked in every line.
*   `internal/util`: Small helpers such as `${VAR}` substitution.

The API of these packages is not yet stable: it may change in minor releases until it is declared stable.

## Configuration

The configuration file is in JSON format and contains the following main sections:

json
{
"port": 8080,
"host": "localhost",
"log_level": "info",
"log_format": "text",
"logfile": "",
"apiKey": "",
"token_wait_timeout": 30,
"token": { ... },
"secrets_managers": { ... },
"login": { ... },
"refresh": { ... },
"relay": { ... }
}

### Basic Configuration

Unknown fields are rejected, so a misspelt setting stops the relay at startup instead of being silently ignored. The whole configuration is checked when it is loaded: ports, URLs, HTTP methods, grant types and the fields each grant needs, `parameters` keys, and the token and server settings. Use `--check-config` to check a file without starting the relay.

- `port`: Port number for the relay server (required)
- `host`: Host address to bind to (required)
- `log_level`, `log_format`, `access_log`, `logfile`, `debug`: Logging (optional, see [Logging and Errors](#logging-and-errors))
- `apiKey`: An optional API key. If set, incoming requests must include a matching `X-API-Key` header or receive `401 Unauthorized`. The key is compared in constant time and is never forwarded to the relay target.
- `token_wait_timeout`: Seconds an incoming request waits for a valid token before failing with `503 Service Unavailable` (optional, default: 30). See [Login Retries and Request Timeouts](#login-retries-and-request-timeouts).
- `token`: When the access token is renewed (optional, see [Token Lifetime and Background Refresh](#token-lifetime-and-background-refresh))
- `secrets_managers`: Optional secret manager definitions (see [Secrets Management](#secrets-management))
- `secrets_refresh_interval`: Seconds between re-fetches of secret placeholders, so rotated credentials are picked up without a restart (optional, default: 0, off; minimum 60). See [Rotating Secrets](#rotating-secrets).
- `trusted_proxies`: Optional list of proxy or load balancer addresses (IPs or CIDR ranges, e.g. `["10.0.0.0/8"]`). When a request arrives from one of these, `${IP}` is taken from the `X-Forwarded-For` header: the rightmost address that is not itself a trusted proxy. Without this setting `${IP}` is the address of the direct connection, and `X-Forwarded-For` is ignored because callers could forge it.
- `max_request_body_bytes`: Largest incoming request body accepted (optional, default: 10485760, i.e. 10 MiB). Larger bodies are rejected with `413 Request Entity Too Large`.
- `server`: Limits for the inbound HTTP server (optional, see [Server Limits](#server-limits))
- `health`, `metrics`, `admin_port`: Health checks and Prometheus metrics (optional, see [Health Checks and Metrics](#health-checks-and-metrics))
- `tls`: Serve HTTPS on the relay port (optional, see [TLS](#tls))
- `ca_file`: PEM file of additional CA certificates to trust for outbound connections (optional, see [TLS](#tls))

### Logging and Errors

Logs are structured (Go `log/slog`) and written to stdout, which suits containers and systemd.

- `log_level`: `debug`, `info` (default), `warn` or `error`. `debug` adds the content of token and relay requests and responses; secrets are still masked.
- `log_format`: `text` (default; `key=value` pairs) or `json` (one JSON object per line, for log collectors).
- `access_log`: Log one line per relayed request (default: `true`). When `false`, only requests the relay rejected or failed are logged.
- `logfile`: Write logs to this file (created with mode `0600`) instead of stdout. The file is opened once in append mode, so rotate it with `logrotate`'s `copytruncate` option.
- `debug`: Older setting; `true` is the same as `"log_level": "debug"` when `log_level` is not set.

Each relayed request produces one `request` log line with `request_id`, `method`, `path`, `client_ip`, `status`, `duration_ms`, `bytes` and `upstream_host`. When the relay itself rejected or failed the request, the line also has `error` (the code below) and `detail` (the internal cause). Server errors (5xx) are logged at `WARN`, everything else at `INFO`. For example, in text format:

```
time=2026-10-20T11:20:55.012Z level=WARN msg=request request_id=393e60c1... method=GET path=/slow client_ip=192.0.2.1 status=504 duration_ms=1001.7 bytes=134 upstream_host=api.example.com error=upstream_timeout detail="... context deadline exceeded ..."
```

All log output passes through a redaction filter:

- Values resolved from secrets managers, and the configured `apiKey`, `fixedtoken`, `password`, `client_secret`, `authstring`, `jwt_key` and `jwt_private_key`, are replaced with `[REDACTED]` wherever they appear.
- Access and refresh tokens are shown as their first 4 characters and length, e.g. `eyJh…(len=1024)`, so log lines can still be matched up.
- Sensitive fields in form, JSON and header text (`access_token`, `refresh_token`, `client_secret`, `password`, `assertion`, `Bearer`/`Basic` credentials, `X-API-Key` and others) and PEM private keys are masked even if not otherwise known.

Startup errors are always logged with their cause, with secrets masked.

Every request gets a request ID: the caller's `X-Request-ID` header if it is 1–128 characters of letters, digits, `.`, `_`, `:` or `-`, otherwise a generated one. It is returned in the `X-Request-ID` response header, logged as `request_id`, and sent to the relay target in an `X-Request-ID` header so the two sides' logs can be matched. A `relay.headers` entry for `X-Request-ID` takes precedence, and listing it in `relay.strip_headers` stops it being sent.

Errors raised by the relay itself are returned as JSON. The details (such as an upstream address or the identity provider's error) are written to the log under the request ID, not sent to the caller:

```json
{"error": "upstream_error", "message": "The upstream request failed", "request_id": "4f1982d5462943cf..."}
```

| Status | `error` | Meaning |
|--------|---------|---------|
| 400 | `bad_request` | Malformed request, or an invalid target URL in `parameter` mode |
| 401 | `unauthorized` | Missing or invalid `X-API-Key` |
| 403 | `forbidden` | Target host not in `allowed_hosts` |
| 403 | `destination_blocked` | `parameter` mode: the target resolves to an internal address not in `allowed_networks` |
| 413 | `request_too_large` | Body larger than `max_request_body_bytes` |
| 500 | `token_error` | No access token could be obtained, and retrying will not help (for example the identity provider rejected the credentials) |
| 500 | `internal_error` | Relay misconfiguration |
| 502 | `upstream_error` | The relayed request failed |
| 502 | `redirect_blocked` | The upstream redirected somewhere not allowed |
| 503 | `token_unavailable` | No access token yet: the identity provider is unreachable or failing, or the token renewal took longer than `token_wait_timeout`. Retry later |
| 504 | `upstream_timeout` | The upstream did not respond within `relay.timeout` |

Responses from the relay target, including its errors, are passed through unchanged.

### Server Limits

The optional `server` section protects the relay from slow or stalled clients and controls shutdown. All values are in seconds except `max_header_bytes`.

```json
"server": {
    "read_header_timeout": 10,
    "read_timeout": 60,
    "write_timeout": 95,
    "idle_timeout": 120,
    "shutdown_timeout": 15,
    "max_header_bytes": 1048576
}
```

- `read_header_timeout`: Time allowed to receive the request headers (default: 10)
- `read_timeout`: Time allowed to receive the whole request, including the body (default: 60)
- `write_timeout`: Time allowed to handle the request and write the response (default: `token_wait_timeout` + `relay.timeout` + 5). It must be at least `token_wait_timeout` + `relay.timeout`, otherwise the server refuses to start.
- `idle_timeout`: How long an idle keep-alive connection stays open (default: 120)
- `shutdown_timeout`: On `SIGINT` or `SIGTERM` the server stops accepting connections and waits this long for in-flight requests to finish (default: 15)
- `shutdown_delay`: Seconds between receiving `SIGTERM` and closing the listener (default: 0). During the delay `/readyz` reports `draining` but requests are still served, so a load balancer or Kubernetes can stop sending traffic first. Keep `shutdown_delay` + `shutdown_timeout` below the platform's grace period (30 seconds by default in Kubernetes).
- `max_header_bytes`: Largest request header block accepted (default: 1048576)

### Health Checks and Metrics

The relay serves three operational endpoints. They do not need the API key.

| Path | Purpose |
|------|---------|
| `/healthz` | Liveness: `200 {"status":"ok"}` while the process is serving HTTP. |
| `/readyz` | Readiness: `200` once the first access token has been obtained (or `relay.fixedtoken` is set); `503` while starting up or shutting down. |
| `/metrics` | Prometheus metrics. |

`/readyz` also reports the token's state (`fixed`, `none`, `valid`, `expired` or `renewal_failed`) and seconds until it expires, never the token itself:

```json
{"status": "ready", "token": {"state": "valid", "expires_in_seconds": 3542}}
```

Readiness does not fail when a token renewal fails. Tokens are renewed when a request needs one, so a replica taken out of the load balancer could never recover, and an identity provider outage affects every replica alike. Alert on the metrics below instead.

```json
"admin_port": 9090,
"health": {"enabled": true, "liveness_path": "/healthz", "readiness_path": "/readyz"},
"metrics": {"enabled": true, "path": "/metrics"}
```

- `admin_port`: Serve these endpoints on a separate port (same `host`) instead of the relay port (optional). **Recommended in production**: metrics are not then reachable by relay callers, and every path on the relay port is relayed. The admin port starts listening before the first token is obtained, so liveness passes during a slow start-up while readiness reports `starting`.
- `health.enabled`, `metrics.enabled`: Turn the endpoints off (default: `true`).
- `health.liveness_path`, `health.readiness_path`, `metrics.path`: Change the paths, e.g. if the relay target has its own `/healthz` that callers must reach through the relay.

Without `admin_port`, these exact paths are answered by the relay and are not relayed. Other paths, including `/healthz/x`, are relayed as usual.

Metrics, all prefixed `oauth2relay_`:

| Metric | Type | Labels | Meaning |
|--------|------|--------|---------|
| `requests_total` | counter | `code`, `upstream_host` | Relayed requests by response status. `upstream_host` is empty for requests rejected before an upstream was chosen (e.g. `401`); in `parameter` mode it is the matching `allowed_hosts` entry. `499` means the caller disconnected. |
| `request_duration_seconds` | histogram | `upstream_host` | Time to handle a request, including waiting for a token. |
| `inbound_auth_failures_total` | counter | | Requests with a missing or wrong API key. |
| `token_renewals_total` | counter | `type` (`login`, `refresh`), `result` (`success`, `failure`) | Token endpoint requests. Every login retry counts. |
| `idp_request_duration_seconds` | histogram | `type` | Time taken by token endpoint requests. |
| `token_expires_in_seconds` | gauge | | Seconds until the current token expires (negative once expired). Not exported with `relay.fixedtoken`. |
| `tls_certificate_expiry_timestamp_seconds` | gauge | | Unix time the relay port's TLS certificate expires. Only exported with `tls`. |
| `secret_refreshes_total` | counter | `result` (`success`, `failure`) | Periodic secret re-fetches (`secrets_refresh_interval`). |
| `secrets_last_refresh_timestamp_seconds` | gauge | | Unix time secrets were last resolved, at startup or by a re-fetch. Only exported with `secrets_managers`. |
| `build_info` | gauge | `version`, `go_version` | Always 1. |

Go runtime (`go_*`) and process (`process_*`) metrics are included. Suggested alerts: `increase(oauth2relay_token_renewals_total{result="failure"}[10m]) > 0`, `oauth2relay_token_expires_in_seconds < 0`, a rising rate of `oauth2relay_requests_total{code=~"5.."}`, and, with `secrets_refresh_interval`, `time() - oauth2relay_secrets_last_refresh_timestamp_seconds` above a few intervals.

### Login Configuration

The `login` section configures how to obtain the initial access token. It supports multiple OAuth 2.0 grant types.

{
    "login": {
        "url": "https://auth-server/token",
        "grant_type": "client_credentials",
        "method": "POST",
        "headers": {},
        "parameters": {
        "AccessToken": "access_token",
        "RefreshToken": "refresh_token",
        "ExpiresIn": "expires_in"
        }
    }
}


#### Common Fields
- `url`: Authentication endpoint URL (required)
- `method`: HTTP method for the custom grant (empty means `GET`; `data` is sent only with `POST`). The `client_credentials`, `password` and `jwt` grants always use `POST`.
- `headers`: Additional headers to include in the request. For the `client_credentials`, `password` and `jwt` grants the relay sets `Content-Type` itself, and `Authorization` when `client_auth` is `basic`; those values replace any set here.
- `parameters`: Maps OAUTH2Relay's token properties (keys) to field names in the provider's JSON response (values). For the `client_credentials`, `password` and `jwt` grants it defaults to the standard OAuth 2.0 names shown above; the custom grant must set it. Other keys are rejected.
  - `AccessToken`: Field containing the access token (required)
  - `RefreshToken`: Field containing the refresh token
  - `ExpiresIn`: Field containing the token lifetime in seconds
  - `ExpiresAt`: Used if `ExpiresIn` is absent; field containing the absolute expiry (Unix timestamp or RFC 3339)

  How the expiry is used is described in [Token Lifetime and Background Refresh](#token-lifetime-and-background-refresh).
- `retry_attempts`: Total login attempts before giving up (default: 5; set to 1 to disable retries)
- `retry_interval`: Seconds to wait before the first retry (default: 5). Each later wait doubles, up to `retry_max_interval`.
- `retry_max_interval`: Longest wait between retries in seconds (default: 60, or `retry_interval` if that is larger).
- `timeout`: Seconds before a single login request times out (default: 10)

#### Login Retries and Request Timeouts

To renew the access token OAUTH2Relay first tries a refresh and, if that fails, a login. A failed login is retried up to `retry_attempts` times with exponential backoff: the first wait is `retry_interval` seconds and each later one doubles, up to `retry_max_interval`. Each wait is shortened at random by up to half, so that several replicas do not retry in step. With the defaults the waits are about 5, 10, 20 and 40 seconds. Each failure is written to the log with the time of the next attempt:

```
level=WARN msg="Login failed; retrying" attempt=1 attempts=5 error="token endpoint returned 503 Service Unavailable" next_attempt=2026-10-20T16:55:57Z
```

Retries apply both at startup (the process exits if every attempt fails) and while serving requests. Errors that a retry cannot fix are not retried: a `4xx` response from the token endpoint (except `408` and `429`), an OAuth error of `invalid_request`, `invalid_client`, `invalid_grant`, `unauthorized_client`, `unsupported_grant_type` or `invalid_scope`, or a configuration error such as a missing `client_id`. The log shows the HTTP status and the provider's `error` and `error_description`. Only one renewal runs at a time. Incoming requests wait for it for at most `token_wait_timeout` seconds and then receive `503 Service Unavailable`, which is also logged. The renewal keeps running in the background, so clients can retry later and pick up the new token once the provider is back. Requests that were waiting on a renewal cycle that failed get that error back instead of each starting a new cycle.

#### Grant Types

##### Client Credentials Grant
{
    "login": {
        "grant_type": "client_credentials",
        "client_id": "your_client_id",
        "client_secret": "your_client_secret"
    }
}

##### Scope, Audience and Client Authentication

The `client_credentials`, `password` and `jwt` grants accept these optional fields. Each is sent in the request body only when set.

- `scope`: Space-separated scopes (`scope`, RFC 6749)
- `audience`: The API the token is for (`audience`, used by Auth0 and others)
- `resource`: The API the token is for (`resource`, RFC 8707 resource indicators)
- `client_auth`: How `client_id` and `client_secret` reach the provider: `post` (default) sends them in the body, `basic` sends them in an `Authorization: Basic` header (`client_secret_basic`). Not used by the `jwt` grant.

Microsoft Entra ID requires a scope ending in `/.default`:

```json
{
    "login": {
        "url": "https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token",
        "grant_type": "client_credentials",
        "client_id": "<application-id>",
        "client_secret": "${env:ENTRA_CLIENT_SECRET}",
        "scope": "api://<api-application-id>/.default"
    }
}
```

Auth0 requires the API identifier as `audience`:

```json
{
    "login": {
        "url": "https://<tenant>.auth0.com/oauth/token",
        "grant_type": "client_credentials",
        "client_id": "<client-id>",
        "client_secret": "${env:AUTH0_CLIENT_SECRET}",
        "audience": "https://api.example.com"
    }
}
```

Okta custom authorization servers require at least one scope, and accept `client_secret_basic`:

```json
{
    "login": {
        "url": "https://<org>.okta.com/oauth2/<server-id>/v1/token",
        "grant_type": "client_credentials",
        "client_id": "<client-id>",
        "client_secret": "${env:OKTA_CLIENT_SECRET}",
        "client_auth": "basic",
        "scope": "reports.read"
    }
}
```

The custom grant rejects these fields; put them in `data` instead.

##### Password Grant

Not recommended: the relay holds a user's password and sends it to the identity provider. OAuth 2.0 Security Best Current Practice (RFC 9700) says this grant must not be used, and many providers have removed it. Use `client_credentials` or `jwt` where the provider supports them. The relay logs a warning at startup when this grant is configured.
{
    "login": {
        "grant_type": "password",
        "user": "username",
        "password": "userpassword",
        "client_id": "your_client_id",
        "client_secret": "your_client_secret"
    }
}

##### JWT Bearer Grant

Signs a JWT assertion and exchanges it for an access token (RFC 7523). The request is sent with `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` and the assertion in `assertion`.

With a shared secret (HMAC):

```json
{
    "login": {
        "grant_type": "jwt",
        "jwt_key": "your_secret_key",
        "jwt_issuer": "your_app",
        "jwt_audience": "auth_server"
    }
}
```

With a private key, as used by Google service accounts and Salesforce:

```json
{
    "login": {
        "grant_type": "jwt",
        "jwt_algorithm": "RS256",
        "jwt_private_key": "${vault_prod:svc/jwt:private_key}",
        "jwt_key_id": "key-2026-10",
        "jwt_issuer": "svc@project.iam.gserviceaccount.com",
        "jwt_subject": "user@example.com",
        "jwt_audience": "https://oauth2.googleapis.com/token",
        "jwt_scope": "https://www.googleapis.com/auth/drive.readonly"
    }
}
```

- `jwt_algorithm`: `HS256` (default), `HS384`, `HS512`, `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `ES256`, `ES384` or `ES512`
- `jwt_key`: Shared secret for the `HS*` algorithms
- `jwt_private_key`: PEM private key (PKCS #1, PKCS #8 or SEC 1) for the `RS*`, `PS*` and `ES*` algorithms. A key stored on one line with literal `\n` sequences is accepted.
- `jwt_private_key_file`: Path to a PEM private key file, used when `jwt_private_key` is empty
- `jwt_issuer`: `iss` claim (required)
- `jwt_subject`: `sub` claim (optional)
- `jwt_audience`: `aud` claim (optional)
- `jwt_scope`: `scope` claim inside the assertion (optional). Providers that read the scope from the request body instead need `scope`, described in [Scope, Audience and Client Authentication](#scope-audience-and-client-authentication); both can be set.
- `jwt_key_id`: `kid` header (optional)
- `jwt_lifetime`: Seconds until the assertion expires (default: 300)
- `jwt_claims`: Additional claims, e.g. `{"tenant": "acme"}`. These override the claims above if the names clash.
- `jwt_grant_type`: Override the `grant_type` value for token endpoints that do not use the standard one

Each assertion also carries `iat`, `nbf`, `exp` and a random `jti`. The key and claims are checked at startup, so an invalid key stops the server before it begins serving.

##### Custom Grant (Legacy)
{
    "login": {
        "user": "username",
        "password": "password",
        "authstring": "base64_encoded_credentials",
        "data": "custom_request_body",
        "headers": {
            "Authorization": "Basic ${AUTHSTRING}"
        }
    }
}

### Refresh Configuration

The `refresh` section configures how to refresh expired tokens.

```json
{
    "refresh": {
        "url": "https://auth-server/token/refresh",
        "method": "POST",
        "token": "initial_refresh_token",
        "data": "refresh_token=${REFRESHTOKEN}",
        "headers": {
            "Content-Type": "application/x-www-form-urlencoded"
        },
        "parameters": {
            "AccessToken": "access_token",
            "RefreshToken": "refresh_token",
            "ExpiresIn": "expires_in"
        }
    }
}
```

- `url`: Refresh token endpoint URL
- `method`: HTTP method for refresh requests. Set it to `POST`: empty means `GET`, and `data` is sent only with `POST`.
- `token`: Initial refresh token (optional)
- `data`: Request body template
- `headers`: Additional headers for refresh requests
- `parameters`: Response field mapping (same as login parameters; defaults to the standard OAuth 2.0 names)
- `timeout`: Seconds before a refresh request times out (default: 10)

### Token Lifetime and Background Refresh

```json
{
    "token": {
        "expiry_buffer": 10,
        "default_lifetime": 300,
        "background_refresh": true,
        "refresh_at": 0.8
    }
}
```

- `expiry_buffer`: Seconds subtracted from the lifetime the identity provider gives, so a token is not used right up to its expiry (default: 10). For a short-lived token at most half its lifetime is subtracted.
- `default_lifetime`: Lifetime in seconds assumed when the token response has no expiry field (default: 300).
- `background_refresh`: Renew the token before it expires, so requests do not wait for a renewal (default: `true`).
- `refresh_at`: Fraction of the token's lifetime after which the background refresh renews it (default: 0.8; must be between 0 and 1). A token that is valid for an hour is renewed after 48 minutes.

With background refresh a failed renewal does not affect requests: the current token is used until it expires, the renewal is retried with the same backoff as login retries, and the failure is logged and counted in `oauth2relay_token_renewals_total`. Readiness shows `renewal_failed` in the token state. If the token does expire, requests renew it themselves as they would without background refresh.

Without background refresh the token is only renewed when a request finds it expired, and that request waits for the renewal. Background refresh means one renewal per token lifetime even when the relay is idle; turn it off if that matters for your identity provider.

### Relay Configuration

The `relay` section configures how authenticated requests are forwarded.

```json
{
    "relay": {
        "mode": "passthrough",
        "url": "https://api-server/endpoint",
        "method": "GET",
        "fixedtoken": "",
        "type": "json",
        "pushheaders": true,
        "headers": {
            "Authorization": "Bearer ${ACCESSTOKEN}",
            "Content-Type": "application/json"
        },
        "parameters": {
            "ipaddr": "${IP}",
            "country_code": "US"
        }
    }
}
```

- `mode`: How the target URL is chosen: `single`, `passthrough` (default) or `parameter`. Case-insensitive. See [Relay Modes](#relay-modes).
- `url`: Target API endpoint URL. Required in `single` and `passthrough` modes, and not used in `parameter` mode.
- `url_param`: `parameter` mode only. The name of the incoming parameter that holds the target URL (default: `external_url`).
- `allowed_hosts`: `parameter` mode only, and required there. The hosts the target URL may point to.
- `allowed_networks`: `parameter` mode only. Internal addresses (IP addresses or CIDR ranges, e.g. `["10.20.0.0/16"]`) that target URLs may connect to. All other non-public addresses are blocked; see [Relay Modes](#relay-modes).
- `method`: HTTP method for relay requests (default: `GET`). Set it to `inherit` to relay each request with the caller's own method, which suits `passthrough` mode.
- `timeout`: Seconds before a relayed request times out (default: 60). On timeout the caller receives `504 Gateway Timeout`. If the caller disconnects, the relayed request is cancelled.
- `fixedtoken`: Use a fixed token instead of obtaining one (optional).
- `type`: Informational payload type (e.g., "json"). Not currently used; the body format is determined by the incoming `Content-Type`.
- `pushheaders`: Forward incoming request headers (default: false). Headers set in `headers` take precedence. The following are never forwarded: `X-API-Key`, and hop-by-hop headers (`Connection` and any headers it names, `Keep-Alive`, `Proxy-Authorization`, `Proxy-Authenticate`, `Proxy-Connection`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`). The caller's `Authorization` and `Cookie` headers are also not forwarded unless listed in `forward_headers`.
- `forward_headers`: Optional allow-list for `pushheaders`. When set, only these incoming headers are forwarded (case-insensitive). Listing `Authorization` or `Cookie` here forwards them; `X-API-Key` cannot be listed.
- `follow_redirects`: Follow upstream redirects (default: false). By default a `3xx` response from the target is returned to the caller unchanged. When enabled, up to 5 redirects are followed, and every hop must stay on the original host (`single` and `passthrough` modes) or on a host in `allowed_hosts` (`parameter` mode) and may not switch from `https` to `http`. A redirect that fails these checks returns `502 Bad Gateway`.
- `strip_headers`: Optional list of additional incoming headers that `pushheaders` never forwards.
- `headers`: Additional headers for relay requests.
- `parameters`: Mapping for additional parameters that are merged into the outbound request. **Keys** represent the outgoing parameter names, while **values** may contain substitution variables. For example, `"ipaddr": "${IP}"` causes the requestor's IP address to be inserted, and `"country_code": "US"` sets a static value.

### Relay Modes

`relay.mode` decides where each incoming request is sent. Mode names are case-insensitive. If `mode` is not one of the three names below, or a setting the mode needs is missing, the server refuses to start and reports the problem.

| Mode | Incoming request | Relayed to |
|------|------------------|------------|
| `single` | `http://localhost:8000/my_profile` | `https://example.com/api/get_statuses` |
| `passthrough` (default) | `http://localhost:8000/my_profile` | `https://example.com/api/my_profile` |
| `parameter` | `http://localhost:8000/?external_url=https://example.com/my_profile` | `https://example.com/my_profile` |

In every mode, query parameters, body parameters and the configured `parameters` are merged into the outbound request in the same way:

- `POST`, `PUT` and `PATCH` requests with a `application/x-www-form-urlencoded` or `application/json` body: the incoming query parameters and the configured `parameters` are merged into the body.
- All other requests: the incoming query parameters and the configured `parameters` are added to the target URL's query string. `GET` and `HEAD` requests carry no body. For other methods the body is `relay.data` if set, otherwise the caller's body is streamed through unchanged with its `Content-Type`.

**single**: every request is sent to `url`, and the incoming path is ignored.

```json
"relay": {
    "mode": "single",
    "url": "https://example.com/api/get_statuses",
    "method": "GET"
}
```

**passthrough**: the incoming path is appended to `url`. Without a `mode` setting, OAUTH2Relay runs in this mode.

```json
"relay": {
    "mode": "passthrough",
    "url": "https://example.com/api",
    "method": "GET"
}
```

**parameter**: the caller supplies the target URL in the parameter named by `url_param` (default `external_url`). The parameter can be in the query string, a form-encoded body or a JSON body. It is removed from all of these before the request is relayed, so the 3rd party never sees it. The incoming path is ignored and never appended to the target URL. If the 3rd-party API has its own parameter called `external_url`, set `url_param` to a different name.

```json
"relay": {
    "mode": "parameter",
    "url_param": "external_url",
    "allowed_hosts": ["example.com", "*.example.com"],
    "method": "GET"
}
```

- If the parameter is missing, or is not an absolute `http`/`https` URL, the request fails with `400 Bad Request`.
- If the URL's host is not in `allowed_hosts`, the request fails with `403 Forbidden`.
- An `allowed_hosts` entry matches the hostname case-insensitively. `*.example.com` matches any subdomain of `example.com` but not `example.com` itself. An entry that includes a port (`api.example.com:8443`) matches that port only.
- `${...}` placeholders are never expanded in a caller-supplied URL.
- The relay will not connect to an internal address: loopback (`127.0.0.0/8`, `::1`), private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`), link-local (`169.254.0.0/16`, which includes the cloud metadata service at `169.254.169.254`, and `fe80::/10`), carrier-grade NAT (`100.64.0.0/10`), multicast and other reserved ranges. Such a request fails with `403 Forbidden` and the error `destination_blocked`. This protects against a host in `allowed_hosts` whose DNS name points, by mistake or on purpose, at an internal service. The check is made on the address actually connected to, after DNS resolution, so a name cannot pass the check and then resolve to a different address (DNS rebinding), and it applies to every redirect hop. To relay to internal services, list their addresses in `allowed_networks`. When an HTTP proxy is configured (`HTTPS_PROXY` and similar), the proxy makes the connection, so the relay checks the addresses the target name resolves to before sending the request to the proxy; the proxy's own address is not checked.

### TLS

The relay port serves plain HTTP unless `tls` is set:

```json
{
    "tls": {
        "cert_file": "/etc/oauth2relay/tls.crt",
        "key_file": "/etc/oauth2relay/tls.key",
        "min_version": "1.2"
    },
    "ca_file": "/etc/oauth2relay/corporate-ca.pem"
}
```

- `cert_file`, `key_file`: PEM certificate chain and private key. Set both to serve HTTPS on the relay port. Plain HTTP requests to that port are then answered with `400 Bad Request`.
- `min_version`: Oldest TLS version accepted, `1.2` (default) or `1.3`.

The certificate is reloaded within 10 seconds of either file changing, so certificates renewed by cert-manager, certbot or a similar tool are picked up without a restart. If the new files cannot be loaded, for example while they are being written, the current certificate stays in use and a warning is logged. `oauth2relay_tls_certificate_expiry_timestamp_seconds` reports when the certificate expires.

The admin port (`admin_port`) always serves plain HTTP. Bind it to a private network, or leave `admin_port` unset so health checks and metrics share the relay port's TLS.

Without `tls`, run the relay behind a TLS-terminating proxy or load balancer, and make sure the relay port cannot be reached any other way: callers send their API key and the relay returns upstream responses over this connection. The relay logs a warning at startup when it serves plain HTTP on an address other than loopback.

`ca_file` adds CA certificates to the system ones for outbound connections to the token endpoint and the relay targets, for example when they use certificates from a corporate CA. It does not apply to the secrets managers, which use their own settings (for Vault, `VAULT_CACERT`). Setting the `SSL_CERT_FILE` environment variable instead replaces the system CA certificates for every outbound connection, secrets managers included.

### Variable Substitution

The following variables are available for substitution in URLs, headers, request bodies, and additional parameters:

- `${ACCESSTOKEN}`: Current access token.
- `${REFRESHTOKEN}`: Current refresh token.
- `${USER}`: Username from login configuration.
- `${PASSWORD}`: Password from login configuration.
- `${AUTHSTRING}`: Base64 encoded credentials.
- `${DATA}`: Data field from configuration.
- `${FIXEDTOKEN}`: The configured fixed token.
- `${IP}`: IP address of the incoming request.

### Secrets Management

OAUTH2Relay can securely fetch sensitive values (like passwords, client secrets, or API keys) from external secret managers. This avoids storing them directly in the configuration file.

**Configuration**

To use this feature, you must define one or more secret managers in the `secrets_managers` section of your `config.json`. Each manager is given a unique alias (e.g., "my_vault", "aws_prod").

```json
"secrets_managers": {
  "aws_prod": {
    "type": "aws_secrets_manager",
    "region": "us-east-1",
    "profile": "default"
  },
  "my_vault": {
    "type": "hashicorp_vault",
    "address": "https://vault.example.com",
    "auth": {
      "type": "approle",
      "role_id": "your-role-id",
      "secret_id_env": "VAULT_SECRET_ID"
    }
  },
  "azure_prod": {
    "type": "azure_key_vault",
    "vault_url": "https://mykeyvault.vault.azure.net/"
  }
}
```

**Supported Secret Managers**

*   **AWS Secrets Manager** (`aws_secrets_manager`):
    *   `region`: The AWS region.
    *   `profile`: The AWS credentials profile to use.
*   **HashiCorp Vault** (`hashicorp_vault`):
    *   `address`: The address of the Vault server (default: the `VAULT_ADDR` environment variable).
    *   `namespace`: Vault Enterprise namespace (optional).
    *   `mount`: Mount path of the KV secrets engine (default: `secret`).
    *   `kv_version`: KV engine version, `1` or `2` (default: `2`).
    *   `auth`: Authentication configuration (optional; without it the `VAULT_TOKEN` environment variable is used).
        *   `type`: `approle`, `token` or `kubernetes`.
        *   `mount`: Mount path of the auth method (default: the `type` name).
        *   `approle`: `role_id` and `secret_id_env` (the name of the environment variable containing the AppRole SecretID).
        *   `token`: `token_env`, the environment variable containing the token (default: `VAULT_TOKEN`).
        *   `kubernetes`: `role`, and `token_path` for the service account token (default: `/var/run/secrets/kubernetes.io/serviceaccount/token`).
*   **Azure Key Vault** (`azure_key_vault`):
    *   `vault_url`: The URL of the Azure Key Vault.
    *   `tenant_id`, `client_id`, `client_secret_env`: When all three are set, the relay signs in as that service principal, reading the client secret from the named environment variable.
    *   `client_id` alone: the relay uses that user-assigned managed identity.
    *   None of these: the relay uses `DefaultAzureCredential` (environment variables, workload identity, managed identity or the Azure CLI login).

Secrets manager settings are checked when the configuration is loaded, so a missing `vault_url`, an incomplete service principal or an unknown Vault auth type stops the server with a clear error.

**Using Secrets in Configuration**

Once a secret manager is configured, you can reference secrets in other parts of the `config.json` using the following placeholder format:

`${alias:secret_name}` or `${alias:secret_name:json_key}`

*   `alias`: The alias you defined for the secret manager.
*   `secret_name`: The name (or path) of the secret in the secret manager.
*   `json_key` (optional): If the secret is a JSON object, this is the key of the value to extract.

**Example**

If you have a secret named `myapp/credentials` in AWS Secrets Manager (aliased as `aws_prod`) with the value `{"client_secret": "supersecret"}`, you can reference it in your login configuration like this:

```json
"login": {
  "client_id": "my-client-id",
  "client_secret": "${aws_prod:myapp/credentials:client_secret}"
}
```

At startup, OAUTH2Relay will connect to the `aws_prod` secret manager, fetch the `myapp/credentials` secret, parse the JSON, and inject the value of the `client_secret` key into the `login.client_secret` field.

Placeholders can appear anywhere in a string value, including inside header and parameter maps, lists such as `allowed_hosts`, and `jwt_claims`. A string can contain several of them, for example `"Authorization": "Basic ${vault_prod:svc:user}:${vault_prod:svc:pass}"`. Each secret is fetched once however many placeholders use it. If the JSON value for a key is a number, boolean or object, its JSON text is used. A placeholder whose alias is not a configured secrets manager (or `env`) is left unchanged.

#### Environment Variables

`${env:NAME}` is replaced with the value of the environment variable `NAME` when the relay starts. It needs no `secrets_managers` entry, and works anywhere a secret placeholder does:

```json
"login": {
  "grant_type": "client_credentials",
  "client_id": "my-client-id",
  "client_secret": "${env:API_CLIENT_SECRET}"
}
```

```bash
export API_CLIENT_SECRET='s3cr3t'
oauth2relay --config config.json
```

- `${env:NAME:json_key}` reads one key from a variable that holds a JSON object, as for secrets managers.
- If the variable is not set, the relay refuses to start and names it. A variable set to an empty string resolves to an empty string.
- Resolved values are masked in the logs like other secrets.
- Placeholders work in string values only, not in numbers such as `port`.
- `env` is reserved: a secrets manager cannot use it as its alias.

Environment variables are a good fit for containers and systemd, where the platform injects them from its own secret store (a Kubernetes Secret, `EnvironmentFile=`, `docker run --env-file`). They are read once at startup, so changing one needs a restart; use a secrets manager with `secrets_refresh_interval` for credentials that rotate without restarts.

#### Rotating Secrets

Secrets are fetched at startup. To pick up rotated credentials without a restart, set `secrets_refresh_interval` (seconds, at least 60). Every interval the relay rebuilds its configuration from the file contents it read at startup, resolves the placeholders again, and switches to the new values for later requests and token renewals. Requests in progress finish with the values they started with. If a re-fetch fails, for example because the secrets manager is unreachable, the relay keeps the current values, logs a warning and tries again at the next interval.

Only secret values change: the configuration file is not re-read, so other changes still need a restart. Each re-fetch logs in to the secrets manager again (for Vault with `approle` or `kubernetes` auth this creates a new Vault token), so choose an interval in minutes rather than seconds. The `oauth2relay_secret_refreshes_total` counter and the `oauth2relay_secrets_last_refresh_timestamp_seconds` gauge show whether re-fetching works.

The current access token is kept when credentials change; the new credentials are used at the next login. To rotate a client secret, add the new secret at the identity provider, update it in the secrets manager, wait for one `secrets_refresh_interval` plus one token lifetime, then revoke the old secret.

## Example Configuration

[`examples/config.example.json`](examples/config.example.json) is a starting point for a new deployment: copy it to `config.json` and replace the `example.com` URLs. It reads the API key and client credentials from environment variables, so the file itself holds no secrets. `config.json` is listed in `.gitignore`, so a local configuration is not committed by mistake.

Here's a complete example configuration using client credentials and a refresh endpoint:

```json
{
    "port": 8080,
    "host": "localhost",
    "log_level": "info",
    "token_wait_timeout": 30,
    "login": {
        "url": "https://auth-server/token",
        "grant_type": "client_credentials",
        "client_id": "${env:API_CLIENT_ID}",
        "client_secret": "${env:API_CLIENT_SECRET}",
        "retry_attempts": 5,
        "retry_interval": 5,
        "retry_max_interval": 60,
        "parameters": {
            "AccessToken": "access_token",
            "RefreshToken": "refresh_token",
            "ExpiresIn": "expires_in"
        }
    },
    "refresh": {
        "url": "https://auth-server/token/refresh",
        "method": "POST",
        "data": "refresh_token=${REFRESHTOKEN}",
        "parameters": {
            "AccessToken": "access_token",
            "RefreshToken": "refresh_token",
            "ExpiresIn": "expires_in"
        }
    },
    "relay": {
        "url": "https://api-server/endpoint",
        "method": "GET",
        "pushheaders": true,
        "headers": {
            "Authorization": "Bearer ${ACCESSTOKEN}",
            "Content-Type": "application/json"
        },
        "parameters": {
            "ipaddr": "${IP}",
            "country_code": "US"
        }
    }
}
```

## Upgrading

See [UPGRADING.md](UPGRADING.md) for the changes to check before upgrading, including the breaking changes in 2.0. The [operations runbook](docs/OPERATIONS.md) covers deployment, monitoring, troubleshooting and credential rotation.

## Security Considerations

1. Store sensitive configuration in secure locations
2. Keep secrets out of the configuration file: use `${env:NAME}` placeholders or a secrets manager
3. Disable debug logging in production
4. Use HTTPS for all endpoints: set `tls` (see [TLS](#tls)) or put the relay behind a TLS-terminating proxy
5. Regularly rotate credentials and tokens
6. Monitor and log authentication failures
7. In `parameter` relay mode, the access token is sent to whichever URL the caller supplies. Keep `allowed_hosts` as narrow as possible, keep `allowed_networks` empty unless you need to reach internal services, and enable `apiKey` so that only trusted callers can use the relay
8. Prefer the `client_credentials` or `jwt` grant to `password`
9. Report vulnerabilities as described in [SECURITY.md](SECURITY.md)

## Installation

Download the archive for your platform and `SHA256SUMS` from the release, and verify the archive before installing it:

```bash
sha256sum -c SHA256SUMS --ignore-missing
tar xzf oauth2relay_2.0.0_linux_amd64.tar.gz
```

Each release also publishes a container image for `linux/amd64` and `linux/arm64`, built from the [`Dockerfile`](Dockerfile): distroless, non-root, with the configuration read from `/etc/oauth2relay/config.json`. A hardened systemd unit is in [`deploy/systemd`](deploy/systemd/oauth2relay.service). See the [operations runbook](docs/OPERATIONS.md#deployment) for both.

## Building and Running

```bash
# Build the application (stamps the version from the latest git tag)
make build

# Release archives for every platform, with SHA256SUMS, in dist/
make release

# Container image
make docker

# Create a configuration from the example, then edit it
cp examples/config.example.json config.json

# Run with default config (config.json in the current directory)
./oauth2relay

# Run with specific config file
./oauth2relay /path/to/config.json

# Check a config file without starting the relay
./oauth2relay --check-config --config /path/to/config.json

# Show version
./oauth2relay --version

# Show help
./oauth2relay --help
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions need a Contributor License Agreement, which is being finalised; until then, issues and suggestions are welcome but outside pull requests cannot be merged.

## License

OAUTH2Relay is open source under the [Apache License 2.0](LICENSE). Copyright 2024-2026 Fijomi Systems SL.

You may use, modify and distribute it, including commercially, under the terms of the license. See [`NOTICE`](NOTICE) for attribution and third-party components. The license does not grant rights to the "OAUTH2Relay" name or logos.

A commercial edition with additional features for organisations (multiple connections per deployment, high availability, admin UI with SSO, audit export, FIPS builds) and commercial support is available from Fijomi Systems SL.

## History

**2026-11-03** (v2.4.3)
- Updated dependencies: the Azure SDK (`azcore` 1.23.3, `azidentity` 1.15.0, `azsecrets` 1.5.1), the AWS SDK (`config` 1.33.13, `secretsmanager` 1.50.8) and the HashiCorp Vault client (`api` 1.23.0, `approle` 0.12.0), used by the secrets managers. No configuration changes.

**2026-11-03** (v2.4.2)
- Security: updated `github.com/go-jose/go-jose/v4` to 4.1.6 (CVE-2026-116587, denial of service through crafted RSA parameters in JWKs) and `golang.org/x/net` to 0.62.0 (GO-2026-6860, GO-2026-6866). `govulncheck` shows the relay does not call the affected code, but image scanners report the old versions. No configuration changes.

**2026-10-30** (v2.4.1)
- First public release of the source code, at https://github.com/ronancashell-design/oauth2relay. `go get oauth2relay.com/oauth2relay/v2` now works without `GOPRIVATE` or repository credentials.
- New [`examples/config.example.json`](examples/config.example.json), also in the release archives: a starting configuration that reads the API key and client credentials from environment variables.
- Security vulnerabilities are now reported to security@fijomi.com (see [SECURITY.md](SECURITY.md)).
- No changes to the relay or the packages.

**2026-10-23** (v2.4.0)
- New for library users: `secrets.ResolveIn` resolves secret placeholders (`${alias:name}`, `${env:NAME}`) in any configuration struct, and `config.CheckSecretsManagers` checks `secrets_managers` definitions, so programs that embed the relay can use the same secret managers for their own settings. The relay itself is unchanged.

**2026-10-23** (v2.3.0)
- See [Upgrading to 2.3](UPGRADING.md#upgrading-to-23) if you build from source or import the packages. Configuration files and the release binaries are unchanged.
- The code is now a Go module, `oauth2relay.com/oauth2relay/v2`, with the command in `cmd/oauth2relay` and the relay in importable packages (`config`, `token`, `secrets`, `relay`, `egress`, `redact`, `logging`). See [Codebase Structure](#codebase-structure). Build from source with `make build` or `go build ./cmd/oauth2relay`; `go build .` in the repository root no longer works.
- No package-level state: the token, health state, metrics registry and HTTP transports belong to a `relay.Server`, so one process can run several relays.
- Extension points for programs that embed the relay: middleware, admin routes, an audit sink, a shared token store and a router (`relay.Options`).
- SIGINT or SIGTERM while the relay is still obtaining its first token now stops it cleanly with exit status 0.
- New for library users: `LoginConfig.Check` and `TokenConfig.Check` to check token settings built without a whole configuration, `token.Exchanger` for OAuth 2.0 Token Exchange (RFC 8693), and the `egress` package with the SSRF guard and host matching that parameter mode uses.

**2026-10-21** (v2.2.1)
- Security: built with Go 1.27.3, which fixes GO-2026-6809 in `crypto/x509` (distrust of compromised intermediate certificates). The relay verifies certificates on every outbound HTTPS connection, to the identity provider and to the relay targets. No configuration changes.

**2026-10-21** (v2.2.0)
- See [Upgrading to 2.2](UPGRADING.md#upgrading-to-22) before upgrading.
- New `login.scope`, `login.audience` and `login.resource` fields for the `client_credentials`, `password` and `jwt` grants, so providers such as Microsoft Entra ID, Auth0 and Okta work without a custom grant.
- New `login.client_auth`: `basic` sends the client ID and secret in an `Authorization: Basic` header instead of the request body.
- `login.headers` are now sent with the `client_credentials`, `password` and `jwt` grants as well as the custom grant.

**2026-10-20** (v2.1.0)
- See [Upgrading to 2.1](UPGRADING.md#upgrading-to-21) before upgrading.
- `${env:NAME}` placeholders: any string in the configuration can take its value from an environment variable at startup, without a secrets manager. An unset variable stops the relay with an error naming it. `env` can no longer be used as a `secrets_managers` alias.
- `CONTRIBUTING.md`.
- `NOTICE` is generated from the dependencies (`make notice`) and checked in CI with the dependency licences (`make licenses`), which fail on GPL, LGPL, AGPL and unidentified licences. This corrected the licence of `github.com/pkg/browser` (BSD-2-Clause) and added `golang.org/x/sys` and `github.com/mitchellh/go-homedir`, which were missing.
- Every source file carries an SPDX licence identifier and copyright line.

**2026-10-20** (v2.0.0)
- First production release. See [UPGRADING.md](UPGRADING.md#upgrading-to-20) before upgrading.
- Structured logging with `log/slog`: new `log_level`, `log_format` (`text` or `json`) and `access_log` settings; `debug: true` still works. Logs now go to **stdout** instead of stderr, and lines are `key=value` (or JSON) rather than free text, so update any log parsing. Each request is logged once with its status and duration; error details are on the same line.
- The relay sends its request ID to the relay target as `X-Request-ID`, also when `pushheaders` is off. List it in `relay.strip_headers` to stop this.
- New `/healthz`, `/readyz` and `/metrics` endpoints, without API key. Without `admin_port` these exact paths are no longer relayed; set `admin_port`, change the paths, or disable the endpoints if callers relied on reaching them through the relay.
- New `admin_port` and `server.shutdown_delay` settings.
- A new `logfile` is created with mode `0600` (owner read/write only) instead of `0644`. Existing files keep their permissions.
- Request paths and methods that contain control characters (for example a decoded `%0A`) are quoted in log lines, so they cannot forge log entries.
- `400` and `403` error messages no longer repeat the status in the text (`"missing required parameter \"url\""` instead of `"Bad Request: missing required parameter \"url\""`); the `error` field is unchanged.
- **Stricter configuration**: unknown fields are rejected, and the whole configuration is checked at startup (port, URLs, HTTP methods, grant types and their required fields, `parameters` keys). A configuration with a misspelt or obsolete field, an unsupported `grant_type`, or a `login.url` or `relay.url` that is not an `http://` or `https://` URL now stops the relay with an error instead of being accepted. Run `oauth2relay --check-config` against your configuration before upgrading.
- **Login retries** back off exponentially with jitter. `retry_interval` is now the first wait (default 5 seconds instead of 60) and the waits double up to the new `retry_max_interval` (default 60). A `retry_interval` above 60 keeps a constant wait, as before, apart from the jitter.
- **Background token refresh**: the token is renewed after 80% of its lifetime instead of when a request finds it expired. This adds one token request per token lifetime while the relay is idle; set `token.background_refresh` to `false` to keep the old behaviour.
- New `token` settings: `expiry_buffer` and `default_lifetime` (previously fixed at 10 and 300 seconds), `background_refresh` and `refresh_at`. For a token that lives less than 20 seconds the buffer is now at most half its lifetime; previously a token that lived 10 seconds or less counted as expired as soon as it was issued. A negative or non-numeric `expires_in` is now ignored and `default_lifetime` applies.
- `login.parameters` and `refresh.parameters` default to the standard OAuth 2.0 field names for the `client_credentials`, `password` and `jwt` grants.
- New `secrets_refresh_interval` setting re-fetches secrets periodically, so rotated credentials are picked up without a restart.
- New command-line flags: `--config`, `--check-config`, `--log-level` and `--log-format`. An unknown flag is now an error (exit status 2); previously it was ignored.
- **Internal addresses blocked in `parameter` mode**: target URLs that resolve to loopback, private, link-local (including cloud metadata) or other non-public addresses are refused with `403 destination_blocked`. If you relay to internal services in `parameter` mode, list their addresses in the new `relay.allowed_networks`.
- **Identity provider outages return 503**: when the identity provider is unreachable or answers with an error that may be temporary, callers now get `503 token_unavailable` instead of `500 token_error`, so clients and load balancers can retry. `500 token_error` is kept for failures that retrying will not fix, such as rejected credentials.
- New `tls` settings serve HTTPS on the relay port, with automatic certificate reload, and `ca_file` trusts additional CA certificates for outbound connections.
- The relay logs a warning at startup when the `password` grant is used, and when it serves plain HTTP on an address other than loopback.
- `SECURITY.md` describes how to report vulnerabilities.
- Continuous integration with GitHub Actions: lint, race-enabled unit tests, the Python integration suite, `govulncheck` and a Trivy scan of the container image run on every push and pull request.
- Release archives for Linux, macOS and Windows (amd64 and arm64) with `SHA256SUMS`, a distroless non-root container image, and a hardened systemd unit.
- New [operations runbook](docs/OPERATIONS.md) and [upgrade notes](UPGRADING.md).
- Versions have three parts and follow semantic versioning.

**2026-10-08** (v1.3)
- Security hardening: see [Upgrading to 1.3](UPGRADING.md#upgrading-to-13) for every behaviour change.
- Licensed under the Apache License 2.0.

**2026-10-08** (v1.2)
- Added relay modes: `single`, `passthrough` (the previous behaviour and still the default) and `parameter`. `parameter` mode takes the target URL from a configurable incoming parameter, limits it to `allowed_hosts`, and strips the parameter before relaying.
- An invalid relay mode configuration now stops the server at startup with a descriptive error.
- For GET relays, a query string in the target URL is now kept and merged with the incoming query parameters. Previously it was dropped.

**2025-08-15**
- Implemented optional API key authentication. If the `apiKey` is set in `config.json`, the relay service will require a matching `X-API-Key` header on all incoming requests.
