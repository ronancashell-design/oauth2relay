# Upgrading OAUTH2Relay

Read the section for every version between the one you run and the one you are installing. The [History](README.md#history) section of the README lists every change, including new features.

## Upgrading to 2.3

Version 2.3 splits the code into a command and importable packages. Configuration files, command-line flags, the release archives and the Dockerfile work as before. Two things change if you build from source or use the code as a library:

- The command is in `cmd/oauth2relay`. Build it with `make build` or `go build ./cmd/oauth2relay`; `go build .` in the repository root no longer works.
- The module path is `oauth2relay.com/oauth2relay/v2`. Import the packages from there, for example `oauth2relay.com/oauth2relay/v2/relay`. Their API is not yet declared stable and may change in minor releases.

## Upgrading to 2.2

Version 2.2 adds `scope`, `audience`, `resource` and `client_auth` to the `login` section. One thing changes for existing configurations:

- `login.headers` are now sent with the `client_credentials`, `password` and `jwt` grants. 2.1 ignored them for these grants. Remove any headers you do not want sent to the identity provider. `Content-Type` is still set by the relay.

## Upgrading to 2.1

Version 2.1 adds `${env:NAME}` placeholders. Two things change for existing configurations:

- A string containing `${env:...}`, which 2.0 passed through unchanged, is now replaced with the environment variable, and the relay does not start if the variable is unset.
- A secrets manager with the alias `env` is rejected. Rename it, and its placeholders, before upgrading.

`oauth2relay --check-config` reports the second case.

## Upgrading to 2.0

Version 2.0 is the first production release. It changes logging, configuration checking and several error responses, so plan the upgrade rather than replacing the binary in place.

### Before you upgrade

1. **Check your configuration with the new binary.** 2.0 rejects configurations that 1.3 accepted:

   ```bash
   oauth2relay --check-config --config /etc/oauth2relay/config.json
   ```

   It exits with status 1 and names the problem if a field is misspelt or obsolete, a `grant_type` is not supported, a URL is not `http://` or `https://`, a `parameters` key is not one of `AccessToken`, `RefreshToken`, `ExpiresIn` or `ExpiresAt`, or a `secrets_managers` entry has an unknown field. It also prints warnings (see below). It does not contact the secrets managers or the identity provider.

2. **Update anything that reads the logs.** See [Logging](#logging).
3. **Check the behaviour changes below** against how you use the relay, in particular `parameter` mode and clients that react to `500` responses.

### Behaviour changes

#### Logging

- Logs go to **stdout** instead of stderr.
- Lines are structured: `key=value` pairs by default, or one JSON object per line with `"log_format": "json"`. Free-text parsing of 1.3 log lines will no longer match. Each request is logged once, with its status and duration, and error details are on the same line.
- A new `logfile` is created with mode `0600` instead of `0644`. Existing files keep their permissions.

#### Configuration

- Unknown fields are rejected, and the whole configuration is checked at startup (see step 1 above). In 1.3 a misspelt field was silently ignored.
- An unknown command-line flag is an error (exit status 2) instead of being ignored.
- `login.parameters` and `refresh.parameters` default to the standard OAuth 2.0 field names for the `client_credentials`, `password` and `jwt` grants. A configuration that sets them is unchanged.

#### Endpoints on the relay port

- `/healthz`, `/readyz` and `/metrics` are now answered by the relay, without an API key, and are no longer relayed. If callers reached paths with these exact names on the relay target through the relay, set `admin_port` (recommended), change the paths under `health` and `metrics`, or turn the endpoints off.
- The relay sends its request ID to the relay target as `X-Request-ID`. List it in `relay.strip_headers` to stop this.

#### Error responses

- **Identity provider outages return `503 token_unavailable`** instead of `500 token_error`, so clients and load balancers can retry. `500 token_error` remains for failures that retrying will not fix, such as rejected credentials. Clients that treat every `500` as fatal will now retry during an outage; clients that only retry `500` should also retry `503`.
- `400` and `403` messages no longer repeat the status in the text. The `error` field is unchanged; match on it rather than on `message`.

#### `parameter` mode

- **Target URLs that resolve to internal addresses are refused** with `403 destination_blocked`: loopback, private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`), link-local (including the cloud metadata address `169.254.169.254`), carrier-grade NAT and other non-public ranges. This applies even when the host name is in `allowed_hosts`. If you relay to internal services in `parameter` mode, list their addresses or networks in the new `relay.allowed_networks`:

  ```json
  "relay": {
      "mode": "parameter",
      "allowed_hosts": ["api.internal.example.com"],
      "allowed_networks": ["10.20.0.0/16"]
  }
  ```

  `single` and `passthrough` modes are not affected.

#### Tokens

- **Background refresh**: the token is renewed after 80% of its lifetime instead of when a request finds it expired. This adds one token request per token lifetime while the relay is idle. Set `"token": {"background_refresh": false}` to keep the 1.3 behaviour.
- **Login retries** back off exponentially with jitter. `retry_interval` is now the first wait (default 5 seconds instead of 60), and the waits double up to the new `retry_max_interval` (default 60). A `retry_interval` above 60 keeps a constant wait, apart from the jitter.
- A token that lives less than 20 seconds is now treated as valid for at least half its lifetime; in 1.3 a token that lived 10 seconds or less counted as expired as soon as it was issued. A negative or non-numeric `expires_in` is ignored and `token.default_lifetime` (300 seconds) applies.

#### Startup warnings

The relay logs a warning at startup, and `--check-config` prints it, when:

- `login.grant_type` is `password` (deprecated by RFC 9700; prefer `client_credentials` or `jwt`), or
- the relay port serves plain HTTP on an address other than loopback. Set `tls`, or make sure a TLS-terminating proxy is the only way to reach the relay port.

The warnings do not stop the relay.

#### Version numbers

Versions now have three parts (`2.0.0`), and the release tags follow [semantic versioning](https://semver.org/): a new major version for breaking changes, a new minor version for new features.

### Upgrade procedure

The relay keeps no state apart from its current access token, so replicas can be upgraded one at a time.

1. Run `--check-config` with the 2.0 binary against the production configuration and fix any errors.
2. Upgrade one replica, or a staging instance. Check that `/readyz` reports `ready`, that requests succeed, and that `oauth2relay_token_renewals_total{result="failure"}` does not increase.
3. Upgrade the remaining replicas.

### Rolling back

1.3 ignores configuration fields it does not know, so a configuration written for 2.0 still loads in 1.3. Settings added in 2.0, such as `tls`, `allowed_networks`, `admin_port` and `secrets_refresh_interval`, then have no effect. In particular, with `tls` set the 1.3 relay serves plain HTTP on the same port, so clients using `https://` will fail until you roll forward again.

## Upgrading to 1.3

Version 1.3 hardens the relay. Check these behaviour changes before upgrading:

- **Header forwarding (`pushheaders`)**: `X-API-Key`, hop-by-hop headers, and the caller's `Authorization` and `Cookie` headers are no longer forwarded. To keep forwarding `Authorization` or `Cookie`, list them in `relay.forward_headers`. Hop-by-hop headers are also removed from responses.
- **Redirects**: upstream redirects are no longer followed; the `3xx` response is returned to the caller. Set `relay.follow_redirects` to `true` to follow redirects that stay on the same host (or on `allowed_hosts` in `parameter` mode).
- **JWT grant**: the token request now uses the standard `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` instead of `jwt-bearer`. If your token endpoint expects the old value, set `login.jwt_grant_type` to `jwt-bearer`. The assertion no longer includes an empty `aud` claim when `jwt_audience` is not set, and now includes `nbf` and `jti`.
- **Login retries**: permanent errors, such as wrong client credentials, are no longer retried, so startup fails immediately instead of after all `retry_attempts`.
- **Secret placeholders**: a placeholder embedded in a longer string (for example `"Bearer ${vault:svc:token}"`) now keeps the surrounding text, every placeholder in a string is resolved, and placeholders in header and parameter maps are resolved (previously they were left as-is). Azure `tenant_id`/`client_id`/`client_secret_env` are now used instead of being ignored.
- **`relay.type`**: deprecated. It still has no effect, and the server now logs a warning when it is set.
- **Error responses**: errors raised by the relay are now JSON (`error`, `message`, `request_id`) and no longer include internal details such as upstream addresses or identity provider messages; these are logged instead. Every response carries an `X-Request-ID` header.
- **Logging**: secrets and tokens are masked in all logs, including debug mode. Startup failures now always log their cause.
- **Methods and bodies**: form and JSON parameter merging now applies to `PUT` and `PATCH` as well as `POST`. For other requests that are not `GET` (for example a `PUT` with an XML body or a `DELETE`), the incoming query string and the configured `parameters` are now added to the target URL instead of being dropped, and the caller's `Content-Type` is kept. An unset `relay.method` is sent as `GET`, as before.
- **`${IP}` behind a proxy**: unchanged unless you set `trusted_proxies`.
- **Timeouts**: relayed requests now time out after 60 seconds (`relay.timeout`) with `504 Gateway Timeout`, and the inbound server applies the `server.*` limits. Raise these if your upstream is slow.
- **Request size**: bodies larger than 10 MiB are rejected with `413` unless `max_request_body_bytes` is raised.
- **Shutdown**: on `SIGTERM` the server drains in-flight requests for up to `server.shutdown_timeout` seconds before exiting.
