# OAUTH2Relay Operations Runbook

How to deploy, run, monitor and troubleshoot OAUTH2Relay in production. The configuration settings themselves are described in the [README](../README.md).

- [Production checklist](#production-checklist)
- [Deployment](#deployment)
- [Scaling](#scaling)
- [Monitoring](#monitoring)
- [Common failures](#common-failures)
- [Rotating credentials](#rotating-credentials)
- [Upgrading](#upgrading)

## Production checklist

| Setting | Recommendation |
|---------|----------------|
| `tls` | Set it, or run behind a TLS-terminating proxy that is the only way to reach the relay port. |
| `apiKey` | Set it unless the network already limits who can reach the relay. Always set it in `parameter` mode, where the caller chooses where the token is sent. |
| `admin_port` | Set it, and keep it on a private network, so metrics and health checks are separate from relayed traffic. |
| `log_level` | `info`. `debug` logs request and response content (with secrets masked) and is for short investigations only. |
| `log_format` | `json` if a log collector reads the logs. |
| Credentials | Keep them in a secrets manager rather than the configuration file, and set `secrets_refresh_interval` if they are rotated. [`examples/config.example.json`](../examples/config.example.json) reads them from environment variables instead. |
| `login.grant_type` | `client_credentials` or `jwt`. Avoid `password`. |
| `relay.allowed_hosts` | `parameter` mode only: as narrow as possible. Keep `allowed_networks` empty unless the relay must reach internal services. |
| `server.shutdown_delay` | Behind a load balancer or in Kubernetes, a few seconds (for example `5`), so traffic stops before the listener closes. |

Check every configuration change before deploying it:

```bash
oauth2relay --check-config --config config.json
```

It exits with status 1 and names the problem if the configuration is invalid, and prints warnings for settings that work but are not recommended. It does not contact the secrets managers or the identity provider, so it is safe to run in CI.

## Deployment

The relay is a single static binary. It needs its configuration file, outbound HTTPS access to the identity provider, the relay targets and any secrets managers, and nothing else: no database, no disk apart from an optional `logfile`.

### Release archives

Each release has an archive per platform (Linux, macOS and Windows; amd64 and arm64) and a `SHA256SUMS` file. Verify the download before installing it:

```bash
sha256sum -c SHA256SUMS --ignore-missing
tar xzf oauth2relay_2.0.0_linux_amd64.tar.gz
```

The archive contains the binary, the licence, this runbook, the upgrade notes and the systemd unit.

To build from source, run `make build`; `make release` builds every archive and `SHA256SUMS` into `dist/`.

### systemd

[`deploy/systemd/oauth2relay.service`](../deploy/systemd/oauth2relay.service) runs the relay as an unprivileged `oauth2relay` user with a restrictive sandbox. The installation commands are at the top of the file. In outline:

- The binary is `/usr/local/bin/oauth2relay` and the configuration `/etc/oauth2relay/config.json`, readable by the `oauth2relay` group only.
- Environment variables go in `/etc/oauth2relay/oauth2relay.env`, mode `0600`, owned by root: credentials referenced as `${env:NAME}` in the configuration, and the secrets managers' settings (`AWS_REGION`, `VAULT_ADDR`, `VAULT_SECRET_ID`, `AZURE_CLIENT_SECRET` and so on). The configuration file then holds no secrets.
- The configuration is checked before each start (`ExecStartPre`), so a restart with an invalid configuration fails at once with the reason in the journal.
- Logs go to the journal: `journalctl -u oauth2relay -f`. If you set `logfile`, use `/var/log/oauth2relay/`, the only directory the service can write to.
- The relay port must be 1024 or higher unless you uncomment the `CAP_NET_BIND_SERVICE` lines.
- `systemctl stop` sends `SIGTERM`; the relay drains in-flight requests (see [Shutdown](#shutdown)). Keep `TimeoutStopSec` above `server.shutdown_delay` + `server.shutdown_timeout`.

To apply a configuration change, check it, then `systemctl restart oauth2relay`. Requests in flight during the restart are drained, but new connections are refused until the relay is ready again, so restart one instance at a time if you run several behind a load balancer.

### Container

The image is built from [`Dockerfile`](../Dockerfile) (`make docker`) on a distroless base: it has no shell or package manager and runs as UID/GID 65532. Releases publish it to `ghcr.io` for `linux/amd64` and `linux/arm64`.

```bash
docker run -d --name oauth2relay -p 8080:8080 -p 9090:9090 \
  -v /etc/oauth2relay:/etc/oauth2relay:ro \
  --env-file /etc/oauth2relay/oauth2relay.env \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  ghcr.io/OWNER/oauth2relay:2.0.0
```

- The configuration is read from `/etc/oauth2relay/config.json`; pass other arguments after the image name to change this.
- Set `"host": "0.0.0.0"` in the configuration, otherwise the relay only listens inside the container.
- The configuration file must be readable by UID 65532.
- The image has no `HEALTHCHECK`, because there is no shell or HTTP client in it to run one. Use the orchestrator's HTTP checks against `/healthz` and `/readyz`.

### Kubernetes

A Helm chart is planned. Until then, the essential parts of a Deployment are:

```yaml
spec:
  template:
    spec:
      terminationGracePeriodSeconds: 30
      securityContext:
        runAsNonRoot: true
        seccompProfile: {type: RuntimeDefault}
      containers:
        - name: oauth2relay
          image: ghcr.io/OWNER/oauth2relay:2.0.0
          ports:
            - {name: relay, containerPort: 8080}
            - {name: admin, containerPort: 9090}
          livenessProbe:
            httpGet: {path: /healthz, port: admin}
          readinessProbe:
            httpGet: {path: /readyz, port: admin}
            periodSeconds: 5
          startupProbe:
            httpGet: {path: /healthz, port: admin}
            failureThreshold: 30
            periodSeconds: 2
          securityContext:
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
            capabilities: {drop: [ALL]}
          volumeMounts:
            - {name: config, mountPath: /etc/oauth2relay, readOnly: true}
      volumes:
        - name: config
          secret:
            secretName: oauth2relay-config
```

with `"host": "0.0.0.0"`, `"admin_port": 9090` and `"server": {"shutdown_delay": 5}` in the configuration. Keep the configuration in a Secret if it contains credentials. For Vault, use the `kubernetes` auth method with a dedicated service account; for AWS and Azure, use workload identity (IRSA, EKS Pod Identity or Azure Workload Identity) instead of static keys.

The liveness probe passes as soon as the admin port is listening, so a slow first login does not get the pod restarted. Readiness passes once the first token has been obtained. TLS certificates mounted from a Secret, for example by cert-manager, are reloaded without a restart.

### Shutdown

On `SIGTERM` or `SIGINT` the relay:

1. Reports `draining` on `/readyz` and keeps serving for `server.shutdown_delay` seconds (default 0), so load balancers stop sending new traffic.
2. Stops accepting connections and waits up to `server.shutdown_timeout` seconds (default 15) for in-flight requests to finish.
3. Exits with status 0.

## Scaling

The relay is stateless apart from its current access token, so it scales horizontally behind any load balancer without session affinity.

Each replica obtains and renews its own token: with background refresh on (the default), N replicas make about N token requests per token lifetime, whether or not they serve traffic. Check that this stays within the identity provider's rate limits and any limit on active tokens per client. Login retries are jittered so that replicas do not retry in step after an outage.

Form and JSON request bodies are read into memory to merge the configured parameters, up to `max_request_body_bytes` (default 10 MiB) each, so memory use grows with concurrent large requests of those types. Other bodies are streamed. There are no published benchmarks yet; size replicas by load testing with your own traffic, watching `process_resident_memory_bytes` and `oauth2relay_request_duration_seconds`.

## Monitoring

The relay exports Prometheus metrics on `/metrics`; every metric is described in the [README](../README.md#health-checks-and-metrics). Suggested alerts:

| Alert | Expression | Meaning |
|-------|------------|---------|
| Token renewal failing | `increase(oauth2relay_token_renewals_total{result="failure"}[10m]) > 0` | The identity provider is failing or rejecting the credentials. The relay keeps the current token until it expires. |
| Token expired | `oauth2relay_token_expires_in_seconds < 0` | Requests are failing with `503` or `500`. |
| Relay errors | `sum(rate(oauth2relay_requests_total{code=~"5.."}[5m])) / sum(rate(oauth2relay_requests_total[5m])) > 0.05` | More than 5% of requests fail. This counts the relay's own errors and errors returned by the relay target; the `request` log lines tell them apart. |
| Certificate expiring | `oauth2relay_tls_certificate_expiry_timestamp_seconds - time() < 14 * 86400` | The relay's TLS certificate expires within 14 days and has not been renewed. |
| Secrets stale | `time() - oauth2relay_secrets_last_refresh_timestamp_seconds > 3 * <secrets_refresh_interval>` | Secret re-fetches are failing; rotated credentials will not be picked up. |
| Relay down | `up{job="oauth2relay"} == 0` | Prometheus cannot scrape the relay. |

Readiness does not fail when token renewal fails (see the README), so these alerts, not the load balancer, are how an identity provider problem is noticed.

Every response has an `X-Request-ID` header, and the same ID is in the relay's `request` log line and is sent to the relay target. Ask callers for it when they report a failed request.

## Common failures

### The relay does not start

Startup failures are logged at `ERROR` with the cause in `error`, and the process exits with status 1.

| Log message | Cause and fix |
|-------------|---------------|
| `Failed to load config` | The file is missing, unreadable or invalid. Run `--check-config` for the exact problem. |
| `Failed to prepare the configuration` | A secrets manager could not be reached, refused the relay's credentials, or a secret or JSON key does not exist. The error names the alias and secret. Check the secrets manager's environment variables and permissions. |
| `Failed to load ca_file` | The `ca_file` is missing or contains no PEM certificates. |
| `Failed to get initial valid token` | The first login failed. `Login failed; not retrying because the error is permanent` means the identity provider rejected the request (for example `invalid_client`): check the client ID, secret, key, scope and token URL. `Login failed; no retries remaining` means it was unreachable or failing throughout the retries. |
| `Failed to set up TLS` | `tls.cert_file` or `tls.key_file` is missing, unreadable, or the certificate does not match the key. |
| `Server failed` | Usually the port is in use (`address already in use`) or below 1024 without the capability to bind it. |

With systemd, `ExecStartPre` runs `--check-config`, so a configuration error shows in `journalctl -u oauth2relay` before the relay itself runs.

### Requests fail

The relay's own errors are JSON with an `error` code; the `request` log line for the same `request_id` has the cause in `detail`. Responses without that JSON body come from the relay target and are passed through unchanged.

| Status and `error` | Likely cause | What to do |
|--------------------|--------------|------------|
| `401 unauthorized` | Missing or wrong `X-API-Key`. | Check the caller's key. `oauth2relay_inbound_auth_failures_total` counts these. |
| `403 forbidden` | `parameter` mode: the target host is not in `allowed_hosts`. | Add the host if it should be allowed. |
| `403 destination_blocked` | `parameter` mode: the target resolves to an internal address. | If the target is meant to be internal, add its address or network to `relay.allowed_networks`. Otherwise this is the protection working. |
| `503 token_unavailable` | The identity provider is unreachable, answering with errors, or slower than `token_wait_timeout`. | Check the identity provider's status and the `Login failed; retrying` and `Background token renewal failed; retrying` log lines. Requests succeed again as soon as a token is obtained; no restart is needed. |
| `500 token_error` | The identity provider rejected the relay's credentials, for example after they were revoked or expired. | Fix the credentials (see [Rotating credentials](#rotating-credentials)). |
| `502 upstream_error` | The relay could not connect to the relay target, or the connection failed (DNS, TLS, connection refused or reset). | Check `detail`. For TLS errors with a private CA, set `ca_file`. |
| `502 redirect_blocked` | The relay target redirected to a host that is not allowed. | Point the relay at the final URL, or check `follow_redirects`. |
| `504 upstream_timeout` | The relay target took longer than `relay.timeout` (default 60 seconds). | Raise `relay.timeout` (and `server.write_timeout` with it) if the target is legitimately slow. |
| `413 request_too_large` | The body is larger than `max_request_body_bytes`. | Raise the limit if needed. |
| `401` or `403` from the relay target | The token was accepted from the identity provider but the target refuses it, usually because of a missing scope or audience. | Check the scope and audience the relay requests (for example `jwt_scope` and `jwt_audience`, or the login request's parameters), and the target's logs. |

### The certificate was renewed but clients see the old one

The relay checks the certificate files at most every 10 seconds when a TLS handshake happens. If the new files cannot be loaded, it keeps the old certificate and logs `Could not reload the TLS certificate; keeping the current one` with the reason, typically a key that does not match the certificate.

### Debug logging

To investigate a problem, restart one instance with `--log-level debug`. Debug logs include the token requests and relayed requests and responses, with secrets and tokens masked, but they may contain personal data from request bodies. Switch back to `info` afterwards.

## Rotating credentials

### Identity provider client secret or private key

With the credential in a secrets manager and `secrets_refresh_interval` set, no restart is needed:

1. Create the new client secret, or register the new public key, at the identity provider, keeping the old one valid.
2. Store the new value in the secrets manager under the same name. For a JWT key, also update `jwt_key_id` if the identity provider selects keys by `kid`; keep it in the secrets manager too if it changes with the key.
3. Wait one `secrets_refresh_interval` (check `oauth2relay_secrets_last_refresh_timestamp_seconds` on every replica), plus one token lifetime so the next login uses the new credential. `oauth2relay_token_renewals_total{type="login",result="success"}` increases when it does.
4. Revoke the old credential at the identity provider.

Without `secrets_refresh_interval`, update the secrets manager or the configuration file, restart the replicas one at a time, then revoke the old credential.

If the old credential was revoked first, renewals fail with `500 token_error` once the current token expires. Update the credential and wait for the next re-fetch, or restart.

### Relay API key

The relay accepts one `apiKey`, so changing it needs callers and relay to switch together:

1. Store the new key where the callers can read it, but keep them using the old one.
2. Change `apiKey` on the relay: with the value in a secrets manager and `secrets_refresh_interval` set, it changes at the next re-fetch; otherwise restart.
3. Switch the callers to the new key.

Requests sent with the old key between steps 2 and 3 fail with `401`. Keep that window short, or run a second set of replicas with the new key and move callers across. Multiple API keys with overlapping validity are planned.

### Secrets manager credentials

- **AWS**: use an IAM role (instance profile, IRSA or EKS Pod Identity) rather than access keys; the AWS SDK renews the role's credentials itself.
- **Vault AppRole**: the relay logs in with the SecretID at startup and at every re-fetch. Rotate the SecretID by updating `VAULT_SECRET_ID` (or the variable named in `secret_id_env`) and restarting. With the `kubernetes` auth method there is nothing to rotate.
- **Azure**: use a managed identity or workload identity rather than a client secret; with a service principal, update the secret's environment variable and restart.

### TLS certificate

Replace the files at `tls.cert_file` and `tls.key_file`. The relay picks them up within 10 seconds of the next connection, without a restart. Write the key first or replace both files atomically (for example by renaming them into place); while the pair does not match, the old certificate stays in use.

## Upgrading

Read [UPGRADING.md](../UPGRADING.md) for the versions you are upgrading across, run `--check-config` with the new binary, then upgrade one replica at a time and check readiness and the token renewal metrics before continuing.
