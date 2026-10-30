# Security Policy

OAUTH2Relay holds OAuth 2.0 credentials and access tokens on behalf of the services that call it, so we take security reports seriously and appreciate the work that goes into them.

## Reporting a vulnerability

Please report vulnerabilities privately by email to **security@fijomi.com**. Do not open a public issue, pull request or discussion for a suspected vulnerability.

Include as much of the following as you can:

- the version (`oauth2relay --version`) or commit you tested
- the configuration needed to reproduce the problem, with real secrets removed
- steps to reproduce, or a proof of concept
- what an attacker could do with it, and what they need first (for example network access to the relay, a valid API key, or control of an upstream or identity provider)

If you would like to encrypt your report, say so in a first email and we will arrange a key.

## What happens next

| Step | Target time |
|------|-------------|
| Acknowledge your report | 3 working days |
| Confirm whether it is a vulnerability, and its severity | 10 working days |
| Release a fix for a critical or high severity issue | 30 days from confirmation |
| Release a fix for a medium or low severity issue | Next scheduled release, or 90 days |

We will keep you informed while we work on a fix, agree a disclosure date with you, and credit you in the release notes unless you prefer not to be named. Severity is assessed with CVSS v3.1. We request a CVE identifier for confirmed vulnerabilities in released versions.

We ask that you give us a reasonable chance to release a fix before you disclose the issue publicly, and that you do not access data that is not yours, degrade the service of others, or test against systems you do not own or have permission to test.

## Supported versions

Security fixes are released for the latest minor version. Users of older versions should upgrade to receive fixes.

| Version | Supported |
|---------|-----------|
| 2.x | Yes |
| Before 2.0 | No: see [Upgrading to 2.0](UPGRADING.md#upgrading-to-20) |

Customers of the commercial edition receive fixes under the terms of their support agreement.

## Scope

In scope: the code in this repository and the release binaries and container images built from it.

Out of scope:

- vulnerabilities in third-party dependencies that OAUTH2Relay does not reach; we track these with `govulncheck` and update dependencies regularly, but please report them to the dependency's maintainers
- problems that need an insecure configuration the documentation warns against, such as running with `log_level: debug` in production, exposing the relay or its metrics port to untrusted networks without an `apiKey`, or adding broad ranges to `relay.allowed_networks`
- denial of service by sending large volumes of traffic

## Security features

For how to run OAUTH2Relay securely, see [Security Considerations](README.md#security-considerations) in the README.
