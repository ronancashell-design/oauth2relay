# Contributing to OAUTH2Relay

Thank you for helping to improve OAUTH2Relay. This guide explains how to propose a change and what a pull request needs before it can be merged.

**Security vulnerabilities:** do not open an issue or pull request. Report them privately as described in [SECURITY.md](SECURITY.md).

## Contributor License Agreement

> The Contributor License Agreement is being reviewed by counsel. Until it is in force, Fijomi Systems SL cannot accept pull requests from outside contributors. Issues, bug reports and suggestions are welcome.

OAUTH2Relay is developed by Fijomi Systems SL, which also sells a commercial edition. Before your first pull request can be merged, you need to accept a Contributor License Agreement (CLA):

- An Individual CLA, if you contribute on your own behalf.
- An Entity CLA, signed by your employer, if you contribute as part of your job. You also accept the Individual CLA.

Both agreements will be published here when they are final.

You keep the copyright in your contribution. The CLA grants Fijomi Systems SL a licence to use and distribute it, including under licence terms other than Apache-2.0, and a patent licence like the one in the Apache License.

A CLA check runs on every pull request. The first time, it asks you to accept the agreement by posting a comment; after that, your later pull requests pass automatically.

## Before you start

For anything larger than a small fix, open an issue first to discuss the change. Some features are part of the commercial edition, and pull requests that add them to the open source core will not be accepted.

## Development setup

You need Go (the version in `go.mod`; the `toolchain` line downloads it automatically), Python 3 for the integration tests (CI uses 3.12), `golangci-lint` v2, `openssl`, and optionally Docker.

```bash
make build                        # build ./oauth2relay
python3 -m venv test_scripts/.venv
test_scripts/.venv/bin/pip install -r test_scripts/requirements.txt
```

## Checks

A pull request must pass all of these, which CI also runs:

```bash
gofmt -l .           # must print nothing
make vet
make lint
make test-race       # unit tests with the race detector
make integration     # Python integration tests against the built binary
make vulncheck       # no reachable known vulnerabilities
make licenses        # dependency licences and NOTICE
```

## Coding standards

- Follow the style of the surrounding code: standard `gofmt` formatting, short functions, comments that explain why rather than what.
- Every source file starts with the licence and copyright header; `TestLicenseHeaders` checks it:

  ```go
  // SPDX-License-Identifier: Apache-2.0
  // Copyright 2024-2026 Fijomi Systems SL
  ```

- Add unit tests for new behaviour and keep total coverage at or above 80% (`make cover`). Add an integration test in `test_scripts/` when the change affects how the binary behaves end to end.
- Never log secrets or tokens. Values that could be sensitive go through the `redact` package; add a test if you add a new kind of secret.
- New configuration fields must be validated in `config/validate.go`, documented in the README, and rejected when misspelt (unknown fields are an error).
- Keep package-level state out of the library packages: put it on `relay.Server` or `token.Manager`, so that one process can run several relays. The log redaction registry is the one deliberate exception.
- Exported identifiers in `config`, `token`, `secrets`, `relay`, `egress`, `redact` and `logging` are a library API that other programs build on. Document each one, and say in the pull request when you change or remove one.

## Dependencies

Prefer the standard library. A new dependency needs a reason in the pull request, and its licence must be permissive (Apache-2.0, MIT, BSD or ISC) or MPL-2.0 used unmodified. GPL, LGPL, AGPL and other copyleft or source-available licences are not accepted. `make licenses` fails on them; after adding or updating a dependency, run `make notice` and commit the updated `NOTICE`.

## Documentation

- Update the README for any change to configuration, behaviour, metrics or error responses.
- Add a bullet to the top entry of the README's History section, in the same style as the others.
- If the change can break an existing deployment, describe what to check in [UPGRADING.md](UPGRADING.md).
- Update [docs/OPERATIONS.md](docs/OPERATIONS.md) if it affects how the relay is deployed, monitored or troubleshot.

## Commits and pull requests

- Keep each pull request to one change, with tests and documentation in the same pull request.
- Write commit messages as `type: summary`, where the type is `feat`, `fix`, `docs`, `test`, `ci` or `chore`, followed by a body explaining why the change is needed.
- Describe in the pull request what changed, why, and how you tested it.

## Licence

OAUTH2Relay is licensed under the [Apache License 2.0](LICENSE). By contributing, you agree that your contribution is provided under the terms of the CLA you have accepted.
