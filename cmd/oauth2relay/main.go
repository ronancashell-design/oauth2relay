// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"oauth2relay.com/oauth2relay/v2/config"
	"oauth2relay.com/oauth2relay/v2/logging"
	"oauth2relay.com/oauth2relay/v2/redact"
	"oauth2relay.com/oauth2relay/v2/relay"
	"oauth2relay.com/oauth2relay/v2/token"
)

// VERSION is set at build time by the Makefile and the Dockerfile:
//
//	go build -ldflags "-X main.VERSION=2.0.0"
var VERSION = "2.3.0-dev"

const (
	USAGE = `OAUTH2Relay - OAuth 2.0 Authentication Relay Server

Usage:
    oauth2relay [options] [config_file]

Options:
    --config FILE        Configuration file (default: config.json)
    --check-config       Check the configuration file and exit; secrets
                         managers and the identity provider are not contacted
    --log-level LEVEL    Override log_level: debug, info, warn or error
    --log-format FORMAT  Override log_format: text or json
    -h, --help           Show this help message
    -v, --version        Show version information

Arguments:
    config_file    Path to configuration file, instead of --config

Description:
    OAUTH2Relay is a server that handles OAuth 2.0 authentication and token management,
    relaying authenticated requests to configured endpoints. It can fetch secrets from
    AWS Secrets Manager, HashiCorp Vault, and Azure Key Vault.`
)

func main() {
	// All log output is redacted, including startup errors logged before the
	// configured logger is installed.
	log.SetOutput(redact.Writer{W: os.Stderr})

	opts, err := parseArgs(os.Args[1:], os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n\n%s\n", err, USAGE)
		os.Exit(2)
	}
	switch {
	case opts.showHelp:
		fmt.Println(USAGE)
		return
	case opts.showVersion:
		fmt.Printf("OAUTH2Relay version %s\n", VERSION)
		return
	}

	if opts.checkConfig {
		os.Exit(checkConfig(opts, os.Stdout, os.Stderr))
	}

	raw, err := config.ReadFile(opts.configFile)
	if err != nil {
		logFatal("Failed to load config", err)
	}
	cfg, err := config.Parse(raw, opts.apply)
	if err != nil {
		logFatal("Failed to load config", err)
	}

	logging.Init(cfg)
	slog.Info("Starting OAUTH2Relay", "version", VERSION, "log_level", cfg.LogLevel)
	for _, w := range config.Warnings(cfg) {
		slog.Warn(w)
	}

	srv, err := relay.New(cfg, relay.Options{
		Version: VERSION,
		Rebuild: relay.Rebuilder(raw, opts.apply),
	})
	if err != nil {
		logFatal("Failed to start", err)
	}

	// SIGINT and SIGTERM start a graceful shutdown, or stop the relay if it
	// is still starting.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := srv.Run(ctx); err != nil {
		stop()
		logFatal("Relay stopped", err)
	}
}

// checkConfig checks the configuration file for --check-config and returns
// the exit status. When the configuration has no secret placeholders it also
// checks the settings that are otherwise checked after secrets are resolved,
// such as the JWT signing key.
func checkConfig(opts *cliOptions, stdout, stderr io.Writer) int {
	fail := func(err error) int {
		fmt.Fprintf(stderr, "%s: %v\n", opts.configFile, err)
		return 1
	}
	raw, err := config.ReadFile(opts.configFile)
	if err != nil {
		return fail(err)
	}
	cfg, err := config.Parse(raw, opts.apply)
	if err != nil {
		return fail(err)
	}
	// Placeholders are not resolved here: the environment and the secrets
	// managers of the machine running the check may not be the relay's.
	placeholders := len(cfg.SecretsManagers) > 0 || bytes.Contains(raw, []byte("${"+config.EnvAlias+":"))
	if !placeholders {
		if err := token.ValidateLogin(cfg.Login); err != nil {
			return fail(fmt.Errorf("invalid login configuration: %w", err))
		}
	}
	if err := relay.CheckTLSFiles(cfg); err != nil {
		return fail(err)
	}
	for _, w := range config.Warnings(cfg) {
		fmt.Fprintf(stderr, "%s: warning: %s\n", opts.configFile, w)
	}
	fmt.Fprintf(stdout, "%s: configuration is valid\n", opts.configFile)
	if placeholders {
		fmt.Fprintln(stdout, "Secret placeholders were not resolved; they are checked when the relay starts.")
	}
	return 0
}

// logFatal logs a fatal error with its cause and exits. Secrets in the
// cause are masked by the redacting log handler.
func logFatal(message string, err error) {
	slog.Error(message, "error", err)
	os.Exit(1)
}
