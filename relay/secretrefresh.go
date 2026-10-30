// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package relay

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"oauth2relay.com/oauth2relay/v2/config"
	"oauth2relay.com/oauth2relay/v2/redact"
	"oauth2relay.com/oauth2relay/v2/secrets"
	"oauth2relay.com/oauth2relay/v2/token"
)

// Periodic secret re-fetch.
//
// With secrets_refresh_interval set, the configuration is rebuilt from the
// file contents read at startup and its secret placeholders are resolved
// again. If that succeeds the new configuration replaces the old one for
// all later requests and renewals, so rotated credentials are picked up
// without a restart. If it fails the old configuration stays in use.
//
// The file itself is not re-read: changing settings still needs a restart.

// Prepare resolves cfg's secret placeholders and the older "$NAME" login
// values, registers the secret values for log redaction and checks the
// settings that need them.
func Prepare(ctx context.Context, cfg *config.Config) error {
	if err := secrets.Resolve(ctx, cfg); err != nil {
		return fmt.Errorf("failed to resolve secrets from managers: %w", err)
	}
	cfg.Login.ExpandEnv()
	registerConfigSecrets(cfg)
	if err := token.ValidateLogin(cfg.Login); err != nil {
		return fmt.Errorf("invalid login configuration: %w", err)
	}
	return nil
}

// registerConfigSecrets masks the credentials held in the configuration.
// It runs after secret placeholders are resolved.
func registerConfigSecrets(cfg *config.Config) {
	redact.AddSecret(cfg.APIKey)
	redact.AddSecret(cfg.Relay.FixedToken)
	if l := cfg.Login; l != nil {
		for _, v := range []string{l.Password, l.ClientSecret, l.AuthString, l.JWTKey, l.JWTPrivateKey} {
			redact.AddSecret(v)
		}
	}
	if cfg.Refresh != nil {
		redact.AddToken(cfg.Refresh.Token)
	}
}

// Rebuilder returns a function that builds a new, prepared configuration
// from raw, for Options.Rebuild. override is applied as in config.Parse.
func Rebuilder(raw []byte, override func(*config.Config)) func(context.Context) (*config.Config, error) {
	return func(ctx context.Context) (*config.Config, error) {
		cfg, err := config.Parse(raw, override)
		if err != nil {
			return nil, err
		}
		if err := Prepare(ctx, cfg); err != nil {
			return nil, err
		}
		return cfg, nil
	}
}

// runSecretRefresher rebuilds the configuration every interval and puts it
// in use, until ctx is done.
func (s *Server) runSecretRefresher(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		cfg, err := s.opts.Rebuild(ctx)
		s.metrics.observeSecretRefresh(err)
		if err != nil {
			slog.Warn("Re-fetching secrets failed; keeping the current values", "error", err,
				"next_attempt", time.Now().Add(interval).Format(time.RFC3339))
			continue
		}
		s.setConfig(cfg)
		slog.Debug("Secrets re-fetched")
	}
}
