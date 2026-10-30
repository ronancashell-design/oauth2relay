// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

// Package logging builds the relay's structured, redacted logger.
//
// All logging goes through log/slog. Values are redacted twice: each
// attribute (including the message) before it is formatted, so secrets are
// caught before quoting or JSON escaping changes them, and the formatted
// line again by redact.Writer as a backstop.
package logging

import (
	"io"
	"log/slog"
	"os"

	"oauth2relay.com/oauth2relay/v2/config"
	"oauth2relay.com/oauth2relay/v2/redact"
)

// New returns a logger with cfg's level and format that writes to out.
func New(cfg *config.Config, out io.Writer) *slog.Logger {
	opts := &slog.HandlerOptions{
		Level:       cfg.SlogLevel(),
		ReplaceAttr: redact.ReplaceAttr,
	}
	w := redact.Writer{W: out}
	if cfg.LogFormat == config.LogFormatJSON {
		return slog.New(slog.NewJSONHandler(w, opts))
	}
	return slog.New(slog.NewTextHandler(w, opts))
}

// Init installs the configured logger as the default. Logs go to stdout
// unless logfile is set. The standard log package is routed through the
// same logger.
func Init(cfg *config.Config) {
	var out io.Writer = os.Stdout
	var fileErr error
	if cfg.LogFile != "" {
		file, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			fileErr = err
		} else {
			out = file
		}
	}
	slog.SetDefault(New(cfg, out))
	if fileErr != nil {
		slog.Warn("Unable to open log file, logging to stdout", "logfile", cfg.LogFile, "error", fileErr)
	}
}
