// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package config

import (
	"fmt"
	"log/slog"
	"strings"
)

// Log formats accepted in log_format.
const (
	LogFormatText = "text"
	LogFormatJSON = "json"
)

var logLevels = map[string]slog.Level{
	"debug": slog.LevelDebug,
	"info":  slog.LevelInfo,
	"warn":  slog.LevelWarn,
	"error": slog.LevelError,
}

// normaliseLogging validates log_level and log_format and applies their
// defaults. The older "debug": true is the same as log_level "debug" when
// log_level is not set. Afterwards cfg.Debug reflects the effective level.
func (cfg *Config) normaliseLogging() error {
	cfg.LogLevel = strings.ToLower(strings.TrimSpace(cfg.LogLevel))
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
		if cfg.Debug {
			cfg.LogLevel = "debug"
		}
	}
	if _, ok := logLevels[cfg.LogLevel]; !ok {
		return fmt.Errorf("log_level %q is not one of debug, info, warn or error", cfg.LogLevel)
	}
	cfg.Debug = cfg.LogLevel == "debug"

	cfg.LogFormat = strings.ToLower(strings.TrimSpace(cfg.LogFormat))
	switch cfg.LogFormat {
	case "":
		cfg.LogFormat = LogFormatText
	case LogFormatText, LogFormatJSON:
	default:
		return fmt.Errorf("log_format %q is not one of text or json", cfg.LogFormat)
	}
	return nil
}

// newLogger builds a logger that writes cfg's level and format to out.
// SlogLevel returns the slog level for log_level.
func (cfg *Config) SlogLevel() slog.Level {
	return logLevels[cfg.LogLevel]
}
