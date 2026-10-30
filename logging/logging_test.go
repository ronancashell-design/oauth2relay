// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package logging

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"oauth2relay.com/oauth2relay/v2/config"
	"oauth2relay.com/oauth2relay/v2/redact"
)

// A secret containing characters that JSON or text output escape must
// still be masked.
func TestLoggerRedactsEscapedSecrets(t *testing.T) {
	secret := `pa"ss\word-123`
	redact.AddSecret(secret)
	for _, format := range []string{"text", "json"} {
		t.Run(format, func(t *testing.T) {
			cfg := &config.Config{LogFormat: format, LogLevel: "info"}
			var buf bytes.Buffer
			logger := New(cfg, &buf)
			logger.Info("login with "+secret, "detail", errors.New("rejected "+secret), "data", map[string]string{"p": secret})
			out := buf.String()
			if strings.Contains(out, "word-123") {
				t.Errorf("secret leaked: %s", out)
			}
			if !strings.Contains(out, "[REDACTED]") {
				t.Errorf("no redaction marker: %s", out)
			}
		})
	}
}
