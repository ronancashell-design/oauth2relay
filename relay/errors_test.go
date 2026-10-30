// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package relay

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"oauth2relay.com/oauth2relay/v2/config"
)

func decodeError(t *testing.T, rec *httptest.ResponseRecorder) errorBody {
	t.Helper()
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var body errorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %q", rec.Body)
	}
	if body.RequestID == "" || body.RequestID != rec.Header().Get(requestIDHeader) {
		t.Errorf("request_id %q does not match header %q", body.RequestID, rec.Header().Get(requestIDHeader))
	}
	return body
}

func TestErrorResponseHidesUpstreamDetails(t *testing.T) {
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()

	cfg := newRelayConfig(t, config.RelayConfig{Method: "GET", URL: deadURL})
	rec := doRelay(cfg, "GET", "http://localhost:8000/x", "", "")
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	body := decodeError(t, rec)
	if body.Error != "upstream_error" {
		t.Errorf("error = %q, want upstream_error", body.Error)
	}
	raw := rec.Body.String()
	if strings.Contains(raw, strings.TrimPrefix(deadURL, "http://")) || strings.Contains(raw, "connection refused") {
		t.Errorf("internal details leaked to caller: %s", raw)
	}
}

func TestErrorResponseTokenFailure(t *testing.T) {
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()

	cfg := &config.Config{
		Login: &config.LoginConfig{URL: deadURL + "/token", GrantType: "client_credentials", ClientID: "id",
			ClientSecret: "secret", RetryAttempts: 1, Parameters: map[string]string{"AccessToken": "access_token"}},
		Relay: config.RelayConfig{Method: "GET", URL: "https://example.com", Mode: config.RelayModeSingle},
	}
	rec := doRelay(cfg, "GET", "http://localhost:8000/x", "", "")
	// An unreachable IdP is temporary, so callers get a retryable 503.
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if body := decodeError(t, rec); body.Error != "token_unavailable" {
		t.Errorf("error = %q, want token_unavailable", body.Error)
	}
	if strings.Contains(rec.Body.String(), strings.TrimPrefix(deadURL, "http://")) {
		t.Errorf("IdP address leaked to caller: %s", rec.Body)
	}
}

func TestRequestIDHandling(t *testing.T) {
	cfg := newRelayConfig(t, config.RelayConfig{Method: "GET", URL: "https://example.com"})
	cfg.APIKey = "relay-secret"

	t.Run("caller ID is echoed", func(t *testing.T) {
		rec := relayWithHeaders(cfg, map[string]string{requestIDHeader: "abc-123"})
		if body := decodeError(t, rec); body.RequestID != "abc-123" || body.Error != "unauthorized" {
			t.Errorf("body = %+v", body)
		}
	})
	t.Run("missing ID is generated", func(t *testing.T) {
		rec := relayWithHeaders(cfg, nil)
		if id := decodeError(t, rec).RequestID; len(id) != 32 {
			t.Errorf("generated request ID %q, want 32 hex characters", id)
		}
	})
	t.Run("malformed ID is replaced", func(t *testing.T) {
		rec := relayWithHeaders(cfg, map[string]string{requestIDHeader: "bad id\nwith newline"})
		if id := decodeError(t, rec).RequestID; strings.Contains(id, " ") || len(id) != 32 {
			t.Errorf("request ID %q, want a generated one", id)
		}
	})
}

func TestErrorResponseParameterModeKeepsDetail(t *testing.T) {
	cfg := newRelayConfig(t, config.RelayConfig{Mode: "parameter", Method: "GET", AllowedHosts: []string{"example.com"}})
	rec := doRelay(cfg, "GET", "http://localhost:8000/?external_url=https://evil.com/", "", "")
	body := decodeError(t, rec)
	if rec.Code != http.StatusForbidden || body.Error != "forbidden" || !strings.Contains(body.Message, "evil.com") {
		t.Errorf("status %d body %+v, want 403 naming the rejected host", rec.Code, body)
	}
}
