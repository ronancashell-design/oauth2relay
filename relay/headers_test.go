// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package relay

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"oauth2relay.com/oauth2relay/v2/config"
)

// newHeaderUpstream returns a fake 3rd party that records the headers it
// receives and answers with a few hop-by-hop headers of its own.
func newHeaderUpstream(t *testing.T) (*httptest.Server, *http.Header) {
	t.Helper()
	got := &http.Header{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*got = r.Header.Clone()
		w.Header().Set("X-Upstream", "yes")
		w.Header().Set("Keep-Alive", "timeout=5")
		w.Header().Set("Proxy-Authenticate", "Basic")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

func relayWithHeaders(cfg *config.Config, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", "http://localhost:8000/x", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	relayHandler(rec, req, cfg)
	return rec
}

var incomingHeaders = map[string]string{
	"X-API-Key":           "relay-secret",
	"X-Client-ID":         "client-123",
	"X-Request-ID":        "req-456",
	"Authorization":       "Bearer caller-token",
	"Cookie":              "session=abc",
	"Connection":          "keep-alive, X-Hop",
	"X-Hop":               "hop-value",
	"Keep-Alive":          "timeout=5",
	"Proxy-Authorization": "Basic Zm9vOmJhcg==",
	"Te":                  "trailers",
	"Upgrade":             "websocket",
}

func TestPushHeadersDefault(t *testing.T) {
	up, got := newHeaderUpstream(t)
	cfg := newRelayConfig(t, config.RelayConfig{Method: "GET", URL: up.URL, PushHeaders: true})
	cfg.APIKey = "relay-secret"

	rec := relayWithHeaders(cfg, incomingHeaders)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
	}

	for _, h := range []string{"X-API-Key", "Cookie", "X-Hop", "Keep-Alive", "Proxy-Authorization", "Te", "Upgrade"} {
		if v := got.Get(h); v != "" {
			t.Errorf("%s forwarded upstream: %q", h, v)
		}
	}
	for h, want := range map[string]string{"X-Client-ID": "client-123", "X-Request-ID": "req-456"} {
		if v := got.Get(h); v != want {
			t.Errorf("%s = %q, want %q", h, v, want)
		}
	}
	// The relay's own Authorization header is used, not the caller's.
	if v := got.Get("Authorization"); v != "Bearer fixed-token" {
		t.Errorf("Authorization = %q, want the relay's token", v)
	}
}

func TestPushHeadersCallerAuthorizationNotForwarded(t *testing.T) {
	up, got := newHeaderUpstream(t)
	cfg := newRelayConfig(t, config.RelayConfig{Method: "GET", URL: up.URL, PushHeaders: true})
	cfg.Relay.Headers = map[string]string{"X-Token": "${ACCESSTOKEN}"} // relay does not set Authorization

	relayWithHeaders(cfg, incomingHeaders)
	if v := got.Get("Authorization"); v != "" {
		t.Errorf("caller's Authorization forwarded upstream: %q", v)
	}
}

func TestPushHeadersAllowList(t *testing.T) {
	up, got := newHeaderUpstream(t)
	cfg := newRelayConfig(t, config.RelayConfig{Method: "GET", URL: up.URL, PushHeaders: true,
		ForwardHeaders: []string{"x-client-id", "Cookie", "Keep-Alive"}})

	headers := map[string]string{"X-Not-Allowed": "value"}
	for k, v := range incomingHeaders {
		headers[k] = v
	}
	relayWithHeaders(cfg, headers)
	if v := got.Get("X-Client-ID"); v != "client-123" {
		t.Errorf("X-Client-ID = %q, want client-123", v)
	}
	if v := got.Get("Cookie"); v != "session=abc" {
		t.Errorf("Cookie = %q, want it forwarded when explicitly allowed", v)
	}
	for _, h := range []string{"X-Not-Allowed", "X-API-Key", "Keep-Alive"} {
		if v := got.Get(h); v != "" {
			t.Errorf("%s forwarded despite allow-list: %q", h, v)
		}
	}
}

func TestPushHeadersStripList(t *testing.T) {
	up, got := newHeaderUpstream(t)
	cfg := newRelayConfig(t, config.RelayConfig{Method: "GET", URL: up.URL, PushHeaders: true,
		StripHeaders: []string{"x-request-id"}})

	relayWithHeaders(cfg, incomingHeaders)
	if v := got.Get("X-Request-ID"); v != "" {
		t.Errorf("X-Request-ID forwarded despite strip_headers: %q", v)
	}
	if v := got.Get("X-Client-ID"); v != "client-123" {
		t.Errorf("X-Client-ID = %q, want client-123", v)
	}
}

func TestPushHeadersDisabled(t *testing.T) {
	up, got := newHeaderUpstream(t)
	cfg := newRelayConfig(t, config.RelayConfig{Method: "GET", URL: up.URL})

	relayWithHeaders(cfg, incomingHeaders)
	if v := got.Get("X-Client-ID"); v != "" {
		t.Errorf("X-Client-ID forwarded with pushheaders off: %q", v)
	}
}

func TestResponseHopByHopHeadersRemoved(t *testing.T) {
	up, _ := newHeaderUpstream(t)
	cfg := newRelayConfig(t, config.RelayConfig{Method: "GET", URL: up.URL})

	rec := relayWithHeaders(cfg, nil)
	if rec.Header().Get("X-Upstream") != "yes" {
		t.Errorf("end-to-end response header missing")
	}
	for _, h := range []string{"Keep-Alive", "Proxy-Authenticate"} {
		if v := rec.Header().Get(h); v != "" {
			t.Errorf("%s returned to caller: %q", h, v)
		}
	}
}

func TestForwardHeadersRejectsAPIKey(t *testing.T) {
	rc := config.RelayConfig{URL: "https://example.com", ForwardHeaders: []string{"x-api-key"}}
	if err := rc.Validate(); err == nil || !strings.Contains(err.Error(), "must not include X-API-Key") {
		t.Fatalf("validate() error = %v, want X-API-Key error", err)
	}
}

func TestAPIKeyMatches(t *testing.T) {
	tests := []struct {
		supplied string
		want     bool
	}{
		{"secret-key", true},
		{"secret-kex", false},
		{"secret-key ", false},
		{"SECRET-KEY", false},
		{"", false},
		{"secret-key-longer", false},
	}
	for _, tt := range tests {
		if got := apiKeyMatches(tt.supplied, "secret-key"); got != tt.want {
			t.Errorf("apiKeyMatches(%q) = %v, want %v", tt.supplied, got, tt.want)
		}
	}
}

func TestRelayHandlerAPIKey(t *testing.T) {
	up, _ := newHeaderUpstream(t)
	cfg := newRelayConfig(t, config.RelayConfig{Method: "GET", URL: up.URL})
	cfg.APIKey = "relay-secret"

	if rec := relayWithHeaders(cfg, map[string]string{"X-API-Key": "wrong"}); rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong key: status = %d, want 401", rec.Code)
	}
	if rec := relayWithHeaders(cfg, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("missing key: status = %d, want 401", rec.Code)
	}
	if rec := relayWithHeaders(cfg, map[string]string{"X-API-Key": "relay-secret"}); rec.Code != http.StatusOK {
		t.Errorf("valid key: status = %d, want 200", rec.Code)
	}
}
