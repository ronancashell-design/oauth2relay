// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"oauth2relay.com/oauth2relay/v2/config"
	"oauth2relay.com/oauth2relay/v2/logging"
	"oauth2relay.com/oauth2relay/v2/token"
)

// captureLogs sends the default logger to a buffer for the rest of the test.
func captureLogs(t *testing.T, cfg *config.Config) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(logging.New(cfg, &buf))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func TestAccessLogEscapesPath(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(up.Close)
	cfg := newRelayConfig(t, config.RelayConfig{Method: "GET", URL: up.URL})
	buf := captureLogs(t, cfg)

	req := httptest.NewRequest("GET", "/a%0Afake=line", nil)
	relayHandler(httptest.NewRecorder(), req, cfg)
	if lines := strings.Count(strings.TrimSpace(buf.String()), "\n"); lines != 0 {
		t.Errorf("one request produced %d log lines: %s", lines+1, buf)
	}
}

func TestAccessLog(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello")
	}))
	t.Cleanup(up.Close)
	off := false

	t.Run("on", func(t *testing.T) {
		cfg := newRelayConfig(t, config.RelayConfig{Method: "GET", URL: up.URL})
		cfg.LogFormat = "json"
		buf := captureLogs(t, cfg)
		req := httptest.NewRequest("GET", "/x", nil)
		req.Header.Set("X-Request-ID", "abc-123")
		relayHandler(httptest.NewRecorder(), req, cfg)

		var line map[string]any
		if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
			t.Fatalf("not one JSON line: %v: %s", err, buf)
		}
		want := map[string]any{"msg": "request", "level": "INFO", "request_id": "abc-123",
			"method": "GET", "path": "/x", "status": float64(200), "bytes": float64(5),
			"upstream_host": strings.TrimPrefix(up.URL, "http://")}
		for k, v := range want {
			if line[k] != v {
				t.Errorf("%s = %v, want %v", k, line[k], v)
			}
		}
		if _, ok := line["duration_ms"]; !ok {
			t.Error("duration_ms missing")
		}
	})

	t.Run("off logs only failures", func(t *testing.T) {
		cfg := newRelayConfig(t, config.RelayConfig{Method: "GET", URL: up.URL})
		cfg.AccessLog = &off
		cfg.APIKey = "secret-key"
		buf := captureLogs(t, cfg)

		ok := httptest.NewRequest("GET", "/x", nil)
		ok.Header.Set(config.APIKeyHeader, "secret-key")
		relayHandler(httptest.NewRecorder(), ok, cfg)
		if buf.Len() != 0 {
			t.Fatalf("successful request logged with access_log off: %s", buf)
		}
		relayHandler(httptest.NewRecorder(), httptest.NewRequest("GET", "/x", nil), cfg)
		if !strings.Contains(buf.String(), "error=unauthorized") || !strings.Contains(buf.String(), "status=401") {
			t.Errorf("rejected request not logged: %s", buf)
		}
	})
}

func TestRequestIDForwarded(t *testing.T) {
	var got string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get(requestIDHeader)
	}))
	t.Cleanup(up.Close)

	t.Run("caller id", func(t *testing.T) {
		cfg := newRelayConfig(t, config.RelayConfig{Method: "GET", URL: up.URL})
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set(requestIDHeader, "caller-1")
		relayHandler(httptest.NewRecorder(), req, cfg)
		if got != "caller-1" {
			t.Errorf("upstream X-Request-ID = %q, want caller-1", got)
		}
	})
	t.Run("generated id", func(t *testing.T) {
		cfg := newRelayConfig(t, config.RelayConfig{Method: "GET", URL: up.URL})
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set(requestIDHeader, "bad id with spaces")
		rec := httptest.NewRecorder()
		relayHandler(rec, req, cfg)
		if got == "" || got != rec.Header().Get(requestIDHeader) {
			t.Errorf("upstream X-Request-ID = %q, response has %q", got, rec.Header().Get(requestIDHeader))
		}
	})
	t.Run("configured header wins", func(t *testing.T) {
		cfg := newRelayConfig(t, config.RelayConfig{Method: "GET", URL: up.URL})
		cfg.Relay.Headers["x-request-id"] = "fixed"
		relayHandler(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil), cfg)
		if got != "fixed" {
			t.Errorf("upstream X-Request-ID = %q, want fixed", got)
		}
	})
}

func readiness(t *testing.T, s *Server) (int, readinessBody) {
	t.Helper()
	rec := httptest.NewRecorder()
	s.readinessHandler(rec, httptest.NewRequest("GET", "/readyz", nil))
	var body readinessBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("readiness body: %v: %s", err, rec.Body)
	}
	return rec.Code, body
}

func TestReadiness(t *testing.T) {
	idp, _ := newTokenEndpoint(t, [3]string{"503", "application/json", `{"error":"temporarily_unavailable"}`})
	s := testServer(t, loginConfig(idp.URL, 1))

	if code, body := readiness(t, s); code != 503 || body.Status != "starting" || body.Token.State != "none" {
		t.Errorf("before start: %d %+v %+v", code, body, body.Token)
	}

	s.started.Store(true)
	s.tokens.Set(&token.Token{AccessToken: "tok", ExpiresAt: time.Now().Add(time.Hour)})
	code, body := readiness(t, s)
	if code != 200 || body.Status != "ready" || body.Token.State != "valid" ||
		body.Token.ExpiresInSeconds == nil || *body.Token.ExpiresInSeconds < 3500 {
		t.Errorf("valid token: %d %+v %+v", code, body, body.Token)
	}

	// An expired token or a failed renewal is reported but still ready.
	s.tokens.Set(&token.Token{AccessToken: "tok", ExpiresAt: time.Now().Add(-time.Minute)})
	if code, body := readiness(t, s); code != 200 || body.Token.State != "expired" {
		t.Errorf("expired token: %d %+v", code, body.Token)
	}
	if _, err := s.tokens.Token(context.Background()); err == nil {
		t.Fatal("renewal against a failing IdP succeeded")
	}
	if code, body := readiness(t, s); code != 200 || body.Token.State != "renewal_failed" {
		t.Errorf("failed renewal: %d %+v", code, body.Token)
	}

	s.draining.Store(true)
	if code, body := readiness(t, s); code != 503 || body.Status != "draining" {
		t.Errorf("draining: %d %+v", code, body)
	}

	fixed := testServer(t, newRelayConfig(t, config.RelayConfig{URL: "https://example.com"}))
	fixed.started.Store(true)
	if code, body := readiness(t, fixed); code != 200 || body.Token.State != "fixed" || body.Token.ExpiresInSeconds != nil {
		t.Errorf("fixed token: %d %+v", code, body.Token)
	}
}

func TestOperationalEndpointsSkipAPIKey(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(up.Close)

	cfg := newRelayConfig(t, config.RelayConfig{Method: "GET", URL: up.URL})
	cfg.APIKey = "secret-key"
	s := testServer(t, cfg)
	s.started.Store(true)
	mux := http.NewServeMux()
	s.registerOperationalEndpoints(mux, cfg)
	mux.Handle("/", s.Handler())

	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		return rec
	}
	for _, p := range []string{"/healthz", "/readyz", "/metrics"} {
		if rec := get(p); rec.Code != http.StatusOK {
			t.Errorf("%s = %d, want 200 without an API key", p, rec.Code)
		}
	}
	if rec := get("/healthz/extra"); rec.Code != http.StatusUnauthorized {
		t.Errorf("/healthz/extra = %d, want it relayed (and rejected without a key)", rec.Code)
	}
	if body := get("/metrics").Body.String(); !strings.Contains(body, "oauth2relay_build_info") {
		t.Errorf("metrics output missing build_info:\n%s", body)
	}
}

func TestRequestMetrics(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	t.Cleanup(up.Close)
	host := strings.TrimPrefix(up.URL, "http://")
	cfg := newRelayConfig(t, config.RelayConfig{Method: "GET", URL: up.URL})
	cfg.APIKey = "secret-key"

	s := testServer(t, cfg)
	m := s.metrics

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set(config.APIKeyHeader, "secret-key")
	s.relayHandler(httptest.NewRecorder(), req)
	s.relayHandler(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))

	if d := testutil.ToFloat64(m.requestsTotal.WithLabelValues("418", host)); d != 1 {
		t.Errorf("requests_total{code=418} grew by %v, want 1", d)
	}
	if d := testutil.ToFloat64(m.requestsTotal.WithLabelValues("401", "")); d != 1 {
		t.Errorf("requests_total{code=401} grew by %v, want 1", d)
	}
	if d := testutil.ToFloat64(m.inboundAuthFailures); d != 1 {
		t.Errorf("inbound_auth_failures_total grew by %v, want 1", d)
	}
}

func TestUpstreamLabel(t *testing.T) {
	param := &config.RelayConfig{Mode: config.RelayModeParameter, AllowedHosts: []string{"api.example.com", "*.example.org"}}
	tests := []struct {
		rc   *config.RelayConfig
		url  string
		want string
	}{
		{&config.RelayConfig{Mode: config.RelayModePassthrough}, "https://API.example.com:8443/x", "api.example.com:8443"},
		{param, "https://api.example.com/x", "api.example.com"},
		{param, "https://tenant-42.example.org/x", "*.example.org"},
	}
	for _, tt := range tests {
		u, _ := url.Parse(tt.url)
		if got := upstreamLabel(tt.rc, u); got != tt.want {
			t.Errorf("upstreamLabel(%s) = %q, want %q", tt.url, got, tt.want)
		}
	}
}

func TestObserveRenewal(t *testing.T) {
	m := newMetrics("test")
	m.ObserveRenewal("refresh", nil)
	m.ObserveRenewal("refresh", errors.New("idp down"))

	if n := testutil.ToFloat64(m.tokenRenewals.WithLabelValues("refresh", "success")); n != 1 {
		t.Errorf("success = %v, want 1", n)
	}
	if n := testutil.ToFloat64(m.tokenRenewals.WithLabelValues("refresh", "failure")); n != 1 {
		t.Errorf("failure = %v, want 1", n)
	}
}
