// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"oauth2relay.com/oauth2relay/v2/config"
	"oauth2relay.com/oauth2relay/v2/token"
)

func TestMiddlewareOrder(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(up.Close)
	cfg := newRelayConfig(t, config.RelayConfig{URL: up.URL})

	var order []string
	mark := func(name string) func(http.Handler) http.Handler {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				order = append(order, name)
				next.ServeHTTP(w, r)
			})
		}
	}
	s, err := New(cfg, Options{Middleware: []func(http.Handler) http.Handler{mark("outer"), mark("inner")}})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusOK || strings.Join(order, ",") != "outer,inner" {
		t.Errorf("status %d, middleware ran %v; want 200 and [outer inner]", rec.Code, order)
	}
}

func TestMiddlewareCanRejectBeforeRelaying(t *testing.T) {
	cfg := newRelayConfig(t, config.RelayConfig{URL: "http://127.0.0.1:1"})
	deny := func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "denied", http.StatusForbidden)
		})
	}
	s, err := New(cfg, Options{Middleware: []func(http.Handler) http.Handler{deny}})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 from the middleware", rec.Code)
	}
}

// auditLog is an AuditSink that keeps every record.
type auditLog struct {
	mu      sync.Mutex
	records []AuditRecord
}

func (a *auditLog) Audit(_ context.Context, rec AuditRecord) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.records = append(a.records, rec)
}

func TestAuditSink(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello")
	}))
	t.Cleanup(up.Close)
	cfg := newRelayConfig(t, config.RelayConfig{URL: up.URL})
	cfg.APIKey = "secret-key"
	audit := &auditLog{}
	s, err := New(cfg, Options{Audit: audit})
	if err != nil {
		t.Fatal(err)
	}

	ok := httptest.NewRequest("GET", "/items", nil)
	ok.Header.Set(config.APIKeyHeader, "secret-key")
	ok.Header.Set(requestIDHeader, "req-1")
	s.Handler().ServeHTTP(httptest.NewRecorder(), ok)
	s.Handler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/denied", nil))

	if len(audit.records) != 2 {
		t.Fatalf("got %d audit records, want 2", len(audit.records))
	}
	first, second := audit.records[0], audit.records[1]
	host := strings.TrimPrefix(up.URL, "http://")
	if first.RequestID != "req-1" || first.Method != "GET" || first.Path != "/items" || first.Status != 200 ||
		first.Bytes != 5 || first.UpstreamHost != host || first.Error != "" || first.ClientIP == "" || first.Time.IsZero() {
		t.Errorf("successful request record = %+v", first)
	}
	if second.Status != http.StatusUnauthorized || second.Error != "unauthorized" || second.UpstreamHost != "" {
		t.Errorf("rejected request record = %+v", second)
	}
}

func TestRouter(t *testing.T) {
	upA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "a:"+r.Header.Get("Authorization"))
	}))
	t.Cleanup(upA.Close)
	cfgA := newRelayConfig(t, config.RelayConfig{URL: upA.URL})
	cfgA.Relay.FixedToken = ""
	tokens := staticTokens{tok: &token.Token{AccessToken: "route-a-token", ExpiresAt: time.Now().Add(time.Hour)}}

	router := routerFunc(func(r *http.Request) (*Route, error) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/a/"):
			return &Route{Config: cfgA, Tokens: tokens}, nil
		case strings.HasPrefix(r.URL.Path, "/broken/"):
			return nil, errors.New("route table unavailable")
		case strings.HasPrefix(r.URL.Path, "/notoken/"):
			return &Route{Config: cfgA}, nil
		}
		return nil, ErrNoRoute
	})
	s, err := New(newRelayConfig(t, config.RelayConfig{URL: "http://127.0.0.1:1"}), Options{Router: router})
	if err != nil {
		t.Fatal(err)
	}
	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		return rec
	}
	if rec := get("/a/x"); rec.Code != 200 || rec.Body.String() != "a:Bearer route-a-token" {
		t.Errorf("route a: %d %q", rec.Code, rec.Body)
	}
	if rec := get("/other"); rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "no_route") {
		t.Errorf("no route: %d %s", rec.Code, rec.Body)
	}
	if rec := get("/broken/x"); rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "route table") {
		t.Errorf("router error: %d %s", rec.Code, rec.Body)
	}
	if rec := get("/notoken/x"); rec.Code != http.StatusInternalServerError {
		t.Errorf("route without a token source: %d %s", rec.Code, rec.Body)
	}
}

func TestNewRequiresRebuildForSecretRefresh(t *testing.T) {
	cfg := newRelayConfig(t, config.RelayConfig{URL: "https://example.com"})
	cfg.SecretsRefreshInterval = 300
	if _, err := New(cfg, Options{}); err == nil {
		t.Error("New accepted secrets_refresh_interval without Options.Rebuild")
	}
}

// freePort returns a TCP port that is free at the time of the call.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestRunServesAndShutsDown(t *testing.T) {
	idp, _ := newTokenEndpoint(t, [3]string{"200", "application/json", okTokenJSON})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.Header.Get("Authorization"))
	}))
	t.Cleanup(up.Close)

	port, adminPort := freePort(t), freePort(t)
	raw := []byte(fmt.Sprintf(`{
		"host": "127.0.0.1", "port": %d, "admin_port": %d,
		"login": {"url": %q, "grant_type": "client_credentials", "client_id": "id", "client_secret": "secret"},
		"relay": {"url": %q, "headers": {"Authorization": "Bearer ${ACCESSTOKEN}"}}
	}`, port, adminPort, idp.URL, up.URL))
	cfg, err := config.Parse(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, Options{
		AdminRoutes: func(mux *http.ServeMux) {
			mux.HandleFunc("/admin/ping", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "pong") })
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	get := func(port int, path string) (int, string) {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d%s", port, path))
		if err != nil {
			return 0, err.Error()
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}
	waitFor(t, "readiness", 5*time.Second, func() bool { code, _ := get(adminPort, "/readyz"); return code == 200 })

	if code, body := get(port, "/x"); code != 200 || body != "Bearer tok-1" {
		t.Errorf("relayed request: %d %q", code, body)
	}
	if code, body := get(adminPort, "/admin/ping"); code != 200 || body != "pong" {
		t.Errorf("admin route: %d %q", code, body)
	}
	// With admin_port set, admin routes live on the admin port only; on the
	// relay port the path is relayed upstream like any other.
	if _, body := get(port, "/admin/ping"); body == "pong" {
		t.Error("admin route served on the relay port")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run after shutdown = %v, want nil", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Run did not return after the context was cancelled")
	}
	if code, _ := get(port, "/x"); code != 0 {
		t.Errorf("relay port still answering after shutdown: %d", code)
	}
}

func TestRunStopsDuringStartup(t *testing.T) {
	// The identity provider never answers, so startup waits for the first
	// token until the context is cancelled.
	hang := make(chan struct{})
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-hang }))
	t.Cleanup(func() { close(hang); idp.Close() })

	raw := []byte(fmt.Sprintf(`{
		"host": "127.0.0.1", "port": %d,
		"login": {"url": %q, "grant_type": "client_credentials", "client_id": "id", "client_secret": "secret"},
		"relay": {"url": "https://example.com"}
	}`, freePort(t), idp.URL))
	cfg, err := config.Parse(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := s.Run(ctx); err != nil {
		t.Errorf("Run cancelled during startup = %v, want nil", err)
	}
}

func TestRunReportsStartupFailure(t *testing.T) {
	idp, _ := newTokenEndpoint(t, [3]string{"401", "application/json", `{"error":"invalid_client"}`})
	raw := []byte(fmt.Sprintf(`{
		"host": "127.0.0.1", "port": %d,
		"login": {"url": %q, "grant_type": "client_credentials", "client_id": "id", "client_secret": "wrong", "retry_attempts": 1},
		"relay": {"url": "https://example.com"}
	}`, freePort(t), idp.URL))
	cfg, err := config.Parse(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "failed to get initial valid token") {
		t.Errorf("Run = %v, want the initial token error", err)
	}
}
