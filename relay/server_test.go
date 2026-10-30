// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package relay

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"oauth2relay.com/oauth2relay/v2/config"
)

func TestRelayHandlerUpstreamTimeout(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(5 * time.Second):
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(up.Close)

	cfg := newRelayConfig(t, config.RelayConfig{Method: "GET", URL: up.URL, Timeout: 1})
	start := time.Now()
	rec := doRelay(cfg, "GET", "http://localhost:8000/slow", "", "")
	if rec.Code != http.StatusGatewayTimeout {
		t.Errorf("status = %d, want 504", rec.Code)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("relay took %v, want about 1s", elapsed)
	}
}

func TestRelayHandlerBodyTooLarge(t *testing.T) {
	up, _ := newUpstream(t)
	big := `{"data":"` + strings.Repeat("x", 100) + `"}`

	for _, tc := range []struct{ method, contentType string }{
		{"POST", "application/json"},
		{"POST", "application/x-www-form-urlencoded"},
		{"PUT", "text/plain"},
	} {
		t.Run(tc.method+" "+tc.contentType, func(t *testing.T) {
			cfg := newRelayConfig(t, config.RelayConfig{Method: tc.method, URL: up.URL})
			cfg.MaxRequestBodyBytes = 50
			rec := doRelay(cfg, tc.method, "http://localhost:8000/", tc.contentType, big)
			if rec.Code != http.StatusRequestEntityTooLarge {
				t.Errorf("status = %d, want 413", rec.Code)
			}
		})
	}

	t.Run("body within the limit is relayed", func(t *testing.T) {
		cfg := newRelayConfig(t, config.RelayConfig{Method: "PUT", URL: up.URL})
		cfg.MaxRequestBodyBytes = 1000
		if rec := doRelay(cfg, "PUT", "http://localhost:8000/", "text/plain", big); rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
	})
}

func TestRelayHandlerClientCancel(t *testing.T) {
	upstreamDone := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(upstreamDone)
		select {
		case <-time.After(5 * time.Second):
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(up.Close)

	cfg := newRelayConfig(t, config.RelayConfig{Method: "GET", URL: up.URL})
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest("GET", "http://localhost:8000/", nil).WithContext(ctx)
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()
	relayHandler(httptest.NewRecorder(), req, cfg)

	select {
	case <-upstreamDone:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream request was not cancelled when the client went away")
	}
}

func TestServerGracefulShutdown(t *testing.T) {
	cfg := newRelayConfig(t, config.RelayConfig{URL: "https://example.com"})
	cfg.Host = "127.0.0.1"
	started := make(chan struct{})
	srv := newHTTPServer(cfg, cfg.Port, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		time.Sleep(300 * time.Millisecond)
		io.WriteString(w, "done")
	}))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)

	type result struct {
		body string
		err  error
	}
	res := make(chan result, 1)
	go func() {
		resp, err := http.Get("http://" + ln.Addr().String())
		if err != nil {
			res <- result{err: err}
			return
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		res <- result{string(b), err}
	}()

	<-started
	if err := srv.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if r := <-res; r.err != nil || r.body != "done" {
		t.Errorf("in-flight request got (%q, %v), want it to complete", r.body, r.err)
	}
}
