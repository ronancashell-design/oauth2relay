// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package relay

import (
	"context"
	"flag"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"

	"oauth2relay.com/oauth2relay/v2/config"
	"oauth2relay.com/oauth2relay/v2/token"
)

func TestMain(m *testing.M) {
	flag.Parse()
	if !testing.Verbose() {
		slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
		log.SetOutput(io.Discard)
	}
	os.Exit(m.Run())
}

// testServer returns an unstarted Server for cfg.
func testServer(t testing.TB, cfg *config.Config) *Server {
	t.Helper()
	s, err := New(cfg, Options{Rebuild: func(context.Context) (*config.Config, error) { return cfg, nil }})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// relayHandler serves one request with a new Server for cfg. It suits
// tests that use a fixed token or do not depend on token state.
func relayHandler(w http.ResponseWriter, r *http.Request, cfg *config.Config) {
	s, err := New(cfg, Options{Rebuild: func(context.Context) (*config.Config, error) { return cfg, nil }})
	if err != nil {
		panic(err)
	}
	s.relayHandler(w, r)
}

// staticTokens is a TokenSource that returns a fixed result.
type staticTokens struct {
	tok *token.Token
	err error
}

func (s staticTokens) Token(context.Context) (*token.Token, error) { return s.tok, s.err }

// routerFunc adapts a function to the Router interface.
type routerFunc func(*http.Request) (*Route, error)

func (f routerFunc) Route(r *http.Request) (*Route, error) { return f(r) }

// newTokenEndpoint returns an IdP that answers each request with the next
// (status, content type, body) in responses, repeating the last one.
func newTokenEndpoint(t *testing.T, responses ...[3]string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(calls.Add(1)) - 1
		if n >= len(responses) {
			n = len(responses) - 1
		}
		resp := responses[n]
		w.Header().Set("Content-Type", resp[1])
		status := map[string]int{"200": 200, "401": 401, "400": 400, "502": 502, "503": 503}[resp[0]]
		w.WriteHeader(status)
		w.Write([]byte(resp[2]))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func loginConfig(url string, attempts int) *config.Config {
	return &config.Config{Login: &config.LoginConfig{
		URL:           url,
		GrantType:     "client_credentials",
		ClientID:      "id",
		ClientSecret:  "secret",
		RetryAttempts: attempts,
		RetryInterval: 1,
		Parameters:    map[string]string{"AccessToken": "access_token", "ExpiresIn": "expires_in"},
	}}
}

func intPtr(n int) *int { return &n }

const okTokenJSON = `{"access_token":"tok-1","expires_in":3600}`
