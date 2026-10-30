// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package relay

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"oauth2relay.com/oauth2relay/v2/config"
)

// switchableIdP issues tok-1, tok-2, ... with the given lifetime, or answers
// 503 while down is set.
type switchableIdP struct {
	*httptest.Server
	down   atomic.Bool
	issued atomic.Int32
}

func newSwitchableIdP(t *testing.T, expiresIn int) *switchableIdP {
	t.Helper()
	idp := &switchableIdP{}
	idp.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if idp.down.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		n := idp.issued.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"tok-%d","expires_in":%d}`, n, expiresIn)
	}))
	t.Cleanup(idp.Close)
	return idp
}

// tokenRelayConfig relays to upstream with the token from idp.
func tokenRelayConfig(t *testing.T, idp, upstream string) *config.Config {
	t.Helper()
	cfg := loginConfig(idp, 1)
	cfg.Token = config.TokenConfig{ExpiryBuffer: intPtr(0)}
	cfg.TokenWaitTimeout = 5
	cfg.Relay = config.RelayConfig{Method: "GET", URL: upstream,
		Headers: map[string]string{"Authorization": "Bearer ${ACCESSTOKEN}"}}
	if err := cfg.Relay.Validate(); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// recordingUpstream records the Authorization header of each request and
// waits delay before answering.
func recordingUpstream(t *testing.T, delay time.Duration) (*httptest.Server, *atomic.Value) {
	t.Helper()
	var lastAuth atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastAuth.Store(r.Header.Get("Authorization"))
		time.Sleep(delay)
	}))
	t.Cleanup(srv.Close)
	return srv, &lastAuth
}

func TestIdPDownWhileServing(t *testing.T) {
	idp := newSwitchableIdP(t, 1)
	upstream, lastAuth := recordingUpstream(t, 0)
	cfg := tokenRelayConfig(t, idp.URL, upstream.URL)
	s := testServer(t, cfg)

	if rec := doRelayOn(s, "GET", "/a", "", ""); rec.Code != http.StatusOK || lastAuth.Load() != "Bearer tok-1" {
		t.Fatalf("first request: %d, upstream saw %v", rec.Code, lastAuth.Load())
	}

	// The provider goes down and the token expires.
	idp.down.Store(true)
	time.Sleep(1100 * time.Millisecond)
	rec := doRelayOn(s, "GET", "/b", "", "")
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "token_unavailable") {
		t.Errorf("while the IdP is down: status %d body %s, want 503 token_unavailable", rec.Code, rec.Body)
	}
	if st := s.tokenStatus(); st.State != "renewal_failed" {
		t.Errorf("token state = %q, want renewal_failed", st.State)
	}

	// Once it recovers the next request gets a new token.
	idp.down.Store(false)
	if rec := doRelayOn(s, "GET", "/c", "", ""); rec.Code != http.StatusOK || lastAuth.Load() != "Bearer tok-2" {
		t.Errorf("after recovery: %d, upstream saw %v", rec.Code, lastAuth.Load())
	}
	if st := s.tokenStatus(); st.State != "valid" {
		t.Errorf("token state = %q, want valid", st.State)
	}
}

func TestIdPRejectsCredentialsWhileServing(t *testing.T) {
	idp, _ := newTokenEndpoint(t, [3]string{"401", "application/json", `{"error":"invalid_client"}`})
	upstream, _ := recordingUpstream(t, 0)
	cfg := tokenRelayConfig(t, idp.URL, upstream.URL)
	s := testServer(t, cfg)

	rec := doRelayOn(s, "GET", "/a", "", "")
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "token_error") {
		t.Errorf("status %d body %s, want 500 token_error for a permanent failure", rec.Code, rec.Body)
	}
}

func TestTokenExpiresMidRequest(t *testing.T) {
	idp := newSwitchableIdP(t, 1)
	upstream, lastAuth := recordingUpstream(t, 1200*time.Millisecond)
	cfg := tokenRelayConfig(t, idp.URL, upstream.URL)
	s := testServer(t, cfg)

	// The token expires while the upstream is still answering: the request
	// completes with the token it started with.
	if rec := doRelayOn(s, "GET", "/slow", "", ""); rec.Code != http.StatusOK || lastAuth.Load() != "Bearer tok-1" {
		t.Fatalf("slow request: %d, upstream saw %v", rec.Code, lastAuth.Load())
	}
	if tok := s.tokens.Current(); time.Now().Before(tok.ExpiresAt) {
		t.Fatalf("token should have expired during the request")
	}
	// The next request renews it.
	if rec := doRelayOn(s, "GET", "/next", "", ""); rec.Code != http.StatusOK || lastAuth.Load() != "Bearer tok-2" {
		t.Errorf("next request: %d, upstream saw %v", rec.Code, lastAuth.Load())
	}
}
