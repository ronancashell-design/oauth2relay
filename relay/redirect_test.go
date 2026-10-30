// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package relay

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"oauth2relay.com/oauth2relay/v2/config"
)

// newRedirectTarget returns a server that counts its hits and records the
// X-Token header it received.
func newRedirectTarget(t *testing.T) (*httptest.Server, *atomic.Int32, *atomic.Value) {
	t.Helper()
	var hits atomic.Int32
	var gotToken atomic.Value
	gotToken.Store("")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		gotToken.Store(r.Header.Get("X-Token"))
		w.Write([]byte("target"))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits, &gotToken
}

// newRedirector returns a server that redirects /redirect to location and
// answers every other path itself.
func newRedirector(t *testing.T, location func() string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, location(), http.StatusFound)
			return
		}
		w.Write([]byte("redirector:" + r.URL.Path))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func redirectConfig(t *testing.T, rc config.RelayConfig) *config.Config {
	cfg := newRelayConfig(t, rc)
	cfg.Relay.Headers["X-Token"] = "${ACCESSTOKEN}"
	return cfg
}

func TestRedirectNotFollowedByDefault(t *testing.T) {
	target, hits, _ := newRedirectTarget(t)
	redir := newRedirector(t, func() string { return target.URL + "/x" })

	cfg := redirectConfig(t, config.RelayConfig{Method: "GET", URL: redir.URL})
	rec := doRelay(cfg, "GET", "http://localhost:8000/redirect", "", "")
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 passed back to the caller", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != target.URL+"/x" {
		t.Errorf("Location = %q, want %q", loc, target.URL+"/x")
	}
	if hits.Load() != 0 {
		t.Errorf("redirect target was contacted %d times", hits.Load())
	}
}

func TestRedirectFollowedSameHost(t *testing.T) {
	var redir *httptest.Server
	redir = newRedirector(t, func() string { return redir.URL + "/landed" })

	cfg := redirectConfig(t, config.RelayConfig{Method: "GET", URL: redir.URL, FollowRedirects: true})
	rec := doRelay(cfg, "GET", "http://localhost:8000/redirect", "", "")
	if rec.Code != http.StatusOK || rec.Body.String() != "redirector:/landed" {
		t.Errorf("got %d %q, want the redirect followed on the same host", rec.Code, rec.Body)
	}
}

func TestRedirectFollowedCrossHostBlocked(t *testing.T) {
	target, hits, gotToken := newRedirectTarget(t)
	redir := newRedirector(t, func() string { return target.URL + "/steal" })

	cfg := redirectConfig(t, config.RelayConfig{Method: "GET", URL: redir.URL, FollowRedirects: true})
	rec := doRelay(cfg, "GET", "http://localhost:8000/redirect", "", "")
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
	if hits.Load() != 0 || gotToken.Load() != "" {
		t.Errorf("token sent to another host: hits=%d X-Token=%q", hits.Load(), gotToken.Load())
	}
}

func TestRedirectParameterMode(t *testing.T) {
	allowedTarget, allowedHits, _ := newRedirectTarget(t)
	otherTarget, otherHits, otherToken := newRedirectTarget(t)
	var location string
	redir := newRedirector(t, func() string { return location })

	host := func(s *httptest.Server) string { u, _ := url.Parse(s.URL); return u.Host }
	external := url.QueryEscape(redir.URL + "/redirect")

	t.Run("not followed by default", func(t *testing.T) {
		location = otherTarget.URL
		cfg := redirectConfig(t, config.RelayConfig{Mode: "parameter", Method: "GET",
			AllowedHosts: []string{host(redir), host(allowedTarget)}})
		rec := doRelay(cfg, "GET", "http://localhost:8000/?external_url="+external, "", "")
		if rec.Code != http.StatusFound || otherHits.Load() != 0 {
			t.Errorf("status = %d, other hits = %d; want 302 and no hits", rec.Code, otherHits.Load())
		}
	})

	t.Run("followed to allowed host", func(t *testing.T) {
		location = allowedTarget.URL + "/ok"
		cfg := redirectConfig(t, config.RelayConfig{Mode: "parameter", Method: "GET", FollowRedirects: true,
			AllowedHosts: []string{host(redir), host(allowedTarget)}})
		rec := doRelay(cfg, "GET", "http://localhost:8000/?external_url="+external, "", "")
		if rec.Code != http.StatusOK || allowedHits.Load() != 1 {
			t.Errorf("status = %d, allowed hits = %d; want 200 and 1 hit", rec.Code, allowedHits.Load())
		}
	})

	t.Run("blocked to host not in allowed_hosts", func(t *testing.T) {
		location = otherTarget.URL + "/steal"
		cfg := redirectConfig(t, config.RelayConfig{Mode: "parameter", Method: "GET", FollowRedirects: true,
			AllowedHosts: []string{host(redir), host(allowedTarget)}})
		rec := doRelay(cfg, "GET", "http://localhost:8000/?external_url="+external, "", "")
		if rec.Code != http.StatusBadGateway {
			t.Errorf("status = %d, want 502", rec.Code)
		}
		if otherHits.Load() != 0 || otherToken.Load() != "" {
			t.Errorf("token sent to a host that is not allowed: hits=%d X-Token=%q", otherHits.Load(), otherToken.Load())
		}
	})
}

func TestRelayRedirectPolicy(t *testing.T) {
	mustReq := func(raw string) *http.Request {
		r, _ := http.NewRequest("GET", raw, nil)
		return r
	}
	rc := &config.RelayConfig{Mode: config.RelayModePassthrough}
	https := []*http.Request{mustReq("https://api.example.com/a")}

	if err := relayRedirectPolicy(rc, mustReq("http://api.example.com/b"), https); err == nil {
		t.Error("https to http downgrade was allowed")
	}
	if err := relayRedirectPolicy(rc, mustReq("ftp://api.example.com/b"), https); err == nil {
		t.Error("non-http scheme was allowed")
	}
	if err := relayRedirectPolicy(rc, mustReq("https://API.example.com/b"), https); err != nil {
		t.Errorf("same host (different case) rejected: %v", err)
	}
	many := make([]*http.Request, maxRelayRedirects+1)
	for i := range many {
		many[i] = https[0]
	}
	if err := relayRedirectPolicy(rc, mustReq("https://api.example.com/b"), many); err == nil {
		t.Error("redirect limit not enforced")
	}
}
