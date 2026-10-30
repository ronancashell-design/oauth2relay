// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package relay

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"oauth2relay.com/oauth2relay/v2/config"
)

// TestMain silences logging unless the tests run with -v.

func TestResolveTargetURL(t *testing.T) {
	single := &config.RelayConfig{Mode: config.RelayModeSingle}
	passthrough := &config.RelayConfig{Mode: config.RelayModePassthrough}
	parameter := &config.RelayConfig{Mode: config.RelayModeParameter, URLParam: "external_url",
		AllowedHosts: []string{"example.com", "*.partner.io", "localhost:8443"}}

	tests := []struct {
		name       string
		rc         *config.RelayConfig
		target     string
		found      bool
		path       string
		want       string
		wantStatus int
	}{
		{name: "single ignores path", rc: single, target: "https://example.com/api/get_statuses", found: true, path: "/my_profile", want: "https://example.com/api/get_statuses"},
		{name: "single root path", rc: single, target: "https://example.com/api/get_statuses", found: true, path: "/", want: "https://example.com/api/get_statuses"},
		{name: "passthrough appends path", rc: passthrough, target: "https://example.com/api", found: true, path: "/get_statuses", want: "https://example.com/api/get_statuses"},
		{name: "passthrough trailing slash", rc: passthrough, target: "https://example.com/api/", found: true, path: "/my_profile", want: "https://example.com/api/my_profile"},
		{name: "passthrough root path", rc: passthrough, target: "https://example.com/api", found: true, path: "/", want: "https://example.com/api"},
		{name: "parameter uses target", rc: parameter, target: "https://example.com/my_profile?id=7", found: true, path: "/ignored", want: "https://example.com/my_profile?id=7"},
		{name: "parameter host case insensitive", rc: parameter, target: "https://EXAMPLE.com/x", found: true, path: "/", want: "https://EXAMPLE.com/x"},
		{name: "parameter wildcard subdomain", rc: parameter, target: "https://api.partner.io/v1", found: true, path: "/", want: "https://api.partner.io/v1"},
		{name: "parameter host with port", rc: parameter, target: "https://localhost:8443/v1", found: true, path: "/", want: "https://localhost:8443/v1"},
		{name: "parameter drops fragment", rc: parameter, target: "https://example.com/a#frag", found: true, path: "/", want: "https://example.com/a"},
		{name: "parameter missing", rc: parameter, found: false, path: "/", wantStatus: http.StatusBadRequest},
		{name: "parameter empty", rc: parameter, target: "  ", found: true, path: "/", wantStatus: http.StatusBadRequest},
		{name: "parameter relative", rc: parameter, target: "/my_profile", found: true, path: "/", wantStatus: http.StatusBadRequest},
		{name: "parameter bad scheme", rc: parameter, target: "file:///etc/passwd", found: true, path: "/", wantStatus: http.StatusBadRequest},
		{name: "parameter userinfo", rc: parameter, target: "https://user:pw@example.com/", found: true, path: "/", wantStatus: http.StatusBadRequest},
		{name: "parameter host not allowed", rc: parameter, target: "https://evil.com/steal", found: true, path: "/", wantStatus: http.StatusForbidden},
		{name: "parameter suffix trick", rc: parameter, target: "https://example.com.evil.com/", found: true, path: "/", wantStatus: http.StatusForbidden},
		{name: "parameter wildcard excludes apex", rc: parameter, target: "https://partner.io/", found: true, path: "/", wantStatus: http.StatusForbidden},
		{name: "parameter wrong port", rc: parameter, target: "https://localhost:9000/", found: true, path: "/", wantStatus: http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, status, err := resolveTargetURL(tt.rc, tt.target, tt.found, tt.path)
			if tt.wantStatus != 0 {
				if err == nil || status != tt.wantStatus {
					t.Fatalf("got (%v, %d, %v), want status %d", got, status, err, tt.wantStatus)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.String() != tt.want {
				t.Errorf("got %q, want %q", got.String(), tt.want)
			}
		})
	}
}

// upstreamRequest records what the fake 3rd-party endpoint received.
type upstreamRequest struct {
	Path  string
	Query url.Values
	Body  string
	Auth  string
}

func newUpstream(t *testing.T) (*httptest.Server, *upstreamRequest) {
	t.Helper()
	got := &upstreamRequest{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		*got = upstreamRequest{Path: r.URL.Path, Query: r.URL.Query(), Body: string(body), Auth: r.Header.Get("Authorization")}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

func newRelayConfig(t *testing.T, rc config.RelayConfig) *config.Config {
	t.Helper()
	rc.FixedToken = "fixed-token"
	rc.Headers = map[string]string{"Authorization": "Bearer ${ACCESSTOKEN}"}
	if strings.EqualFold(rc.Mode, config.RelayModeParameter) && rc.AllowedNetworks == nil {
		// The test servers listen on loopback, which parameter mode blocks.
		rc.AllowedNetworks = []string{"127.0.0.0/8", "::1"}
	}
	cfg := &config.Config{Port: 8080, Relay: rc}
	if err := cfg.Check(); err != nil {
		t.Fatalf("Check: %v", err)
	}
	return cfg
}

func doRelay(cfg *config.Config, method, target, contentType, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	relayHandler(rec, req, cfg)
	return rec
}

// doRelayOn sends one request through s, which keeps its token between
// requests.
func doRelayOn(s *Server, method, target, contentType, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	s.relayHandler(rec, req)
	return rec
}

func TestRelayHandlerSingleMode(t *testing.T) {
	up, got := newUpstream(t)
	cfg := newRelayConfig(t, config.RelayConfig{Mode: "Single", Method: "GET", URL: up.URL + "/api/get_statuses"})

	rec := doRelay(cfg, "GET", "http://localhost:8000/my_profile?a=1", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
	}
	if got.Path != "/api/get_statuses" {
		t.Errorf("upstream path = %q, want /api/get_statuses", got.Path)
	}
	if got.Query.Get("a") != "1" {
		t.Errorf("upstream query = %v, want a=1", got.Query)
	}
	if got.Auth != "Bearer fixed-token" {
		t.Errorf("Authorization = %q", got.Auth)
	}
}

func TestRelayHandlerPassthroughMode(t *testing.T) {
	up, got := newUpstream(t)
	cfg := newRelayConfig(t, config.RelayConfig{Method: "GET", URL: up.URL + "/api"})

	for _, p := range []string{"/get_statuses", "/my_profile"} {
		rec := doRelay(cfg, "GET", "http://localhost:8000"+p, "", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
		}
		if got.Path != "/api"+p {
			t.Errorf("upstream path = %q, want %q", got.Path, "/api"+p)
		}
	}
}

func TestRelayHandlerParameterMode(t *testing.T) {
	up, got := newUpstream(t)
	upURL, _ := url.Parse(up.URL)
	external := up.URL + "/my_profile?id=7"

	t.Run("GET query parameter is stripped", func(t *testing.T) {
		cfg := newRelayConfig(t, config.RelayConfig{Mode: "parameter", Method: "GET", AllowedHosts: []string{upURL.Host}})
		rec := doRelay(cfg, "GET", "http://localhost:8000/ignored?a=1&external_url="+url.QueryEscape(external), "", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
		}
		if got.Path != "/my_profile" {
			t.Errorf("upstream path = %q, want /my_profile", got.Path)
		}
		if got.Query.Get("id") != "7" || got.Query.Get("a") != "1" {
			t.Errorf("upstream query = %v, want id=7 and a=1", got.Query)
		}
		if got.Query.Has("external_url") {
			t.Errorf("external_url leaked upstream: %v", got.Query)
		}
	})

	t.Run("custom param name lets external_url through", func(t *testing.T) {
		cfg := newRelayConfig(t, config.RelayConfig{Mode: "parameter", Method: "GET", URLParam: "relay_to", AllowedHosts: []string{upURL.Host}})
		rec := doRelay(cfg, "GET", "http://localhost:8000/?external_url=keep-me&relay_to="+url.QueryEscape(external), "", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
		}
		if got.Query.Get("external_url") != "keep-me" {
			t.Errorf("external_url = %q, want keep-me", got.Query.Get("external_url"))
		}
		if got.Query.Has("relay_to") {
			t.Errorf("relay_to leaked upstream: %v", got.Query)
		}
	})

	t.Run("POST form parameter is stripped", func(t *testing.T) {
		cfg := newRelayConfig(t, config.RelayConfig{Mode: "parameter", Method: "POST", AllowedHosts: []string{upURL.Host}})
		form := url.Values{"name": {"x"}, "external_url": {external}}.Encode()
		rec := doRelay(cfg, "POST", "http://localhost:8000/", "application/x-www-form-urlencoded", form)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
		}
		vals, _ := url.ParseQuery(got.Body)
		if got.Path != "/my_profile" || vals.Get("name") != "x" || vals.Has("external_url") {
			t.Errorf("upstream got path %q body %q", got.Path, got.Body)
		}
	})

	t.Run("POST JSON parameter is stripped", func(t *testing.T) {
		cfg := newRelayConfig(t, config.RelayConfig{Mode: "parameter", Method: "POST", AllowedHosts: []string{upURL.Host}})
		body, _ := json.Marshal(map[string]string{"name": "x", "external_url": external})
		rec := doRelay(cfg, "POST", "http://localhost:8000/", "application/json", string(body))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
		}
		var sent map[string]interface{}
		json.Unmarshal([]byte(got.Body), &sent)
		if _, leaked := sent["external_url"]; leaked || sent["name"] != "x" || got.Path != "/my_profile" {
			t.Errorf("upstream got path %q body %q", got.Path, got.Body)
		}
	})

	t.Run("missing parameter is 400", func(t *testing.T) {
		cfg := newRelayConfig(t, config.RelayConfig{Mode: "parameter", Method: "GET", AllowedHosts: []string{upURL.Host}})
		rec := doRelay(cfg, "GET", "http://localhost:8000/my_profile", "", "")
		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("disallowed host is 403", func(t *testing.T) {
		cfg := newRelayConfig(t, config.RelayConfig{Mode: "parameter", Method: "GET", AllowedHosts: []string{"example.com"}})
		rec := doRelay(cfg, "GET", "http://localhost:8000/?external_url="+url.QueryEscape(external), "", "")
		if rec.Code != http.StatusForbidden {
			t.Errorf("status = %d, want 403", rec.Code)
		}
	})
}

// fuzzAllowedHosts covers exact, wildcard and host:port entries.
var fuzzAllowedHosts = []string{"example.com", "*.partner.io", "localhost:8443"}

func FuzzResolveTargetURL(f *testing.F) {
	for _, seed := range []string{
		"https://example.com/api", "http://a.partner.io/x?y=1#frag", "https://localhost:8443/",
		"https://evil.com/", "https://example.com@evil.com/", "https://evil.com#@example.com",
		"//example.com/", "javascript:alert(1)", "https://example.com.evil.com/", "HTTPS://EXAMPLE.COM",
		"https://[::1]/", " https://example.com/ ", "https://example.com\\@evil.com/",
		"https://user:pass@example.com/", "http://example.com:99999/", "",
	} {
		f.Add(seed)
	}
	rc := &config.RelayConfig{Mode: config.RelayModeParameter, URLParam: "external_url", AllowedHosts: fuzzAllowedHosts}
	f.Fuzz(func(t *testing.T, target string) {
		u, status, err := resolveTargetURL(rc, target, true, "/ignored")
		if err != nil {
			if status != 400 && status != 403 {
				t.Fatalf("resolveTargetURL(%q) failed with status %d", target, status)
			}
			return
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			t.Fatalf("resolveTargetURL(%q) accepted scheme %q", target, u.Scheme)
		}
		if u.User != nil || u.Fragment != "" || u.Hostname() == "" {
			t.Fatalf("resolveTargetURL(%q) = %q has user info, a fragment or no host", target, u)
		}
		if !hostAllowed(u, rc.AllowedHosts) {
			t.Fatalf("resolveTargetURL(%q) accepted host %q", target, u.Host)
		}
		// What the transport will dial must be the host that was checked.
		reparsed, err := url.Parse(u.String())
		if err != nil || reparsed.Host != u.Host {
			t.Fatalf("resolveTargetURL(%q) = %q does not round-trip (host %q)", target, u, reparsed.Host)
		}
	})
}
