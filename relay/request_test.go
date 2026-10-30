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

func TestClientIP(t *testing.T) {
	cfg := newRelayConfig(t, config.RelayConfig{URL: "https://example.com"})
	cfg.TrustedProxies = []string{"10.0.0.0/8", "192.168.1.5", "fd00::/8"}
	if err := cfg.Check(); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, remote, xff, want string
	}{
		{"no proxy", "203.0.113.7:5000", "", "203.0.113.7"},
		{"untrusted peer ignores XFF", "203.0.113.7:5000", "1.2.3.4", "203.0.113.7"},
		{"trusted peer uses XFF", "10.1.2.3:5000", "198.51.100.9", "198.51.100.9"},
		{"skips trusted hops from the right", "10.1.2.3:5000", "198.51.100.9, 192.168.1.5, 10.9.9.9", "198.51.100.9"},
		{"forged left entries ignored", "10.1.2.3:5000", "6.6.6.6, 198.51.100.9", "198.51.100.9"},
		{"all hops trusted gives leftmost", "10.1.2.3:5000", "10.5.5.5, 10.6.6.6", "10.5.5.5"},
		{"malformed entry stops the chain", "10.1.2.3:5000", "198.51.100.9, not-an-ip", "10.1.2.3"},
		{"trusted peer without XFF", "10.1.2.3:5000", "", "10.1.2.3"},
		{"IPv6 proxy", "[fd00::1]:5000", "2001:db8::42", "2001:db8::42"},
		{"IPv4-mapped peer", "[::ffff:10.1.2.3]:5000", "198.51.100.9", "198.51.100.9"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tt.remote
			if tt.xff != "" {
				r.Header.Set("X-Forwarded-For", tt.xff)
			}
			if got := clientIP(r, cfg.TrustedNetworks()); got != tt.want {
				t.Errorf("clientIP = %q, want %q", got, tt.want)
			}
		})
	}

	t.Run("multiple XFF headers", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "10.1.2.3:5000"
		r.Header.Add("X-Forwarded-For", "198.51.100.9")
		r.Header.Add("X-Forwarded-For", "10.7.7.7")
		if got := clientIP(r, cfg.TrustedNetworks()); got != "198.51.100.9" {
			t.Errorf("clientIP = %q, want 198.51.100.9", got)
		}
	})
}

func TestIPSubstitutionBehindProxy(t *testing.T) {
	up, got := newUpstream(t)
	cfg := newRelayConfig(t, config.RelayConfig{Method: "GET", URL: up.URL, Parameters: map[string]string{"ipaddr": "${IP}"}})
	cfg.TrustedProxies = []string{"192.0.2.0/24"}
	if err := cfg.Check(); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "http://localhost:8000/", nil) // RemoteAddr 192.0.2.1
	req.Header.Set("X-Forwarded-For", "198.51.100.9")
	relayHandler(httptest.NewRecorder(), req, cfg)
	if ip := got.Query.Get("ipaddr"); ip != "198.51.100.9" {
		t.Errorf("ipaddr = %q, want the client behind the proxy", ip)
	}
}

func TestRelayMethod(t *testing.T) {
	tests := []struct{ configured, incoming, want string }{
		{"", "DELETE", "GET"},
		{"post", "GET", "POST"},
		{"inherit", "delete", "DELETE"},
		{"INHERIT", "PATCH", "PATCH"},
	}
	for _, tt := range tests {
		if got := relayMethod(tt.configured, tt.incoming); got != tt.want {
			t.Errorf("relayMethod(%q, %q) = %q, want %q", tt.configured, tt.incoming, got, tt.want)
		}
	}
	rc := config.RelayConfig{URL: "https://example.com", Method: "GE T"}
	if err := rc.Validate(); err == nil {
		t.Error("invalid method accepted")
	}
}

// methodUpstream records the method, query, body and content type it received.
type methodRequest struct {
	Method, Body, ContentType string
	Query                     url.Values
	ContentLength             int64
	Chunked                   bool
}

func newMethodUpstream(t *testing.T) (*httptest.Server, *methodRequest) {
	t.Helper()
	got := &methodRequest{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		*got = methodRequest{Method: r.Method, Body: string(body), ContentType: r.Header.Get("Content-Type"),
			Query: r.URL.Query(), ContentLength: r.ContentLength,
			Chunked: len(r.TransferEncoding) > 0 && r.TransferEncoding[0] == "chunked"}
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

func TestInheritMethod(t *testing.T) {
	up, got := newMethodUpstream(t)
	cfg := newRelayConfig(t, config.RelayConfig{Method: "inherit", URL: up.URL})

	for _, m := range []string{"GET", "DELETE", "PUT", "PATCH", "POST"} {
		doRelay(cfg, m, "http://localhost:8000/users/5", "", "")
		if got.Method != m {
			t.Errorf("incoming %s relayed as %s", m, got.Method)
		}
	}
}

func TestPutPatchMergeParameters(t *testing.T) {
	up, got := newMethodUpstream(t)
	for _, m := range []string{"PUT", "PATCH"} {
		t.Run(m+" JSON", func(t *testing.T) {
			cfg := newRelayConfig(t, config.RelayConfig{Method: m, URL: up.URL, Parameters: map[string]string{"source": "relay"}})
			doRelay(cfg, m, "http://localhost:8000/?q=1", "application/json", `{"name":"x"}`)
			var sent map[string]interface{}
			json.Unmarshal([]byte(got.Body), &sent)
			if sent["name"] != "x" || sent["source"] != "relay" || sent["q"] != "1" {
				t.Errorf("JSON body = %s, want name, source and q merged", got.Body)
			}
		})
		t.Run(m+" form", func(t *testing.T) {
			cfg := newRelayConfig(t, config.RelayConfig{Method: m, URL: up.URL, Parameters: map[string]string{"source": "relay"}})
			doRelay(cfg, m, "http://localhost:8000/", "application/x-www-form-urlencoded", "name=x")
			vals, _ := url.ParseQuery(got.Body)
			if vals.Get("name") != "x" || vals.Get("source") != "relay" {
				t.Errorf("form body = %q, want name and source merged", got.Body)
			}
		})
	}
}

func TestRawBodyStreamedWithQueryAndContentType(t *testing.T) {
	up, got := newMethodUpstream(t)
	cfg := newRelayConfig(t, config.RelayConfig{Method: "inherit", URL: up.URL, Parameters: map[string]string{"source": "relay"}})

	body := strings.Repeat("<xml/>", 1000)
	rec := doRelay(cfg, "PUT", "http://localhost:8000/doc?version=3", "application/xml", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
	}
	if got.Body != body {
		t.Errorf("body not relayed intact (%d bytes, want %d)", len(got.Body), len(body))
	}
	if got.ContentType != "application/xml" {
		t.Errorf("Content-Type = %q, want application/xml", got.ContentType)
	}
	if got.ContentLength != int64(len(body)) {
		t.Errorf("Content-Length = %d, want %d", got.ContentLength, len(body))
	}
	if got.Query.Get("version") != "3" || got.Query.Get("source") != "relay" {
		t.Errorf("query = %v, want version=3 and source=relay", got.Query)
	}
}

func TestRawBodyUnknownLengthIsChunked(t *testing.T) {
	up, got := newMethodUpstream(t)
	cfg := newRelayConfig(t, config.RelayConfig{Method: "POST", URL: up.URL})

	req := httptest.NewRequest("POST", "http://localhost:8000/", io.NopCloser(strings.NewReader("stream-me")))
	req.ContentLength = -1
	req.Header.Set("Content-Type", "text/plain")
	relayHandler(httptest.NewRecorder(), req, cfg)
	if got.Body != "stream-me" || !got.Chunked {
		t.Errorf("got body %q chunked=%v, want stream-me sent chunked", got.Body, got.Chunked)
	}
}

func TestConfiguredDataWins(t *testing.T) {
	up, got := newMethodUpstream(t)
	cfg := newRelayConfig(t, config.RelayConfig{Method: "DELETE", URL: up.URL, Data: "ip=${IP}"})
	doRelay(cfg, "DELETE", "http://localhost:8000/", "text/plain", "ignored")
	if got.Body != "ip=192.0.2.1" {
		t.Errorf("body = %q, want the substituted relay.data", got.Body)
	}
}
