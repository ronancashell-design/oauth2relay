// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package egress

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestIsPublic(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "127.255.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254",
		"100.100.100.200", "0.0.0.0", "0.1.2.3", "192.0.0.170", "198.18.0.1", "224.0.0.1", "255.255.255.255",
		"::", "::1", "fe80::1", "fc00::1", "fd00:ec2::254", "ff02::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1",
		"64:ff9b::a00:1",
	}
	public := []string{"8.8.8.8", "93.184.216.34", "172.32.0.1", "2001:4860:4860::8888", "::ffff:8.8.8.8"}
	for _, s := range blocked {
		if IsPublic(netip.MustParseAddr(s)) {
			t.Errorf("%s counted as public", s)
		}
	}
	for _, s := range public {
		if !IsPublic(netip.MustParseAddr(s)) {
			t.Errorf("%s counted as non-public", s)
		}
	}
}

func TestGuardCheck(t *testing.T) {
	g := &Guard{Allowed: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("192.168.1.5/32")}}
	for addr, wantOK := range map[string]bool{
		"10.20.3.4": true, "192.168.1.5": true, "::ffff:10.20.3.4": true,
		"10.21.0.1": false, "192.168.1.6": false, "127.0.0.1": false, "8.8.8.8": true,
	} {
		err := g.Check(netip.MustParseAddr(addr))
		if (err == nil) != wantOK {
			t.Errorf("Check(%s) = %v, want allowed=%v", addr, err, wantOK)
		}
		if err != nil && !errors.Is(err, ErrBlocked) {
			t.Errorf("Check(%s) = %v, does not wrap ErrBlocked", addr, err)
		}
	}
	var zero Guard
	if zero.Check(netip.MustParseAddr("10.0.0.1")) == nil || zero.Check(netip.MustParseAddr("8.8.8.8")) != nil {
		t.Error("the zero Guard must allow public addresses only")
	}
}

func TestGuardCheckHost(t *testing.T) {
	ctx := t.Context()
	g := &Guard{}
	for _, host := range []string{"localhost", "127.0.0.1", "::1", "169.254.169.254"} {
		if err := g.CheckHost(ctx, host); !errors.Is(err, ErrBlocked) {
			t.Errorf("CheckHost(%q) = %v, want ErrBlocked", host, err)
		}
	}
	if err := g.CheckHost(ctx, "93.184.216.34"); err != nil {
		t.Errorf("CheckHost(public address) = %v", err)
	}
	if err := g.CheckHost(ctx, "name.invalid"); err == nil || errors.Is(err, ErrBlocked) {
		t.Errorf("CheckHost(unresolvable) = %v, want a lookup error", err)
	}
	for in, want := range map[string]string{"http://a.example": "a.example:80", "https://a.example": "a.example:443", "https://a.example:8443": "a.example:8443"} {
		u, _ := url.Parse(in)
		if got := hostPort(u); got != want {
			t.Errorf("hostPort(%s) = %s, want %s", in, got, want)
		}
	}
}

func TestNewTransportBlocksInternalAddresses(t *testing.T) {
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	_, port, _ := net.SplitHostPort(u.Host)
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.Proxy = nil

	client := &http.Client{Transport: NewTransport(base, &Guard{}), Timeout: 5 * time.Second}
	for _, target := range []string{upstream.URL, "http://localhost:" + port} {
		if resp, err := client.Get(target); err == nil {
			resp.Body.Close()
			t.Errorf("%s: connected to a loopback address", target)
		} else if !errors.Is(err, ErrBlocked) {
			t.Errorf("%s: %v, want ErrBlocked", target, err)
		}
	}
	if hits.Load() != 0 {
		t.Errorf("the upstream was reached %d times", hits.Load())
	}

	allowed := &Guard{Allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}
	client = &http.Client{Transport: NewTransport(base, allowed), Timeout: 5 * time.Second}
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatalf("loopback in Allowed: %v", err)
	}
	resp.Body.Close()
	if hits.Load() != 1 {
		t.Errorf("upstream hits = %d, want 1", hits.Load())
	}
}

func TestNewTransportThroughProxy(t *testing.T) {
	var proxied atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied.Add(1)
		w.Write([]byte("via proxy"))
	}))
	defer proxy.Close()
	proxyURL, _ := url.Parse(proxy.URL)

	base := http.DefaultTransport.(*http.Transport).Clone()
	base.Proxy = http.ProxyURL(proxyURL)
	client := &http.Client{Transport: NewTransport(base, &Guard{}), Timeout: 5 * time.Second}

	// The proxy itself is on loopback and must stay reachable.
	resp, err := client.Get("http://93.184.216.34/x")
	if err != nil {
		t.Fatalf("public target through a loopback proxy: %v", err)
	}
	resp.Body.Close()
	if proxied.Load() != 1 {
		t.Errorf("proxy requests = %d, want 1", proxied.Load())
	}
	// An internal target is refused before the proxy is asked.
	if resp, err := client.Get("http://169.254.169.254/latest/meta-data/"); err == nil {
		resp.Body.Close()
		t.Error("metadata address through a proxy was allowed")
	} else if !errors.Is(err, ErrBlocked) {
		t.Errorf("metadata address through a proxy: %v", err)
	}
	if proxied.Load() != 1 {
		t.Errorf("the proxy was asked for a blocked address")
	}
}

func TestMatchHost(t *testing.T) {
	allowed := []string{"Example.com", "*.Partner.io", "localhost:8443"}
	for host, want := range map[string]string{
		"example.com": "Example.com", "EXAMPLE.COM:443": "Example.com", "a.partner.io": "*.Partner.io",
		"partner.io": "", "evil-example.com": "", "localhost:8443": "localhost:8443", "localhost": "",
	} {
		u := &url.URL{Scheme: "https", Host: host}
		entry, ok := MatchHost(u, allowed)
		if entry != want || ok != (want != "") {
			t.Errorf("MatchHost(%q) = %q, %v, want %q", host, entry, ok, want)
		}
	}
}

// fuzzAllowedHosts covers exact, wildcard and host:port entries.
var fuzzAllowedHosts = []string{"example.com", "*.partner.io", "localhost:8443"}

func FuzzMatchHost(f *testing.F) {
	for _, seed := range []string{
		"example.com", "EXAMPLE.com", "example.com:443", "evil-example.com", "example.com.evil.net",
		"a.partner.io", "partner.io", "a.b.partner.io", "apartner.io", "localhost:8443", "localhost",
		"localhost:8444", "[::1]:8443", "example.com%00", "user@example.com",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, host string) {
		u, err := url.Parse("http://" + host + "/")
		if err != nil {
			return
		}
		entry, ok := MatchHost(u, fuzzAllowedHosts)
		if !ok {
			return
		}
		hostname, hostport := strings.ToLower(u.Hostname()), strings.ToLower(u.Host)
		switch entry {
		case "example.com":
			ok = hostname == "example.com"
		case "*.partner.io":
			ok = strings.HasSuffix(hostname, ".partner.io")
		case "localhost:8443":
			ok = hostport == "localhost:8443"
		default:
			ok = false
		}
		if !ok {
			t.Fatalf("host %q (hostname %q) matched %q", u.Host, hostname, entry)
		}
	})
}
