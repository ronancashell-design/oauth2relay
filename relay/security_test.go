// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package relay

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"oauth2relay.com/oauth2relay/v2/config"
	"oauth2relay.com/oauth2relay/v2/egress"
)

func TestAddrGuardAllowedNetworks(t *testing.T) {
	rc := config.RelayConfig{Mode: config.RelayModeParameter, AllowedHosts: []string{"example.com"},
		AllowedNetworks: []string{"10.20.0.0/16", "192.168.1.5"}}
	if err := rc.Validate(); err != nil {
		t.Fatal(err)
	}
	g := &egress.Guard{Allowed: rc.AllowedNetworkPrefixes()}
	for addr, wantOK := range map[string]bool{
		"10.20.3.4": true, "192.168.1.5": true, "::ffff:10.20.3.4": true,
		"10.21.0.1": false, "192.168.1.6": false, "127.0.0.1": false, "8.8.8.8": true,
	} {
		if err := g.Check(netip.MustParseAddr(addr)); (err == nil) != wantOK {
			t.Errorf("check(%s) = %v, want allowed=%v", addr, err, wantOK)
		}
	}
}

func TestParameterModeBlocksInternalAddresses(t *testing.T) {
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	_, port, _ := net.SplitHostPort(u.Host)

	// allowed_hosts permits the name, but it resolves to loopback.
	for _, host := range []string{u.Host, "localhost:" + port} {
		cfg := newRelayConfig(t, config.RelayConfig{Mode: "parameter", Method: "GET", AllowedHosts: []string{host},
			AllowedNetworks: []string{}})
		rec := doRelay(cfg, "GET", "/?external_url="+url.QueryEscape("http://"+host+"/x"), "", "")
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "destination_blocked") {
			t.Errorf("%s: status %d body %s, want 403 destination_blocked", host, rec.Code, rec.Body)
		}
	}
	if hits.Load() != 0 {
		t.Errorf("the upstream was reached %d times", hits.Load())
	}

	// Other modes are not restricted: the operator chose the URL.
	cfg := newRelayConfig(t, config.RelayConfig{Method: "GET", URL: upstream.URL})
	if rec := doRelay(cfg, "GET", "/x", "", ""); rec.Code != http.StatusOK {
		t.Errorf("passthrough to loopback: status %d", rec.Code)
	}
}

func TestParameterModeRedirectToInternalBlocked(t *testing.T) {
	// The internal target listens on ::1; only 127.0.0.1 is allowed.
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	internal := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the redirect target was reached")
	}))
	internal.Listener.Close()
	internal.Listener = ln
	internal.Start()
	defer internal.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, internal.URL+"/secret", http.StatusFound)
	}))
	defer redirector.Close()
	ru, _ := url.Parse(redirector.URL)
	iu, _ := url.Parse(internal.URL)

	cfg := newRelayConfig(t, config.RelayConfig{Mode: "parameter", Method: "GET", FollowRedirects: true,
		AllowedHosts: []string{ru.Hostname(), iu.Hostname()}, AllowedNetworks: []string{"127.0.0.1"}})
	rec := doRelay(cfg, "GET", "/?external_url="+url.QueryEscape(redirector.URL+"/start"), "", "")
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "destination_blocked") {
		t.Errorf("status %d body %s, want 403 destination_blocked", rec.Code, rec.Body)
	}
}

// ---------------- TLS ----------------

// writeCert writes a self-signed certificate for 127.0.0.1 and its key as
// PEM files and returns the certificate.
func writeCert(t *testing.T, certFile, keyFile, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert
}

func TestCertReloader(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	writeCert(t, certFile, keyFile, "first")

	r, err := newCertReloader(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	subject := func() string {
		r.mu.Lock()
		r.checked = time.Time{} // skip the check interval
		r.mu.Unlock()
		c, _ := r.GetCertificate(nil)
		return c.Leaf.Subject.CommonName
	}
	if got := subject(); got != "first" {
		t.Fatalf("subject = %q", got)
	}

	// A renewed certificate is picked up.
	writeCert(t, certFile, keyFile, "second")
	later := time.Now().Add(time.Minute)
	os.Chtimes(certFile, later, later)
	os.Chtimes(keyFile, later, later)
	if got := subject(); got != "second" {
		t.Errorf("after renewal subject = %q, want second", got)
	}

	// A broken file keeps the current certificate.
	os.WriteFile(certFile, []byte("half written"), 0o600)
	evenLater := later.Add(time.Minute)
	os.Chtimes(certFile, evenLater, evenLater)
	if got := subject(); got != "second" {
		t.Errorf("after a broken write subject = %q, want second", got)
	}

	if _, err := newCertReloader(filepath.Join(dir, "missing.crt"), keyFile); err == nil {
		t.Error("a missing certificate file was accepted")
	}
}

func TestServerTLS(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	cert := writeCert(t, certFile, keyFile, "relay")

	tlsCfg, _, err := serverTLSConfig(&config.TLSConfig{CertFile: certFile, KeyFile: keyFile})
	if err != nil {
		t.Fatal(err)
	}
	// Serve as main does: an http.Server whose certificate comes only from
	// GetCertificate.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }),
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go srv.ServeTLS(ln, "", "")
	defer srv.Close()
	srvURL := "https://" + ln.Addr().String()

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	get := func(maxVersion uint16) error {
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MaxVersion: maxVersion}}}
		resp, err := client.Get(srvURL)
		if err == nil {
			resp.Body.Close()
		}
		return err
	}
	if err := get(0); err != nil {
		t.Errorf("TLS request: %v", err)
	}
	if err := get(tls.VersionTLS11); err == nil {
		t.Error("a TLS 1.1 client was accepted")
	}
}

func TestOutboundCAFile(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("trusted"))
	}))
	defer upstream.Close()

	s := testServer(t, newRelayConfig(t, config.RelayConfig{URL: upstream.URL}))
	client := &http.Client{Transport: s.transport, Timeout: 5 * time.Second}
	if resp, err := client.Get(upstream.URL); err == nil {
		resp.Body.Close()
		t.Fatal("the test server's certificate was trusted without ca_file")
	}

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw}), 0o600)
	if err := s.configureOutboundTLS(&config.Config{CAFile: caFile}); err != nil {
		t.Fatal(err)
	}
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatalf("with ca_file: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "trusted" {
		t.Errorf("body = %q", body)
	}

	os.WriteFile(caFile, []byte("not a certificate"), 0o600)
	if err := s.configureOutboundTLS(&config.Config{CAFile: caFile}); err == nil || !strings.Contains(err.Error(), "no PEM certificates") {
		t.Errorf("invalid ca_file: %v", err)
	}
}
