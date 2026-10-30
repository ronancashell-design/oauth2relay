// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package relay

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"oauth2relay.com/oauth2relay/v2/config"
)

// TLS.
//
// The relay port serves HTTPS when tls.cert_file and tls.key_file are set.
// The certificate is reloaded when either file changes, so certificates
// renewed by cert-manager or a similar tool are picked up without a
// restart. The admin port always serves plain HTTP.
//
// ca_file adds CA certificates to the system ones for outbound connections
// to the token endpoint and the relay targets.

// certCheckInterval is how often the certificate files are checked for
// changes, at most.
const certCheckInterval = 10 * time.Second

// certReloader holds the server certificate and reloads it when its files
// change.
type certReloader struct {
	certFile, keyFile string

	mu              sync.Mutex
	cert            *tls.Certificate
	certMod, keyMod time.Time
	checked         time.Time
}

func newCertReloader(certFile, keyFile string) (*certReloader, error) {
	r := &certReloader{certFile: certFile, keyFile: keyFile}
	if err := r.reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// reload loads the certificate if either file changed since the last load.
// Callers hold r.mu, except in newCertReloader.
func (r *certReloader) reload() error {
	certInfo, err := os.Stat(r.certFile)
	if err != nil {
		return fmt.Errorf("tls.cert_file: %w", err)
	}
	keyInfo, err := os.Stat(r.keyFile)
	if err != nil {
		return fmt.Errorf("tls.key_file: %w", err)
	}
	if r.cert != nil && certInfo.ModTime().Equal(r.certMod) && keyInfo.ModTime().Equal(r.keyMod) {
		return nil
	}
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return fmt.Errorf("loading the TLS certificate: %w", err)
	}
	r.cert, r.certMod, r.keyMod = &cert, certInfo.ModTime(), keyInfo.ModTime()
	slog.Info("TLS certificate loaded", "cert_file", r.certFile, "subject", cert.Leaf.Subject.String(),
		"not_after", cert.Leaf.NotAfter.Format(time.RFC3339))
	return nil
}

// GetCertificate implements tls.Config.GetCertificate. If a changed
// certificate cannot be loaded, for example because it is half written, the
// previous one stays in use and the load is retried at the next check.
func (r *certReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Since(r.checked) >= certCheckInterval {
		r.checked = time.Now()
		if err := r.reload(); err != nil {
			slog.Warn("Could not reload the TLS certificate; keeping the current one", "error", err)
		}
	}
	return r.cert, nil
}

// notAfter returns when the current certificate expires.
func (r *certReloader) notAfter() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cert.Leaf.NotAfter
}

// serverTLSConfig returns the relay port's TLS configuration.
func serverTLSConfig(tc *config.TLSConfig) (*tls.Config, *certReloader, error) {
	minVersion, err := tc.MinTLSVersion()
	if err != nil {
		return nil, nil, err
	}
	reloader, err := newCertReloader(tc.CertFile, tc.KeyFile)
	if err != nil {
		return nil, nil, err
	}
	return &tls.Config{MinVersion: minVersion, GetCertificate: reloader.GetCertificate}, reloader, nil
}

// loadCAFile returns the system CA pool with the certificates in caFile
// added.
func loadCAFile(caFile string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(caFile) //nolint:gosec // G304: the path comes from the config
	if err != nil {
		return nil, fmt.Errorf("ca_file: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("ca_file %s holds no PEM certificates", caFile)
	}
	return pool, nil
}

// configureOutboundTLS applies ca_file to the server's outbound transport.
// It must run before the first outbound request.
func (s *Server) configureOutboundTLS(cfg *config.Config) error {
	if cfg.CAFile == "" {
		return nil
	}
	pool, err := loadCAFile(cfg.CAFile)
	if err != nil {
		return err
	}
	s.transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return nil
}

// CheckTLSFiles loads the files named by tls and ca_file, for
// --check-config.
func CheckTLSFiles(cfg *config.Config) error {
	if cfg.TLS.Enabled() {
		if _, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile); err != nil {
			return fmt.Errorf("loading the TLS certificate: %w", err)
		}
	}
	if cfg.CAFile != "" {
		if _, err := loadCAFile(cfg.CAFile); err != nil {
			return err
		}
	}
	return nil
}
