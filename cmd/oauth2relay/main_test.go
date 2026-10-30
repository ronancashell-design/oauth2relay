// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"io"
	"log"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"oauth2relay.com/oauth2relay/v2/config"
)

// TestMain silences logging unless the tests run with -v.
func TestMain(m *testing.M) {
	flag.Parse()
	if !testing.Verbose() {
		slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
		log.SetOutput(io.Discard)
	}
	os.Exit(m.Run())
}

// baseConfigJSON is a minimal valid configuration.
const baseConfigJSON = `{
	"port": 8080,
	"login": {"url": "https://idp.example.com/token", "grant_type": "client_credentials", "client_id": "id", "client_secret": "secret"},
	"relay": {"url": "https://api.example.com"}
	%s
}`

func configWith(extra string) []byte {
	if extra != "" {
		extra = "," + extra
	}
	return []byte(strings.Replace(baseConfigJSON, "%s", extra, 1))
}

func TestParseArgs(t *testing.T) {
	tests := []struct {
		args    []string
		want    cliOptions
		wantErr string
	}{
		{nil, cliOptions{configFile: "config.json"}, ""},
		{[]string{"my.json"}, cliOptions{configFile: "my.json"}, ""},
		{[]string{"--config", "my.json", "--check-config"}, cliOptions{configFile: "my.json", checkConfig: true}, ""},
		{[]string{"my.json", "--check-config", "-log-level=debug"}, cliOptions{configFile: "my.json", checkConfig: true, logLevel: "debug"}, ""},
		{[]string{"--log-format", "json", "my.json"}, cliOptions{configFile: "my.json", logFormat: "json"}, ""},
		{[]string{"-v"}, cliOptions{configFile: "config.json", showVersion: true}, ""},
		{[]string{"--version"}, cliOptions{configFile: "config.json", showVersion: true}, ""},
		{[]string{"--help"}, cliOptions{showHelp: true}, ""},
		{[]string{"-h"}, cliOptions{showHelp: true}, ""},
		{[]string{"a.json", "b.json"}, cliOptions{}, "only one config file"},
		{[]string{"--config", "a.json", "b.json"}, cliOptions{}, "both as --config"},
		{[]string{"--bogus"}, cliOptions{}, "flag provided but not defined"},
	}
	for _, tt := range tests {
		got, err := parseArgs(tt.args, &bytes.Buffer{})
		if tt.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("parseArgs(%q) error = %v, want %q", tt.args, err, tt.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseArgs(%q): %v", tt.args, err)
			continue
		}
		if *got != tt.want {
			t.Errorf("parseArgs(%q) = %+v, want %+v", tt.args, *got, tt.want)
		}
	}
}

func TestCheckConfig(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, raw []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	tests := []struct {
		name, path string
		code       int
		stdout     string
		stderr     string
	}{
		{"valid", write("ok.json", configWith("")), 0, "configuration is valid", ""},
		{"deprecated", write("dep.json", []byte(`{"port": 8080, "relay": {"url": "https://a.example", "fixedtoken": "t", "type": "json"}}`)), 0, "configuration is valid", "relay.type is deprecated"},
		{"secrets", write("sec.json", configWith(`"secrets_managers": {"aws": {"type": "aws_secrets_manager", "region": "eu-west-1"}}`)), 0, "were not resolved", ""},
		{"env jwt key", write("env.json", []byte(`{"port": 8080, "login": {"url": "https://i.example", "grant_type": "jwt", "jwt_algorithm": "RS256", "jwt_private_key": "${env:O2R_UNSET_KEY}"}, "relay": {"url": "https://a.example"}}`)), 0, "were not resolved", ""},
		{"unknown field", write("bad.json", configWith(`"prot": 1`)), 1, "", `unknown field "prot"`},
		{"bad jwt key", write("jwt.json", []byte(`{"port": 8080, "login": {"url": "https://i.example", "grant_type": "jwt", "jwt_algorithm": "RS256", "jwt_private_key": "nope"}, "relay": {"url": "https://a.example"}}`)), 1, "", "invalid login configuration"},
		{"missing", filepath.Join(dir, "none.json"), 1, "", "failed to open config file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := checkConfig(&cliOptions{configFile: tt.path}, &stdout, &stderr)
			if code != tt.code || !strings.Contains(stdout.String(), tt.stdout) || !strings.Contains(stderr.String(), tt.stderr) {
				t.Errorf("checkConfig = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
			}
		})
	}
}

func TestCheckConfigTLSFiles(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	writeCert(t, certFile, keyFile, "relay")
	write := func(extra string) string {
		path := filepath.Join(dir, "config.json")
		os.WriteFile(path, configWith(extra), 0o600)
		return path
	}
	for extra, wantCode := range map[string]int{
		`"tls": {"cert_file": "` + certFile + `", "key_file": "` + keyFile + `"}`:                0,
		`"tls": {"cert_file": "` + certFile + `", "key_file": "` + certFile + `"}`:               1,
		`"tls": {"cert_file": "` + filepath.Join(dir, "x") + `", "key_file": "` + keyFile + `"}`: 1,
		`"ca_file": "` + certFile + `"`: 0,
		`"ca_file": "` + keyFile + `"`:  1,
	} {
		var stdout, stderr bytes.Buffer
		if code := checkConfig(&cliOptions{configFile: write(extra)}, &stdout, &stderr); code != wantCode {
			t.Errorf("%s: exit %d, want %d: %s", extra, code, wantCode, stderr.String())
		}
	}
}

// ---------------- Warnings ----------------

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

func TestParseConfigOverride(t *testing.T) {
	opts := &cliOptions{logLevel: "warn", logFormat: "json"}
	cfg, err := config.Parse(configWith(`"debug": true, "log_level": "debug"`), opts.apply)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LogLevel != "warn" || cfg.LogFormat != "json" || cfg.Debug {
		t.Errorf("override not applied: log_level=%q log_format=%q debug=%v", cfg.LogLevel, cfg.LogFormat, cfg.Debug)
	}
	opts = &cliOptions{logLevel: "loud"}
	if _, err := config.Parse(configWith(""), opts.apply); err == nil {
		t.Error("an invalid --log-level was accepted")
	}
}
