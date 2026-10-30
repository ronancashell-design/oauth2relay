// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package relay

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"oauth2relay.com/oauth2relay/v2/config"
)

func TestSecretRefresherSwapsConfig(t *testing.T) {
	idp, _ := newTokenEndpoint(t, [3]string{"200", "application/json", okTokenJSON})
	first := loginConfig(idp.URL, 1)
	first.APIKey = "first"

	var calls atomic.Int32
	rebuild := func(context.Context) (*config.Config, error) {
		switch calls.Add(1) {
		case 1:
			return nil, errors.New("vault unavailable")
		default:
			second := loginConfig(idp.URL, 1)
			second.APIKey = "second"
			second.Login.ClientSecret = "rotated"
			return second, nil
		}
	}
	s, err := New(first, Options{Rebuild: rebuild})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.runSecretRefresher(ctx, 50*time.Millisecond)
		close(done)
	}()
	defer func() {
		cancel()
		<-done
	}()

	waitFor(t, "the first re-fetch", time.Second, func() bool { return calls.Load() >= 1 })
	if calls.Load() == 1 && s.Config() != first {
		t.Error("a failed re-fetch replaced the configuration")
	}
	waitFor(t, "a successful re-fetch", time.Second, func() bool { return s.Config().APIKey == "second" })
	// The token manager uses the new login settings for its next renewal.
	if _, err := s.tokens.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareSecretsChecksLogin(t *testing.T) {
	cfg := &config.Config{Login: &config.LoginConfig{GrantType: "jwt", JWTAlgorithm: "RS256"}}
	if err := Prepare(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "invalid login configuration") {
		t.Errorf("Prepare error = %v, want an invalid login configuration", err)
	}
}

func TestConfigRebuilderPicksUpRotatedSecret(t *testing.T) {
	var password atomic.Value
	password.Store("first-password")
	vaultSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "vault-token" || r.URL.Path != "/v1/secret/data/relay" {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"errors":["permission denied"]}`))
			return
		}
		fmt.Fprintf(w, `{"data":{"data":{"api_key":%q},"metadata":{"version":1}}}`, password.Load())
	}))
	defer vaultSrv.Close()
	t.Setenv("VAULT_TOKEN", "vault-token")

	raw := []byte(fmt.Sprintf(`{
		"port": 8080,
		"apiKey": "${vault:relay:api_key}",
		"relay": {"url": "https://a.example", "fixedtoken": "t"},
		"secrets_refresh_interval": 60,
		"secrets_managers": {"vault": {"type": "hashicorp_vault", "address": %q}}
	}`, vaultSrv.URL))
	rebuild := Rebuilder(raw, nil)

	cfg, err := rebuild(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.APIKey != "first-password" {
		t.Fatalf("apiKey = %q", cfg.APIKey)
	}
	password.Store("rotated-password")
	next, err := rebuild(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if next.APIKey != "rotated-password" || cfg.APIKey != "first-password" {
		t.Errorf("after rotation: new apiKey %q, old apiKey %q", next.APIKey, cfg.APIKey)
	}

	t.Setenv("VAULT_TOKEN", "revoked")
	if _, err := rebuild(context.Background()); err == nil || !strings.Contains(err.Error(), "failed to resolve secrets") {
		t.Errorf("rebuild with a rejected Vault token: %v", err)
	}
}

func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
