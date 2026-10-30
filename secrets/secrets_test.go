// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"oauth2relay.com/oauth2relay/v2/config"
	"oauth2relay.com/oauth2relay/v2/redact"
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

// fakeSecrets is an in-memory SecretManager that counts fetches.
type fakeSecrets struct {
	values map[string]string
	calls  map[string]int
}

func (f *fakeSecrets) GetSecret(_ context.Context, name string) (string, error) {
	f.calls[name]++
	v, ok := f.values[name]
	if !ok {
		return "", errors.New("secret " + name + " not found")
	}
	return v, nil
}

func newResolver(values map[string]string) (*secretResolver, *fakeSecrets) {
	f := &fakeSecrets{values: values, calls: map[string]int{}}
	return &secretResolver{ctx: context.Background(), managers: map[string]SecretManager{"vault": f}, cache: map[string]string{}}, f
}

func TestResolveStringPlaceholders(t *testing.T) {
	r, _ := newResolver(map[string]string{
		"app":   `{"user":"alice","pass":"s3cret","port":5432,"tls":true}`,
		"plain": "raw-value",
	})
	tests := []struct{ in, want string }{
		{"${vault:plain}", "raw-value"},
		{"Bearer ${vault:plain}", "Bearer raw-value"},
		{"${vault:app:user}:${vault:app:pass}", "alice:s3cret"},
		{"port=${vault:app:port} tls=${vault:app:tls}", "port=5432 tls=true"},
		{"${ACCESSTOKEN}", "${ACCESSTOKEN}"},
		{"${other:thing}", "${other:thing}"},
		{"no placeholders", "no placeholders"},
	}
	for _, tt := range tests {
		got, err := r.resolveString(tt.in)
		if err != nil {
			t.Errorf("resolveString(%q) error: %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("resolveString(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestResolveStringErrors(t *testing.T) {
	r, _ := newResolver(map[string]string{"app": `{"user":"alice"}`, "plain": "not json"})
	for _, in := range []string{"${vault:missing}", "${vault:app:nokey}", "${vault:plain:key}"} {
		if _, err := r.resolveString(in); err == nil {
			t.Errorf("resolveString(%q) succeeded, want an error", in)
		}
	}
}

func TestResolveConfigWalksMapsSlicesAndClaims(t *testing.T) {
	r, f := newResolver(map[string]string{"app": `{"id":"cid","secret":"csecret","host":"api.example.com","tenant":"acme"}`})
	cfg := &config.Config{
		Login: &config.LoginConfig{
			ClientSecret: "${vault:app:secret}",
			Headers:      map[string]string{"Authorization": "Basic ${vault:app:id}:${vault:app:secret}"},
			JWTClaims: map[string]interface{}{
				"tenant": "${vault:app:tenant}",
				"nested": map[string]interface{}{"host": "${vault:app:host}"},
				"list":   []interface{}{"${vault:app:id}", 7.0},
			},
		},
		Relay: config.RelayConfig{
			AllowedHosts: []string{"${vault:app:host}"},
			Parameters:   map[string]string{"client": "${vault:app:id}", "ip": "${IP}"},
		},
	}
	if err := r.resolveValue(reflect.ValueOf(cfg).Elem()); err != nil {
		t.Fatalf("resolveValue: %v", err)
	}

	checks := map[string][2]string{
		"login.client_secret":         {cfg.Login.ClientSecret, "csecret"},
		"login.headers.Authorization": {cfg.Login.Headers["Authorization"], "Basic cid:csecret"},
		"relay.allowed_hosts[0]":      {cfg.Relay.AllowedHosts[0], "api.example.com"},
		"relay.parameters.client":     {cfg.Relay.Parameters["client"], "cid"},
		"relay.parameters.ip":         {cfg.Relay.Parameters["ip"], "${IP}"},
	}
	for name, c := range checks {
		if c[0] != c[1] {
			t.Errorf("%s = %q, want %q", name, c[0], c[1])
		}
	}
	claims, _ := json.Marshal(cfg.Login.JWTClaims)
	if want := `{"list":["cid",7],"nested":{"host":"api.example.com"},"tenant":"acme"}`; string(claims) != want {
		t.Errorf("jwt_claims = %s, want %s", claims, want)
	}
	if f.calls["app"] != 1 {
		t.Errorf("secret fetched %d times, want 1 (cached)", f.calls["app"])
	}
}

// newFakeVault serves KV v2 at mount "secret", KV v1 at mount "kv1" and a
// Kubernetes login. Reads require wantToken and wantNamespace (if set).
func newFakeVault(t *testing.T, wantToken, wantNamespace string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/kubernetes/login" {
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			if body["role"] != "relay" || body["jwt"] != "sa-jwt" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.Write([]byte(`{"auth":{"client_token":"k8s-token"}}`))
			return
		}
		if r.Header.Get("X-Vault-Token") != wantToken || r.Header.Get("X-Vault-Namespace") != wantNamespace {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"errors":["permission denied"]}`))
			return
		}
		switch r.URL.Path {
		case "/v1/secret/data/app":
			w.Write([]byte(`{"data":{"data":{"password":"v2pass"},"metadata":{"version":1}}}`))
		case "/v1/kv1/app":
			w.Write([]byte(`{"data":{"password":"v1pass"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"errors":[]}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func getVaultPassword(t *testing.T, vc *config.VaultConfig) string {
	t.Helper()
	sm, err := NewVaultSecretManager(vc)
	if err != nil {
		t.Fatalf("NewVaultSecretManager: %v", err)
	}
	raw, err := sm.GetSecret(context.Background(), "app")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	var data map[string]string
	json.Unmarshal([]byte(raw), &data)
	return data["password"]
}

func TestVaultSecretManager(t *testing.T) {
	t.Run("KV v2 with token auth and namespace", func(t *testing.T) {
		srv := newFakeVault(t, "env-token", "team-a")
		t.Setenv("MY_VAULT_TOKEN", "env-token")
		got := getVaultPassword(t, &config.VaultConfig{Address: srv.URL, Namespace: "team-a",
			Auth: &config.VaultAuthConfig{Type: "token", TokenEnv: "MY_VAULT_TOKEN"}})
		if got != "v2pass" {
			t.Errorf("password = %q, want v2pass", got)
		}
	})

	t.Run("KV v1 at a custom mount", func(t *testing.T) {
		srv := newFakeVault(t, "env-token", "")
		t.Setenv("VAULT_TOKEN", "env-token")
		got := getVaultPassword(t, &config.VaultConfig{Address: srv.URL, Mount: "/kv1/", KVVersion: 1,
			Auth: &config.VaultAuthConfig{Type: "token"}})
		if got != "v1pass" {
			t.Errorf("password = %q, want v1pass", got)
		}
	})

	t.Run("kubernetes auth", func(t *testing.T) {
		srv := newFakeVault(t, "k8s-token", "")
		jwtFile := filepath.Join(t.TempDir(), "token")
		os.WriteFile(jwtFile, []byte("sa-jwt\n"), 0600)
		got := getVaultPassword(t, &config.VaultConfig{Address: srv.URL,
			Auth: &config.VaultAuthConfig{Type: "kubernetes", Role: "relay", TokenPath: jwtFile}})
		if got != "v2pass" {
			t.Errorf("password = %q, want v2pass", got)
		}
	})

	t.Run("token auth with unset variable", func(t *testing.T) {
		t.Setenv("MISSING_TOKEN", "")
		_, err := NewVaultSecretManager(&config.VaultConfig{Address: "http://127.0.0.1:1",
			Auth: &config.VaultAuthConfig{Type: "token", TokenEnv: "MISSING_TOKEN"}})
		if err == nil || !strings.Contains(err.Error(), "MISSING_TOKEN") {
			t.Errorf("error = %v, want one naming MISSING_TOKEN", err)
		}
	})
}

func TestAzureCredentialSelection(t *testing.T) {
	t.Setenv("AZ_SECRET", "s")
	cred, err := azureCredential(&config.AzureConfig{TenantID: "00000000-0000-0000-0000-000000000000", ClientID: "c", ClientSecretEnv: "AZ_SECRET"})
	if _, ok := cred.(*azidentity.ClientSecretCredential); err != nil || !ok {
		t.Errorf("service principal: got %T, %v", cred, err)
	}

	cred, err = azureCredential(&config.AzureConfig{ClientID: "c"})
	if _, ok := cred.(*azidentity.ManagedIdentityCredential); err != nil || !ok {
		t.Errorf("managed identity: got %T, %v", cred, err)
	}

	t.Setenv("AZ_EMPTY", "")
	if _, err := azureCredential(&config.AzureConfig{TenantID: "t", ClientID: "c", ClientSecretEnv: "AZ_EMPTY"}); err == nil {
		t.Error("expected an error when the client secret variable is empty")
	}
}

func TestEnvPlaceholders(t *testing.T) {
	t.Setenv("O2R_TEST_SECRET", "env-secret-value-1234")
	t.Setenv("O2R_TEST_JSON", `{"user":"alice","port":5432}`)
	t.Setenv("O2R_TEST_EMPTY", "")
	cfg := &config.Config{
		Login: &config.LoginConfig{
			ClientSecret: "${env:O2R_TEST_SECRET}",
			Headers:      map[string]string{"Authorization": "Basic ${env:O2R_TEST_JSON:user}:${env:O2R_TEST_SECRET}"},
		},
		Relay: config.RelayConfig{URL: "https://api.example/${env:O2R_TEST_EMPTY}x", FixedToken: "${ACCESSTOKEN}"},
	}
	if err := Resolve(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Login.ClientSecret != "env-secret-value-1234" {
		t.Errorf("client_secret = %q", cfg.Login.ClientSecret)
	}
	if got := cfg.Login.Headers["Authorization"]; got != "Basic alice:env-secret-value-1234" {
		t.Errorf("header = %q", got)
	}
	if cfg.Relay.URL != "https://api.example/x" {
		t.Errorf("an empty variable should resolve to empty text, got %q", cfg.Relay.URL)
	}
	if cfg.Relay.FixedToken != "${ACCESSTOKEN}" {
		t.Errorf("runtime variables must be left alone, got %q", cfg.Relay.FixedToken)
	}
	if out := redact.String("secret is env-secret-value-1234"); strings.Contains(out, "env-secret-value-1234") {
		t.Errorf("resolved environment value is not redacted: %s", out)
	}
}

func TestEnvPlaceholderUnset(t *testing.T) {
	os.Unsetenv("O2R_TEST_UNSET")
	cfg := &config.Config{Login: &config.LoginConfig{ClientSecret: "${env:O2R_TEST_UNSET}"}}
	err := Resolve(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "environment variable O2R_TEST_UNSET is not set") {
		t.Errorf("resolveSecrets error = %v, want the unset variable named", err)
	}
}

func TestResolveIn(t *testing.T) {
	srv := newFakeVault(t, "env-token", "")
	t.Setenv("VAULT_TOKEN", "env-token")
	t.Setenv("O2R_TEST_ID", "client-123")
	type conn struct {
		Secret string
		Tags   []string
	}
	type appConfig struct {
		Name        string
		Connections map[string]*conn
		Default     conn
		Count       int
		hidden      string
	}
	cfg := &appConfig{
		Name:        "${env:O2R_TEST_ID}",
		Connections: map[string]*conn{"crm": {Secret: "${vault:app:password}", Tags: []string{"${vault:app:password}-tag"}}},
		Default:     conn{Secret: "literal"},
		hidden:      "${env:O2R_TEST_ID}",
	}
	managers := map[string]*config.SecretsManagerConfig{"vault": {Type: "hashicorp_vault",
		VaultConfig: &config.VaultConfig{Address: srv.URL, Auth: &config.VaultAuthConfig{Type: "token"}}}}
	if err := config.CheckSecretsManagers(managers); err != nil {
		t.Fatal(err)
	}
	if err := ResolveIn(context.Background(), managers, cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Name != "client-123" || cfg.Connections["crm"].Secret != "v2pass" || cfg.Connections["crm"].Tags[0] != "v2pass-tag" ||
		cfg.Default.Secret != "literal" || cfg.hidden != "${env:O2R_TEST_ID}" {
		t.Errorf("resolved %+v %+v", cfg, cfg.Connections["crm"])
	}

	if err := ResolveIn(context.Background(), nil, *cfg); err == nil {
		t.Error("ResolveIn accepted a struct value instead of a pointer")
	}
	if err := config.CheckSecretsManagers(map[string]*config.SecretsManagerConfig{"env": {Type: "aws_secrets_manager"}}); err == nil {
		t.Error("CheckSecretsManagers accepted the reserved alias env")
	}
}
