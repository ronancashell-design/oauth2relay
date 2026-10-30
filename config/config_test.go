// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

func TestParseConfigDefaults(t *testing.T) {
	cfg, err := Parse(configWith(""), nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Login.Parameters["AccessToken"] != "access_token" || cfg.Login.Parameters["ExpiresIn"] != "expires_in" {
		t.Errorf("standard grant did not get the standard parameters: %v", cfg.Login.Parameters)
	}
	// The default mapping is a copy, not the shared map.
	cfg.Login.Parameters["AccessToken"] = "changed"
	if standardTokenParameters["AccessToken"] != "access_token" {
		t.Error("standardTokenParameters was modified through a config")
	}
}

func TestParseConfigErrors(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
		want string
	}{
		{"unknown top-level field", configWith(`"rety_attempts": 3`), `unknown field "rety_attempts"`},
		{"unknown nested field", []byte(`{"port": 8080, "relay": {"url": "https://a.example", "methd": "GET"}}`), `unknown field "methd"`},
		{"trailing data", append(configWith(""), []byte(` {"port": 1}`)...), "unexpected data after"},
		{"port missing", []byte(`{"relay": {"url": "https://a.example", "fixedtoken": "t"}}`), "port 0 is not a valid port"},
		{"port too large", []byte(`{"port": 70000, "relay": {"url": "https://a.example", "fixedtoken": "t"}}`), "not a valid port"},
		{"no token source", []byte(`{"port": 8080, "relay": {"url": "https://a.example"}}`), "no way to obtain an access token"},
		{"bad grant type", []byte(`{"port": 8080, "login": {"url": "https://i.example", "grant_type": "authorization_code"}, "relay": {"url": "https://a.example"}}`), `grant_type "authorization_code" is not supported`},
		{"missing client secret", []byte(`{"port": 8080, "login": {"url": "https://i.example", "grant_type": "client_credentials", "client_id": "x"}, "relay": {"url": "https://a.example"}}`), "login.client_secret is required"},
		{"missing password", []byte(`{"port": 8080, "login": {"url": "https://i.example", "grant_type": "password", "client_id": "x", "client_secret": "y", "user": "u"}, "relay": {"url": "https://a.example"}}`), "login.password is required"},
		{"login url scheme", []byte(`{"port": 8080, "login": {"url": "ftp://i.example", "grant_type": "client_credentials", "client_id": "x", "client_secret": "y"}, "relay": {"url": "https://a.example"}}`), "login.url"},
		{"login url missing", []byte(`{"port": 8080, "login": {"grant_type": "client_credentials", "client_id": "x", "client_secret": "y"}, "relay": {"url": "https://a.example"}}`), "login.url is required"},
		{"relay url scheme", []byte(`{"port": 8080, "relay": {"url": "not-a-url", "fixedtoken": "t"}}`), "relay.url"},
		{"custom grant without mapping", []byte(`{"port": 8080, "login": {"url": "https://i.example", "data": "x"}, "relay": {"url": "https://a.example"}}`), "login.parameters must map AccessToken"},
		{"unknown parameter key", configWith(`"refresh": {"url": "https://i.example/r", "parameters": {"AccessToken": "a", "accesstoken": "b"}}`), `unknown key "accesstoken"`},
		{"refresh url", configWith(`"refresh": {"url": ""}`), "refresh.url is required"},
		{"refresh_at", configWith(`"token": {"refresh_at": 1.5}`), "token.refresh_at"},
		{"negative buffer", configWith(`"token": {"expiry_buffer": -1}`), "token.expiry_buffer"},
		{"negative retries", configWith(`"login": {"url": "https://i.example", "grant_type": "client_credentials", "client_id": "x", "client_secret": "y", "retry_interval": -1}`), "must not be negative"},
		{"scope on custom grant", []byte(`{"port": 8080, "login": {"url": "https://i.example", "method": "POST", "scope": "read", "parameters": {"AccessToken": "token"}}, "relay": {"url": "https://a.example"}}`), "login.scope applies only to"},
		{"bad client_auth", configWith(`"login": {"url": "https://i.example", "grant_type": "client_credentials", "client_id": "x", "client_secret": "y", "client_auth": "jwt"}`), `login.client_auth "jwt" is not supported`},
		{"client_auth on jwt grant", configWith(`"login": {"url": "https://i.example", "grant_type": "jwt", "jwt_key": "k", "jwt_issuer": "me", "client_auth": "basic"}`), "does not apply to the jwt grant"},
		{"secrets refresh too often", configWith(`"secrets_refresh_interval": 5`), "at least 60"},
		{"secrets refresh without managers", configWith(`"secrets_refresh_interval": 300`), "no secrets_managers"},
		{"secrets manager unknown field", configWith(`"secrets_managers": {"aws": {"type": "aws_secrets_manager", "region": "eu-west-1", "regoin": "x"}}`), `unknown field "regoin"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.raw, nil)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want one containing %q", err, tt.want)
			}
		})
	}
}

func TestParseConfigAccepts(t *testing.T) {
	for name, raw := range map[string][]byte{
		"placeholder urls":    []byte(`{"port": 8080, "login": {"url": "${vault:idp:url}", "grant_type": "client_credentials", "client_id": "x", "client_secret": "y"}, "relay": {"url": "${vault:api:url}"}, "secrets_managers": {"vault": {"type": "hashicorp_vault", "address": "http://127.0.0.1:8200"}}}`),
		"refresh token only":  []byte(`{"port": 8080, "refresh": {"url": "https://i.example/r", "token": "rt"}, "relay": {"url": "https://a.example"}}`),
		"fixed token":         []byte(`{"port": 8080, "relay": {"url": "https://a.example", "fixedtoken": "t"}}`),
		"secrets refresh":     configWith(`"secrets_refresh_interval": 300, "secrets_managers": {"aws": {"type": "aws_secrets_manager", "region": "eu-west-1"}}`),
		"token settings":      configWith(`"token": {"expiry_buffer": 0, "default_lifetime": 600, "background_refresh": false, "refresh_at": 0.5}`),
		"lower-case method":   configWith(`"refresh": {"url": "https://i.example/r", "method": "post"}`),
		"grant parameters":    configWith(`"login": {"url": "https://i.example", "grant_type": "client_credentials", "client_id": "x", "client_secret": "y", "scope": "read write", "audience": "https://api.example", "resource": "https://api.example", "client_auth": "Basic"}`),
		"custom with mapping": []byte(`{"port": 8080, "login": {"url": "https://i.example", "method": "post", "parameters": {"AccessToken": "token"}}, "relay": {"url": "https://a.example"}}`),
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := Parse(raw, nil)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Refresh != nil && cfg.Refresh.Method != strings.ToUpper(cfg.Refresh.Method) {
				t.Errorf("refresh.method %q not upper-cased", cfg.Refresh.Method)
			}
		})
	}
}

func TestLoadConfigFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, configWith(""), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path + ".missing"); err == nil || !strings.Contains(err.Error(), "failed to open config file") {
		t.Errorf("missing file error = %v", err)
	}
}

// ---------------- Secret re-fetch ----------------

func TestApplyDefaults(t *testing.T) {
	t.Run("fills in defaults", func(t *testing.T) {
		cfg := &Config{Login: &LoginConfig{}, Refresh: &RefreshConfig{}}
		if err := cfg.applyDefaults(); err != nil {
			t.Fatalf("applyDefaults: %v", err)
		}
		if cfg.TokenWaitTimeout != DefaultTokenWaitTimeout || cfg.Relay.Timeout != DefaultRelayTimeout ||
			cfg.Login.Timeout != DefaultIdPTimeout || cfg.Refresh.Timeout != DefaultIdPTimeout {
			t.Errorf("timeouts not defaulted: %+v", cfg)
		}
		if cfg.MaxRequestBodyBytes != DefaultMaxRequestBodyBytes {
			t.Errorf("MaxRequestBodyBytes = %d", cfg.MaxRequestBodyBytes)
		}
		if want := DefaultTokenWaitTimeout + DefaultRelayTimeout + 5; cfg.Server.WriteTimeout != want {
			t.Errorf("WriteTimeout = %d, want %d", cfg.Server.WriteTimeout, want)
		}
		if cfg.Server.ReadHeaderTimeout != defaultReadHeaderTimeout || cfg.Server.ShutdownTimeout != defaultShutdownTimeout {
			t.Errorf("server limits not defaulted: %+v", cfg.Server)
		}
	})

	t.Run("keeps explicit values", func(t *testing.T) {
		cfg := &Config{TokenWaitTimeout: 5, Relay: RelayConfig{Timeout: 7}, Server: ServerConfig{WriteTimeout: 12}}
		if err := cfg.applyDefaults(); err != nil {
			t.Fatalf("applyDefaults: %v", err)
		}
		if cfg.TokenWaitTimeout != 5 || cfg.Relay.Timeout != 7 || cfg.Server.WriteTimeout != 12 {
			t.Errorf("explicit values changed: %+v", cfg)
		}
	})

	t.Run("rejects write timeout shorter than a request can take", func(t *testing.T) {
		cfg := &Config{TokenWaitTimeout: 30, Relay: RelayConfig{Timeout: 60}, Server: ServerConfig{WriteTimeout: 20}}
		if err := cfg.applyDefaults(); err == nil || !strings.Contains(err.Error(), "server.write_timeout") {
			t.Fatalf("applyDefaults error = %v, want write_timeout error", err)
		}
	})
}

func TestNormaliseLogging(t *testing.T) {
	tests := []struct {
		name               string
		cfg                Config
		wantLevel, wantFmt string
		wantDebug          bool
		wantErr            bool
	}{
		{name: "defaults", wantLevel: "info", wantFmt: "text"},
		{name: "debug alias", cfg: Config{Debug: true}, wantLevel: "debug", wantFmt: "text", wantDebug: true},
		{name: "level wins over debug", cfg: Config{Debug: true, LogLevel: "WARN"}, wantLevel: "warn", wantFmt: "text"},
		{name: "json", cfg: Config{LogFormat: " JSON "}, wantLevel: "info", wantFmt: "json"},
		{name: "bad level", cfg: Config{LogLevel: "verbose"}, wantErr: true},
		{name: "bad format", cfg: Config{LogFormat: "xml"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.normaliseLogging()
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if tt.cfg.LogLevel != tt.wantLevel || tt.cfg.LogFormat != tt.wantFmt || tt.cfg.Debug != tt.wantDebug {
				t.Errorf("got level=%q format=%q debug=%v", tt.cfg.LogLevel, tt.cfg.LogFormat, tt.cfg.Debug)
			}
		})
	}
}

func TestNormaliseEndpoints(t *testing.T) {
	off := false
	tests := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{name: "defaults"},
		{name: "duplicate", cfg: Config{Metrics: MetricsConfig{Path: "/healthz"}}, wantErr: "both"},
		{name: "duplicate but disabled", cfg: Config{Metrics: MetricsConfig{Path: "/healthz", Enabled: &off}}},
		{name: "relative path", cfg: Config{Health: HealthConfig{ReadinessPath: "ready"}}, wantErr: "must be a path"},
		{name: "pattern", cfg: Config{Health: HealthConfig{ReadinessPath: "GET /ready"}}, wantErr: "must be a path"},
		{name: "admin port clash", cfg: Config{Port: 8080, AdminPort: 8080}, wantErr: "must differ"},
		{name: "admin port range", cfg: Config{AdminPort: 70000}, wantErr: "not a valid port"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.normaliseEndpoints()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want it to mention %q", err, tt.wantErr)
			}
		})
	}
	var cfg Config
	if err := cfg.normaliseEndpoints(); err != nil {
		t.Fatal(err)
	}
	if cfg.Health.LivenessPath != "/healthz" || cfg.Health.ReadinessPath != "/readyz" || cfg.Metrics.Path != "/metrics" {
		t.Errorf("defaults not applied: %+v %+v", cfg.Health, cfg.Metrics)
	}
}

func TestParseTrustedProxiesInvalid(t *testing.T) {
	for _, bad := range []string{"10.0.0.0/33", "not-an-ip", "10.0.0"} {
		cfg := &Config{TrustedProxies: []string{bad}}
		if err := cfg.parseTrustedProxies(); err == nil {
			t.Errorf("trusted_proxies %q accepted", bad)
		}
	}
}

func TestValidateSecretsManagers(t *testing.T) {
	t.Setenv("VAULT_ADDR", "")
	vault := func(vc VaultConfig) map[string]*SecretsManagerConfig {
		return map[string]*SecretsManagerConfig{"v": {Type: "hashicorp_vault", VaultConfig: &vc}}
	}
	azure := func(ac AzureConfig) map[string]*SecretsManagerConfig {
		return map[string]*SecretsManagerConfig{"a": {Type: "azure_key_vault", AzureConfig: &ac}}
	}
	tests := []struct {
		name    string
		in      map[string]*SecretsManagerConfig
		wantErr string
	}{
		{"vault ok", vault(VaultConfig{Address: "https://vault"}), ""},
		{"vault needs address", vault(VaultConfig{}), "address is required"},
		{"vault bad kv version", vault(VaultConfig{Address: "https://vault", KVVersion: 3}), "kv_version"},
		{"vault approle incomplete", vault(VaultConfig{Address: "https://vault", Auth: &VaultAuthConfig{Type: "approle", RoleID: "r"}}), "secret_id_env"},
		{"vault kubernetes needs role", vault(VaultConfig{Address: "https://vault", Auth: &VaultAuthConfig{Type: "kubernetes"}}), "requires role"},
		{"vault unknown auth", vault(VaultConfig{Address: "https://vault", Auth: &VaultAuthConfig{Type: "ldap"}}), "unsupported auth type"},
		{"vault token auth", vault(VaultConfig{Address: "https://vault", Auth: &VaultAuthConfig{Type: "token"}}), ""},
		{"azure needs url", azure(AzureConfig{}), "vault_url is required"},
		{"azure partial service principal", azure(AzureConfig{VaultURL: "https://kv", TenantID: "t"}), "needs tenant_id, client_id and client_secret_env"},
		{"azure managed identity", azure(AzureConfig{VaultURL: "https://kv", ClientID: "c"}), ""},
		{"azure service principal", azure(AzureConfig{VaultURL: "https://kv", TenantID: "t", ClientID: "c", ClientSecretEnv: "S"}), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSecretsManagers(tt.in)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestEnvAliasReserved(t *testing.T) {
	err := validateSecretsManagers(map[string]*SecretsManagerConfig{"env": {Type: "aws_secrets_manager"}})
	if err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Errorf("validateSecretsManagers error = %v, want env reserved", err)
	}
}

func TestRelayConfigValidate(t *testing.T) {
	tests := []struct {
		name      string
		rc        RelayConfig
		wantMode  string
		wantParam string
		wantErr   string
	}{
		{name: "default is passthrough", rc: RelayConfig{URL: "https://example.com/api"}, wantMode: "passthrough"},
		{name: "single", rc: RelayConfig{Mode: "single", URL: "https://example.com/api"}, wantMode: "single"},
		{name: "case insensitive", rc: RelayConfig{Mode: " SiNgLe ", URL: "https://example.com"}, wantMode: "single"},
		{name: "passthrough upper", rc: RelayConfig{Mode: "PASSTHROUGH", URL: "https://example.com"}, wantMode: "passthrough"},
		{name: "parameter defaults param", rc: RelayConfig{Mode: "Parameter", AllowedHosts: []string{"Example.com"}}, wantMode: "parameter", wantParam: "external_url"},
		{name: "parameter custom param", rc: RelayConfig{Mode: "parameter", URLParam: "relay_to", AllowedHosts: []string{"example.com"}}, wantMode: "parameter", wantParam: "relay_to"},
		{name: "unknown mode", rc: RelayConfig{Mode: "Singel", URL: "https://example.com"}, wantErr: `unknown relay.mode "Singel" (valid modes: single, passthrough, parameter)`},
		{name: "single needs url", rc: RelayConfig{Mode: "single"}, wantErr: `relay.url is required in "single" mode`},
		{name: "passthrough needs url", rc: RelayConfig{}, wantErr: `relay.url is required in "passthrough" mode`},
		{name: "parameter needs hosts", rc: RelayConfig{Mode: "parameter"}, wantErr: "relay.allowed_hosts must list at least one host"},
		{name: "parameter rejects wildcard", rc: RelayConfig{Mode: "parameter", AllowedHosts: []string{"*"}}, wantErr: `relay.allowed_hosts[0] "*" is not a valid host`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rc.Validate()
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("validate() error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("validate() unexpected error: %v", err)
			}
			if tt.rc.Mode != tt.wantMode {
				t.Errorf("Mode = %q, want %q", tt.rc.Mode, tt.wantMode)
			}
			if tt.rc.URLParam != tt.wantParam {
				t.Errorf("URLParam = %q, want %q", tt.rc.URLParam, tt.wantParam)
			}
		})
	}
}

func TestRelayConfigAllowedNetworks(t *testing.T) {
	rc := RelayConfig{Mode: "parameter", AllowedHosts: []string{"a.example"}, AllowedNetworks: []string{"nope"}}
	if err := rc.Validate(); err == nil || !strings.Contains(err.Error(), "relay.allowed_networks[0]") {
		t.Errorf("invalid network: %v", err)
	}
	rc = RelayConfig{URL: "https://a.example", AllowedNetworks: []string{"10.0.0.0/8"}}
	if err := rc.Validate(); err == nil || !strings.Contains(err.Error(), "only applies") {
		t.Errorf("allowed_networks outside parameter mode: %v", err)
	}
}

func TestTLSConfigValidate(t *testing.T) {
	for _, tt := range []struct {
		tc   TLSConfig
		want string
	}{
		{TLSConfig{CertFile: "c.pem"}, "must be set together"},
		{TLSConfig{KeyFile: "k.pem"}, "must be set together"},
		{TLSConfig{CertFile: "c.pem", KeyFile: "k.pem", MinVersion: "1.1"}, "not supported"},
		{TLSConfig{CertFile: "c.pem", KeyFile: "k.pem", MinVersion: "1.3"}, ""},
		{TLSConfig{}, ""},
	} {
		err := tt.tc.validate()
		if (tt.want == "" && err != nil) || (tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want))) {
			t.Errorf("%+v: error %v, want %q", tt.tc, err, tt.want)
		}
	}
}

func TestConfigWarnings(t *testing.T) {
	has := func(cfg *Config, want string) bool {
		for _, w := range Warnings(cfg) {
			if strings.Contains(w, want) {
				return true
			}
		}
		return false
	}
	if !has(&Config{Host: "localhost", Login: &LoginConfig{GrantType: "password"}}, "RFC 9700") {
		t.Error("no warning for the password grant")
	}
	for _, host := range []string{"", "0.0.0.0", "10.0.0.5", "relay.internal"} {
		if !has(&Config{Host: host}, "plain HTTP") {
			t.Errorf("no plain HTTP warning for host %q", host)
		}
	}
	for _, cfg := range []*Config{{Host: "localhost"}, {Host: "127.0.0.1"}, {Host: "::1"},
		{Host: "0.0.0.0", TLS: TLSConfig{CertFile: "c", KeyFile: "k"}}} {
		if w := Warnings(cfg); len(w) != 0 {
			t.Errorf("host %q tls %v: unexpected warnings %q", cfg.Host, cfg.TLS.Enabled(), w)
		}
	}
}

func TestLoginConfigCheck(t *testing.T) {
	lc := &LoginConfig{URL: "https://idp.example.com/token", GrantType: "client_credentials", ClientID: "id", ClientSecret: "s", ClientAuth: " Basic "}
	if err := lc.Check(); err != nil {
		t.Fatal(err)
	}
	if lc.Timeout != DefaultIdPTimeout || lc.ClientAuth != ClientAuthBasic || lc.Parameters["AccessToken"] != "access_token" {
		t.Errorf("defaults not applied: %+v", lc)
	}
	for name, bad := range map[string]*LoginConfig{
		"nil":          nil,
		"no secret":    {URL: "https://idp.example.com/token", GrantType: "client_credentials", ClientID: "id"},
		"bad URL":      {URL: "idp", GrantType: "client_credentials", ClientID: "id", ClientSecret: "s"},
		"custom scope": {URL: "https://idp.example.com/token", Scope: "a"},
	} {
		if err := bad.Check(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := (&TokenConfig{RefreshAt: 1.5}).Check(); err == nil {
		t.Error("TokenConfig.Check accepted refresh_at 1.5")
	}
}
