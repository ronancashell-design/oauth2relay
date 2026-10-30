// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

// Package config defines the relay's configuration file: its types,
// parsing, defaults and checks.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"
)

// ---------------- Configuration structures ----------------

type LoginConfig struct {
	User         string `json:"user"`
	Password     string `json:"password"`
	AuthString   string `json:"authstring"`
	ClientID     string `json:"client_id"`     // For client credentials and password grants
	ClientSecret string `json:"client_secret"` // For client credentials and password grants
	GrantType    string `json:"grant_type"`    // "client_credentials", "password", "jwt", or "" for custom
	// Optional token request fields for the client_credentials, password
	// and jwt grants.
	Scope       string `json:"scope"`        // scope parameter (RFC 6749)
	Audience    string `json:"audience"`     // audience parameter (Auth0 and others)
	Resource    string `json:"resource"`     // resource indicator (RFC 8707)
	ClientAuth  string `json:"client_auth"`  // "post" (default) sends the client credentials in the body, "basic" in an Authorization header
	JWTKey      string `json:"jwt_key"`      // Secret key for JWT signing
	JWTIssuer   string `json:"jwt_issuer"`   // JWT issuer claim
	JWTAudience string `json:"jwt_audience"` // JWT audience claim
	// JWT bearer grant (RFC 7523) options.
	JWTGrantType      string                 `json:"jwt_grant_type"`       // grant_type sent (default urn:ietf:params:oauth:grant-type:jwt-bearer)
	JWTAlgorithm      string                 `json:"jwt_algorithm"`        // HS256 (default), HS384, HS512, RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512
	JWTPrivateKey     string                 `json:"jwt_private_key"`      // PEM private key for RS*, PS* and ES* algorithms
	JWTPrivateKeyFile string                 `json:"jwt_private_key_file"` // file holding the PEM private key
	JWTKeyID          string                 `json:"jwt_key_id"`           // kid header
	JWTSubject        string                 `json:"jwt_subject"`          // sub claim
	JWTScope          string                 `json:"jwt_scope"`            // scope claim
	JWTLifetime       int                    `json:"jwt_lifetime"`         // assertion lifetime in seconds (default 300)
	JWTClaims         map[string]interface{} `json:"jwt_claims"`           // additional claims
	Data              string                 `json:"data"`
	Method            string                 `json:"method"`
	URL               string                 `json:"url"`
	Headers           map[string]string      `json:"headers"`
	Parameters        map[string]string      `json:"parameters"`
	RetryAttempts     int                    `json:"retry_attempts"` // Total login attempts before giving up (default 5)
	// RetryInterval is the wait in seconds before the first retry (default
	// 5). Each later wait doubles, up to RetryMaxInterval.
	RetryInterval int `json:"retry_interval"`
	// RetryMaxInterval caps the wait between retries in seconds (default 60,
	// or retry_interval if that is larger).
	RetryMaxInterval int `json:"retry_max_interval"`
	Timeout          int `json:"timeout"` // Seconds before a login request times out (default 10)
}

type RefreshConfig struct {
	Token      string            `json:"token"` // initial refresh token if available
	Data       string            `json:"data"`
	Method     string            `json:"method"`
	URL        string            `json:"url"`
	Headers    map[string]string `json:"headers"`
	Parameters map[string]string `json:"parameters"`
	Timeout    int               `json:"timeout"` // Seconds before a refresh request times out (default 10)
}

// Relay modes control how the outbound URL is chosen for each request.
const (
	// RelayModeSingle sends every request to relay.url; the incoming path is ignored.
	RelayModeSingle = "single"
	// RelayModePassthrough appends the incoming path to relay.url (the default).
	RelayModePassthrough = "passthrough"
	// RelayModeParameter takes the target URL from an incoming parameter
	// (relay.url_param), which is stripped before the request is sent on.
	RelayModeParameter = "parameter"

	defaultURLParam = "external_url"
)

type RelayConfig struct {
	Mode         string   `json:"mode"`          // "single", "passthrough" (default) or "parameter"; case-insensitive
	URLParam     string   `json:"url_param"`     // parameter mode: incoming parameter holding the target URL (default "external_url")
	AllowedHosts []string `json:"allowed_hosts"` // parameter mode: hosts the target URL may point to, e.g. "api.example.com" or "*.example.com"
	// AllowedNetworks lists non-public addresses (CIDR ranges or IPs) that
	// parameter mode may connect to; all others are blocked.
	AllowedNetworks []string `json:"allowed_networks"`
	allowedNets     []netip.Prefix

	URL         string `json:"url"`
	Data        string `json:"data"`
	Method      string `json:"method"`
	FixedToken  string `json:"fixedtoken"`
	Type        string `json:"type"` // e.g., "json"
	PushHeaders bool   `json:"pushheaders"`
	// ForwardHeaders, if set, limits pushheaders to these incoming headers.
	ForwardHeaders []string `json:"forward_headers"`
	// StripHeaders lists incoming headers that pushheaders never forwards.
	StripHeaders []string          `json:"strip_headers"`
	Headers      map[string]string `json:"headers"`
	Parameters   map[string]string `json:"parameters"`
	Timeout      int               `json:"timeout"` // Seconds before a relayed request times out (default 60)
	// FollowRedirects makes the relay follow upstream redirects (up to 5),
	// re-checking every hop. By default 3xx responses go back to the caller.
	FollowRedirects bool `json:"follow_redirects"`
}

// ServerConfig holds the inbound HTTP server limits. All durations are in
// seconds; zero means "use the default".
type ServerConfig struct {
	ReadHeaderTimeout int `json:"read_header_timeout"` // default 10
	ReadTimeout       int `json:"read_timeout"`        // default 60
	// WriteTimeout defaults to token_wait_timeout + relay.timeout + 5 so that
	// a request waiting for a token and then a slow upstream is not cut off.
	WriteTimeout    int `json:"write_timeout"`
	IdleTimeout     int `json:"idle_timeout"`     // default 120
	ShutdownTimeout int `json:"shutdown_timeout"` // default 15
	// ShutdownDelay is how long readiness reports "draining" before the
	// server stops accepting connections, so load balancers can stop
	// sending traffic first (default 0).
	ShutdownDelay  int `json:"shutdown_delay"`
	MaxHeaderBytes int `json:"max_header_bytes"` // default 1 MiB
}

// HealthConfig controls the liveness and readiness endpoints. They are
// served without API key authentication.
type HealthConfig struct {
	Enabled       *bool  `json:"enabled"`        // default true
	LivenessPath  string `json:"liveness_path"`  // default /healthz
	ReadinessPath string `json:"readiness_path"` // default /readyz
}

// MetricsConfig controls the Prometheus metrics endpoint. It is served
// without API key authentication.
type MetricsConfig struct {
	Enabled *bool  `json:"enabled"` // default true
	Path    string `json:"path"`    // default /metrics
}

// TokenConfig controls when the access token is renewed.
type TokenConfig struct {
	// ExpiryBuffer is subtracted from the lifetime the identity provider
	// gives, so a token is not used right up to its expiry (seconds,
	// default 10; at most half the lifetime is subtracted).
	ExpiryBuffer *int `json:"expiry_buffer"`
	// DefaultLifetime applies when the token response has no expiry
	// (seconds, default 300).
	DefaultLifetime int `json:"default_lifetime"`
	// BackgroundRefresh renews the token before it expires, so requests do
	// not wait for a renewal (default true).
	BackgroundRefresh *bool `json:"background_refresh"`
	// RefreshAt is the fraction of the token's lifetime after which the
	// background refresh renews it (default 0.8).
	RefreshAt float64 `json:"refresh_at"`
}

// Token lifetime defaults.
const (
	defaultTokenExpiryBuffer = 10  // seconds
	defaultTokenLifetime     = 300 // seconds
	defaultTokenRefreshAt    = 0.8
)

func (tc *TokenConfig) ExpiryBufferDuration() time.Duration {
	if tc.ExpiryBuffer == nil {
		return defaultTokenExpiryBuffer * time.Second
	}
	return time.Duration(*tc.ExpiryBuffer) * time.Second
}

func (tc *TokenConfig) DefaultLifetimeDuration() time.Duration {
	if tc.DefaultLifetime <= 0 {
		return defaultTokenLifetime * time.Second
	}
	return time.Duration(tc.DefaultLifetime) * time.Second
}

func (tc *TokenConfig) RefreshFraction() float64 {
	if tc.RefreshAt <= 0 {
		return defaultTokenRefreshAt
	}
	return tc.RefreshAt
}

// --- Secrets Manager Configuration ---

// VaultAuthConfig selects how the relay logs in to Vault. Without an auth
// block the client uses the VAULT_TOKEN environment variable.
type VaultAuthConfig struct {
	Type string `json:"type"` // "approle", "token" or "kubernetes"
	// Mount is the auth method's mount path (default: the type name).
	Mount string `json:"mount"`
	// approle
	RoleID      string `json:"role_id"`
	SecretIDEnv string `json:"secret_id_env"`
	// token
	TokenEnv string `json:"token_env"` // environment variable holding the token (default VAULT_TOKEN)
	// kubernetes
	Role      string `json:"role"`
	TokenPath string `json:"token_path"` // service account token (default /var/run/secrets/kubernetes.io/serviceaccount/token)
}

type VaultConfig struct {
	Address   string           `json:"address"`    // defaults to VAULT_ADDR
	Namespace string           `json:"namespace"`  // Vault Enterprise namespace
	Mount     string           `json:"mount"`      // KV secrets engine mount (default "secret")
	KVVersion int              `json:"kv_version"` // 1 or 2 (default 2)
	Auth      *VaultAuthConfig `json:"auth"`
}

type AWSConfig struct {
	Region  string `json:"region"`
	Profile string `json:"profile"`
}

// AzureConfig selects the Key Vault and the identity used to read it: a
// service principal when tenant_id, client_id and client_secret_env are all
// set, a user-assigned managed identity when only client_id is set, and
// DefaultAzureCredential otherwise.
type AzureConfig struct {
	VaultURL        string `json:"vault_url"`
	TenantID        string `json:"tenant_id"`
	ClientID        string `json:"client_id"`
	ClientSecretEnv string `json:"client_secret_env"`
}

type SecretsManagerConfig struct {
	Type        string       `json:"type"`
	AWSConfig   *AWSConfig   `json:"aws_config,omitempty"`
	VaultConfig *VaultConfig `json:"vault_config,omitempty"`
	AzureConfig *AzureConfig `json:"azure_config,omitempty"`
}

// UnmarshalJSON reads a secrets manager definition: a "type" field plus the
// settings of that type, all in one object. Unknown fields are rejected.
func (smc *SecretsManagerConfig) UnmarshalJSON(data []byte) error {
	var head struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		return err
	}
	smc.Type = head.Type

	switch head.Type {
	case "aws_secrets_manager":
		var v struct {
			Type string `json:"type"`
			AWSConfig
		}
		if err := strictUnmarshal(data, &v); err != nil {
			return err
		}
		smc.AWSConfig = &v.AWSConfig
	case "hashicorp_vault":
		var v struct {
			Type string `json:"type"`
			VaultConfig
		}
		if err := strictUnmarshal(data, &v); err != nil {
			return err
		}
		smc.VaultConfig = &v.VaultConfig
	case "azure_key_vault":
		var v struct {
			Type string `json:"type"`
			AzureConfig
		}
		if err := strictUnmarshal(data, &v); err != nil {
			return err
		}
		smc.AzureConfig = &v.AzureConfig
	default:
		return fmt.Errorf("unknown secret manager type: %s", head.Type)
	}

	return nil
}

// strictUnmarshal decodes data into v, rejecting fields v does not have.
func strictUnmarshal(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

type Config struct {
	Port      int            `json:"port"`
	Host      string         `json:"host"`
	APIKey    string         `json:"apiKey,omitempty"`
	Login     *LoginConfig   `json:"login"`
	Refresh   *RefreshConfig `json:"refresh"`
	Relay     RelayConfig    `json:"relay"`
	Debug     bool           `json:"debug"` // same as log_level "debug"
	LogFile   string         `json:"logfile"`
	LogLevel  string         `json:"log_level"`  // debug, info (default), warn or error
	LogFormat string         `json:"log_format"` // text (default) or json
	// AccessLog logs one line per relayed request (default true). When off,
	// only requests the relay rejected or failed are logged.
	AccessLog       *bool                            `json:"access_log"`
	SecretsManagers map[string]*SecretsManagerConfig `json:"secrets_managers"`
	// TokenWaitTimeout is how long (in seconds) an incoming request waits for a
	// valid token before failing with 503 Service Unavailable (default 30).
	TokenWaitTimeout int `json:"token_wait_timeout"`
	// MaxRequestBodyBytes caps the size of incoming request bodies; larger
	// bodies are rejected with 413 Request Entity Too Large (default 10 MiB).
	MaxRequestBodyBytes int64        `json:"max_request_body_bytes"`
	Server              ServerConfig `json:"server"`
	// TrustedProxies lists the proxies and load balancers (IP addresses or
	// CIDR ranges) whose X-Forwarded-For header is believed when working
	// out the client IP for ${IP}.
	TrustedProxies []string `json:"trusted_proxies"`
	// AdminPort, when set, serves the health and metrics endpoints on their
	// own port (on the same host) instead of the relay port.
	AdminPort int           `json:"admin_port"`
	Health    HealthConfig  `json:"health"`
	Metrics   MetricsConfig `json:"metrics"`
	Token     TokenConfig   `json:"token"`
	// SecretsRefreshInterval, when set, re-fetches the secret placeholders
	// every this many seconds so rotated credentials are picked up without
	// a restart (minimum 60; default 0, off).
	SecretsRefreshInterval int `json:"secrets_refresh_interval"`
	// TLS enables HTTPS on the relay port.
	TLS TLSConfig `json:"tls"`
	// CAFile holds PEM CA certificates trusted for outbound connections, in
	// addition to the system ones.
	CAFile string `json:"ca_file"`

	trustedNets []netip.Prefix // parsed TrustedProxies
}

// enabled reports whether an optional boolean is on, given its default.
func enabled(b *bool, def bool) bool {
	if b == nil {
		return def
	}
	return *b
}

// AccessLogEnabled reports whether every relayed request is logged.
func (cfg *Config) AccessLogEnabled() bool { return enabled(cfg.AccessLog, true) }

// IsEnabled reports whether the health endpoints are served.
func (hc *HealthConfig) IsEnabled() bool { return enabled(hc.Enabled, true) }

// IsEnabled reports whether the metrics endpoint is served.
func (mc *MetricsConfig) IsEnabled() bool { return enabled(mc.Enabled, true) }

// BackgroundRefreshEnabled reports whether the token is renewed before it
// expires.
func (tc *TokenConfig) BackgroundRefreshEnabled() bool { return enabled(tc.BackgroundRefresh, true) }

// TrustedNetworks returns trusted_proxies, parsed.
func (cfg *Config) TrustedNetworks() []netip.Prefix { return cfg.trustedNets }

// AllowedNetworkPrefixes returns relay.allowed_networks, parsed.
func (rc *RelayConfig) AllowedNetworkPrefixes() []netip.Prefix { return rc.allowedNets }

// ExpandEnv replaces user, password and authstring values that start with
// "$" with the environment variable they name (the older form of
// ${env:NAME}). It runs once, when the configuration is prepared.
func (lc *LoginConfig) ExpandEnv() {
	if lc == nil {
		return
	}
	for _, v := range []*string{&lc.User, &lc.Password, &lc.AuthString} {
		if strings.HasPrefix(*v, "$") {
			*v = os.ExpandEnv(*v)
		}
	}
}

// Default paths of the operational endpoints.
const (
	defaultLivenessPath  = "/healthz"
	defaultReadinessPath = "/readyz"
	defaultMetricsPath   = "/metrics"
)

// normaliseEndpoints applies the default health and metrics paths and
// checks that they are valid, distinct, and that admin_port does not clash
// with port.
func (cfg *Config) normaliseEndpoints() error {
	setPath := func(p *string, def string) {
		*p = strings.TrimSpace(*p)
		if *p == "" {
			*p = def
		}
	}
	setPath(&cfg.Health.LivenessPath, defaultLivenessPath)
	setPath(&cfg.Health.ReadinessPath, defaultReadinessPath)
	setPath(&cfg.Metrics.Path, defaultMetricsPath)

	seen := map[string]string{}
	check := func(name, p string, on bool) error {
		if !on {
			return nil
		}
		if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, " {}") {
			return fmt.Errorf("%s %q must be a path starting with /", name, p)
		}
		if other, dup := seen[p]; dup {
			return fmt.Errorf("%s and %s are both %q", other, name, p)
		}
		seen[p] = name
		return nil
	}
	healthOn := enabled(cfg.Health.Enabled, true)
	if err := check("health.liveness_path", cfg.Health.LivenessPath, healthOn); err != nil {
		return err
	}
	if err := check("health.readiness_path", cfg.Health.ReadinessPath, healthOn); err != nil {
		return err
	}
	if err := check("metrics.path", cfg.Metrics.Path, enabled(cfg.Metrics.Enabled, true)); err != nil {
		return err
	}
	if cfg.AdminPort < 0 || cfg.AdminPort > 65535 {
		return fmt.Errorf("admin_port %d is not a valid port", cfg.AdminPort)
	}
	if cfg.AdminPort != 0 && cfg.AdminPort == cfg.Port {
		return fmt.Errorf("admin_port must differ from port (%d)", cfg.Port)
	}
	return nil
}

// MethodInherit as relay.method relays each request with its own method.
const MethodInherit = "INHERIT"

// parseTrustedProxies parses trusted_proxies into trustedNets. A plain IP
// address is treated as a single-address range.
func (cfg *Config) parseTrustedProxies() error {
	cfg.trustedNets = nil
	for i, entry := range cfg.TrustedProxies {
		prefix, err := parsePrefixOrAddr(entry)
		if err != nil {
			return fmt.Errorf("trusted_proxies[%d] %q is not an IP address or CIDR range", i, cfg.TrustedProxies[i])
		}
		cfg.trustedNets = append(cfg.trustedNets, prefix)
	}
	return nil
}

// parsePrefixOrAddr parses a CIDR range, or an IP address as a range
// holding only that address.
func parsePrefixOrAddr(entry string) (netip.Prefix, error) {
	entry = strings.TrimSpace(entry)
	if strings.Contains(entry, "/") {
		prefix, err := netip.ParsePrefix(entry)
		return prefix.Masked(), err
	}
	addr, err := netip.ParseAddr(entry)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// Defaults for the inbound server and outbound HTTP clients.
const (
	DefaultRelayTimeout        = 60 // seconds
	DefaultIdPTimeout          = 10 // seconds
	defaultReadHeaderTimeout   = 10
	defaultReadTimeout         = 60
	defaultIdleTimeout         = 120
	defaultShutdownTimeout     = 15
	defaultMaxHeaderBytes      = 1 << 20
	DefaultMaxRequestBodyBytes = 10 << 20
	// MaxIdPResponseBytes caps how much of a token endpoint response is read.
	MaxIdPResponseBytes = 1 << 20
	// DefaultTokenWaitTimeout is how long (in seconds) an incoming request
	// waits for a valid token by default.
	DefaultTokenWaitTimeout = 30
)

// APIKeyHeader is the incoming header that carries the relay's API key. It
// authenticates the caller to the relay and is never sent upstream.
const APIKeyHeader = "X-API-Key" //nolint:gosec // G101: a header name, not a credential

// Values of login.client_auth.
const (
	ClientAuthPost  = "post"
	ClientAuthBasic = "basic"
)

// applyDefaults fills in unset limits and timeouts, then checks that they
// are consistent with each other.
func (cfg *Config) applyDefaults() error {
	setDefault := func(v *int, d int) {
		if *v <= 0 {
			*v = d
		}
	}
	setDefault(&cfg.TokenWaitTimeout, DefaultTokenWaitTimeout)
	setDefault(&cfg.Relay.Timeout, DefaultRelayTimeout)
	if cfg.Login != nil {
		setDefault(&cfg.Login.Timeout, DefaultIdPTimeout)
	}
	if cfg.Refresh != nil {
		setDefault(&cfg.Refresh.Timeout, DefaultIdPTimeout)
	}
	if cfg.MaxRequestBodyBytes <= 0 {
		cfg.MaxRequestBodyBytes = DefaultMaxRequestBodyBytes
	}

	s := &cfg.Server
	setDefault(&s.ReadHeaderTimeout, defaultReadHeaderTimeout)
	setDefault(&s.ReadTimeout, defaultReadTimeout)
	setDefault(&s.IdleTimeout, defaultIdleTimeout)
	setDefault(&s.ShutdownTimeout, defaultShutdownTimeout)
	if s.ShutdownDelay < 0 {
		s.ShutdownDelay = 0
	}
	setDefault(&s.MaxHeaderBytes, defaultMaxHeaderBytes)
	minWrite := cfg.TokenWaitTimeout + cfg.Relay.Timeout
	if s.WriteTimeout <= 0 {
		s.WriteTimeout = minWrite + 5
	} else if s.WriteTimeout < minWrite {
		return fmt.Errorf("server.write_timeout (%ds) must be at least token_wait_timeout + relay.timeout (%ds), "+
			"otherwise slow but valid requests are cut off", s.WriteTimeout, minWrite)
	}
	return nil
}

// Load reads and checks the configuration file.
func Load(configFile string) (*Config, error) {
	raw, err := ReadFile(configFile)
	if err != nil {
		return nil, err
	}
	return Parse(raw, nil)
}

func ReadFile(configFile string) ([]byte, error) {
	raw, err := os.ReadFile(configFile) //nolint:gosec // G304: the path is the operator's --config
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %w", err)
	}
	return raw, nil
}

// Parse decodes and checks a configuration. Unknown fields are
// rejected so that typos are caught. override, if not nil, is applied after
// decoding and before the checks; it carries the command-line flags.
func Parse(raw []byte, override func(*Config)) (*Config, error) {
	var cfg Config
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("failed to parse config: unexpected data after the configuration object")
	}
	if override != nil {
		override(&cfg)
	}
	if err := cfg.Check(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Check validates a configuration and fills in its defaults. Parse calls
// it; call it directly for a Config built in code.
func (cfg *Config) Check() error {
	if err := cfg.Relay.Validate(); err != nil {
		return fmt.Errorf("invalid relay configuration: %w", err)
	}
	if err := cfg.parseTrustedProxies(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	if err := validateSecretsManagers(cfg.SecretsManagers); err != nil {
		return fmt.Errorf("invalid secrets_managers configuration: %w", err)
	}
	for _, check := range []func() error{
		cfg.validate, cfg.applyDefaults, cfg.normaliseLogging, cfg.normaliseEndpoints,
	} {
		if err := check(); err != nil {
			return fmt.Errorf("invalid configuration: %w", err)
		}
	}
	return nil
}

// Check validates a login configuration on its own and fills in its
// defaults, for programs that build token.Settings without a whole Config.
// Config.Check does the same for cfg.Login.
func (lc *LoginConfig) Check() error {
	if lc == nil {
		return fmt.Errorf("login configuration is not provided")
	}
	if err := lc.validate(); err != nil {
		return err
	}
	if lc.Timeout <= 0 {
		lc.Timeout = DefaultIdPTimeout
	}
	return nil
}

// Check validates token settings on their own. Config.Check does the same
// for cfg.Token.
func (tc *TokenConfig) Check() error {
	return tc.validate()
}

// Validate checks the relay settings for the configured mode and normalises
// them: the mode is lower-cased (defaulting to passthrough), url_param
// defaults to "external_url" and allowed_hosts entries are lower-cased.
func (rc *RelayConfig) Validate() error {
	rc.Method = strings.ToUpper(strings.TrimSpace(rc.Method))
	if rc.Method == "" {
		rc.Method = http.MethodGet
	}
	if strings.ContainsAny(rc.Method, " \t/") {
		return fmt.Errorf("relay.method %q is not a valid HTTP method or %q", rc.Method, strings.ToLower(MethodInherit))
	}

	configured := rc.Mode
	rc.Mode = strings.ToLower(strings.TrimSpace(rc.Mode))
	if rc.Mode == "" {
		rc.Mode = RelayModePassthrough
	}

	switch rc.Mode {
	case RelayModeSingle, RelayModePassthrough:
		if strings.TrimSpace(rc.URL) == "" {
			return fmt.Errorf("relay.url is required in %q mode", rc.Mode)
		}
		if err := checkURL("relay.url", rc.URL); err != nil {
			return err
		}
	case RelayModeParameter:
		rc.URLParam = strings.TrimSpace(rc.URLParam)
		if rc.URLParam == "" {
			rc.URLParam = defaultURLParam
		}
		if len(rc.AllowedHosts) == 0 {
			return fmt.Errorf("relay.allowed_hosts must list at least one host in %q mode, "+
				"otherwise callers could send the access token to any server", rc.Mode)
		}
		for i, h := range rc.AllowedHosts {
			h = strings.ToLower(strings.TrimSpace(h))
			if h == "" || h == "*" || h == "*." {
				return fmt.Errorf("relay.allowed_hosts[%d] %q is not a valid host", i, rc.AllowedHosts[i])
			}
			rc.AllowedHosts[i] = h
		}
		nets, err := parseNetworks("relay.allowed_networks", rc.AllowedNetworks)
		if err != nil {
			return err
		}
		rc.allowedNets = nets
	default:
		return fmt.Errorf("unknown relay.mode %q (valid modes: %s, %s, %s)",
			configured, RelayModeSingle, RelayModePassthrough, RelayModeParameter)
	}
	if len(rc.AllowedNetworks) > 0 && rc.Mode != RelayModeParameter {
		return fmt.Errorf("relay.allowed_networks only applies in %q mode", RelayModeParameter)
	}
	for _, h := range rc.ForwardHeaders {
		if strings.EqualFold(strings.TrimSpace(h), APIKeyHeader) {
			return fmt.Errorf("relay.forward_headers must not include %s: the relay's API key is never sent upstream", APIKeyHeader)
		}
	}
	return nil
}

// parseNetworks parses relay.allowed_networks: CIDR ranges or single IP
// addresses.
func parseNetworks(name string, entries []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for i, entry := range entries {
		prefix, err := parsePrefixOrAddr(entry)
		if err != nil {
			return nil, fmt.Errorf("%s[%d] %q is not an IP address or CIDR range", name, i, entry)
		}
		out = append(out, prefix)
	}
	return out, nil
}
