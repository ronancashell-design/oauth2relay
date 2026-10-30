// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package config

import (
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strings"
)

// ---------------- Configuration checks ----------------
//
// validate checks the settings outside relay, trusted_proxies and
// secrets_managers (which have their own checks): the port, the token
// source, the login and refresh endpoints and the token settings. Values
// may still hold secret placeholders, so only their presence and shape are
// checked; anything that needs the resolved value is checked at startup.

// Grant types accepted in login.grant_type. "" and "custom" use the
// login.data and login.headers templates.
var loginGrantTypes = []string{"", "custom", "client_credentials", "password", "jwt"}

// tokenParameterKeys are the keys of login.parameters and refresh.parameters:
// each maps one token value to a field of the token endpoint's response.
var tokenParameterKeys = []string{"AccessToken", "RefreshToken", "ExpiresIn", "ExpiresAt"}

// standardTokenParameters is the RFC 6749 response mapping, used when a
// standard grant or the refresh request has no parameters configured.
var standardTokenParameters = map[string]string{
	"AccessToken":  "access_token",
	"RefreshToken": "refresh_token",
	"ExpiresIn":    "expires_in",
}

// minSecretsRefreshInterval keeps secret re-fetching from hammering the
// secrets managers.
const minSecretsRefreshInterval = 60

func (cfg *Config) validate() error {
	if cfg.Port < 1 || cfg.Port > 65535 {
		return fmt.Errorf("port %d is not a valid port (1-65535)", cfg.Port)
	}
	if cfg.Relay.FixedToken == "" && cfg.Login == nil && (cfg.Refresh == nil || cfg.Refresh.Token == "") {
		return fmt.Errorf("no way to obtain an access token: set login, relay.fixedtoken, or refresh with refresh.token")
	}
	if err := cfg.Login.validate(); err != nil {
		return err
	}
	if err := cfg.Refresh.validate(); err != nil {
		return err
	}
	if err := cfg.Token.validate(); err != nil {
		return err
	}
	if err := cfg.TLS.validate(); err != nil {
		return err
	}
	if cfg.TokenWaitTimeout < 0 || cfg.MaxRequestBodyBytes < 0 {
		return fmt.Errorf("token_wait_timeout and max_request_body_bytes must not be negative")
	}
	if n := cfg.SecretsRefreshInterval; n != 0 {
		if n < minSecretsRefreshInterval {
			return fmt.Errorf("secrets_refresh_interval must be 0 (off) or at least %d seconds", minSecretsRefreshInterval)
		}
		if len(cfg.SecretsManagers) == 0 {
			return fmt.Errorf("secrets_refresh_interval is set but no secrets_managers are configured")
		}
	}
	return nil
}

func (lc *LoginConfig) validate() error {
	if lc == nil {
		return nil
	}
	if err := checkURL("login.url", lc.URL); err != nil {
		return err
	}
	if !slices.Contains(loginGrantTypes, lc.GrantType) {
		return fmt.Errorf("login.grant_type %q is not supported (valid: client_credentials, password, jwt, custom)", lc.GrantType)
	}
	if err := normaliseMethod("login.method", &lc.Method); err != nil {
		return err
	}
	var required []string
	switch lc.GrantType {
	case "client_credentials":
		required = []string{"client_id", "client_secret"}
	case "password":
		required = []string{"user", "password", "client_id", "client_secret"}
	}
	if lc.GrantType == "" || lc.GrantType == "custom" {
		for _, f := range []struct{ name, value string }{
			{"scope", lc.Scope}, {"audience", lc.Audience}, {"resource", lc.Resource}, {"client_auth", lc.ClientAuth},
		} {
			if f.value != "" {
				return fmt.Errorf("login.%s applies only to the client_credentials, password and jwt grants; for a custom grant put it in login.data", f.name)
			}
		}
	}
	lc.ClientAuth = strings.ToLower(strings.TrimSpace(lc.ClientAuth))
	switch {
	case lc.ClientAuth != "" && lc.ClientAuth != ClientAuthPost && lc.ClientAuth != ClientAuthBasic:
		return fmt.Errorf("login.client_auth %q is not supported (valid: post, basic)", lc.ClientAuth)
	case lc.ClientAuth != "" && lc.GrantType == "jwt":
		return fmt.Errorf("login.client_auth does not apply to the jwt grant, which authenticates with the signed assertion")
	}
	values := map[string]string{"client_id": lc.ClientID, "client_secret": lc.ClientSecret, "user": lc.User, "password": lc.Password}
	for _, name := range required {
		if strings.TrimSpace(values[name]) == "" {
			return fmt.Errorf("login.%s is required for the %s grant", name, lc.GrantType)
		}
	}
	if lc.RetryAttempts < 0 || lc.RetryInterval < 0 || lc.RetryMaxInterval < 0 || lc.Timeout < 0 || lc.JWTLifetime < 0 {
		return fmt.Errorf("login retry, timeout and lifetime settings must not be negative")
	}
	standard := lc.GrantType != "" && lc.GrantType != "custom"
	return checkTokenParameters("login.parameters", &lc.Parameters, standard)
}

func (rc *RefreshConfig) validate() error {
	if rc == nil {
		return nil
	}
	if err := checkURL("refresh.url", rc.URL); err != nil {
		return err
	}
	if err := normaliseMethod("refresh.method", &rc.Method); err != nil {
		return err
	}
	if rc.Timeout < 0 {
		return fmt.Errorf("refresh.timeout must not be negative")
	}
	return checkTokenParameters("refresh.parameters", &rc.Parameters, true)
}

func (tc *TokenConfig) validate() error {
	if tc.ExpiryBuffer != nil && *tc.ExpiryBuffer < 0 {
		return fmt.Errorf("token.expiry_buffer must not be negative")
	}
	if tc.DefaultLifetime < 0 {
		return fmt.Errorf("token.default_lifetime must not be negative")
	}
	if tc.RefreshAt < 0 || tc.RefreshAt >= 1 {
		return fmt.Errorf("token.refresh_at must be a fraction between 0 and 1, such as 0.8")
	}
	return nil
}

// checkTokenParameters checks a response mapping. An empty mapping gets the
// standard OAuth 2.0 field names when useStandard is set.
func checkTokenParameters(name string, params *map[string]string, useStandard bool) error {
	if len(*params) == 0 && useStandard {
		*params = maps.Clone(standardTokenParameters)
	}
	for _, k := range slices.Sorted(maps.Keys(*params)) {
		if !slices.Contains(tokenParameterKeys, k) {
			return fmt.Errorf("%s has unknown key %q (valid: %s)", name, k, strings.Join(tokenParameterKeys, ", "))
		}
	}
	if strings.TrimSpace((*params)["AccessToken"]) == "" {
		return fmt.Errorf("%s must map AccessToken to a field of the token response", name)
	}
	return nil
}

// checkURL checks that raw is an http or https URL. Values containing a
// placeholder are only checked for presence, since they are completed later.
func checkURL(name, raw string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("%s is required", name)
	}
	if strings.Contains(raw, "${") {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("%s %q must be an http:// or https:// URL", name, raw)
	}
	return nil
}

// normaliseMethod upper-cases an HTTP method and rejects malformed ones. An
// empty method is left empty for the caller's default.
func normaliseMethod(name string, method *string) error {
	*method = strings.ToUpper(strings.TrimSpace(*method))
	if strings.ContainsAny(*method, " \t/") {
		return fmt.Errorf("%s %q is not a valid HTTP method", name, *method)
	}
	return nil
}
