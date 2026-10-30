// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package config

import "net/netip"

// Warnings lists settings that work but are discouraged.
func Warnings(cfg *Config) []string {
	var warnings []string
	if cfg.Relay.Type != "" {
		warnings = append(warnings, "relay.type is deprecated and has no effect; the body format follows the incoming Content-Type")
	}
	if cfg.Login != nil && cfg.Login.GrantType == "password" {
		warnings = append(warnings, "login.grant_type \"password\" sends a user's password to the identity provider and is "+
			"deprecated by OAuth 2.0 Security Best Current Practice (RFC 9700); use client_credentials or jwt where the provider supports them")
	}
	if !cfg.TLS.Enabled() && !isLoopbackHost(cfg.Host) {
		warnings = append(warnings, "the relay port serves plain HTTP on a non-loopback address; set tls.cert_file and tls.key_file, "+
			"or make sure a TLS-terminating proxy is the only way to reach it")
	}
	return warnings
}

// isLoopbackHost reports whether host is a loopback name or address. An
// empty host listens on every interface.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}
