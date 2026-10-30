// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package config

import (
	"crypto/tls"
	"fmt"
)

// TLSConfig enables HTTPS on the relay port.
type TLSConfig struct {
	CertFile   string `json:"cert_file"`   // PEM certificate chain
	KeyFile    string `json:"key_file"`    // PEM private key
	MinVersion string `json:"min_version"` // "1.2" (default) or "1.3"
}

// Enabled reports whether the relay port serves HTTPS.
func (tc *TLSConfig) Enabled() bool { return tc.CertFile != "" }

func (tc *TLSConfig) validate() error {
	if (tc.CertFile == "") != (tc.KeyFile == "") {
		return fmt.Errorf("tls.cert_file and tls.key_file must be set together")
	}
	if _, err := tc.MinTLSVersion(); err != nil {
		return err
	}
	return nil
}

// MinTLSVersion returns min_version as a crypto/tls version.
func (tc *TLSConfig) MinTLSVersion() (uint16, error) {
	switch tc.MinVersion {
	case "", "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("tls.min_version %q is not supported (valid: 1.2, 1.3)", tc.MinVersion)
	}
}
