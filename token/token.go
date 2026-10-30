// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

// Package token obtains and renews the access token: the OAuth 2.0 grants,
// refresh, retries and background renewal.
package token

import (
	"fmt"
	"time"

	"oauth2relay.com/oauth2relay/v2/config"
	"oauth2relay.com/oauth2relay/v2/internal/util"
	"oauth2relay.com/oauth2relay/v2/redact"
)

type Token struct {
	AccessToken  string
	RefreshToken string
	IssuedAt     time.Time
	// ExpiresAt is when the relay stops using the token: the expiry the
	// identity provider gave, less token.expiry_buffer. (An ExchangeResult
	// has the expiry without a buffer; see there.)
	ExpiresAt time.Time
}

// String masks the token values so a Token can be logged safely.
func (t *Token) String() string {
	if t == nil {
		return "<nil>"
	}
	return fmt.Sprintf("{AccessToken:%s RefreshToken:%s ExpiresAt:%s}",
		redact.MaskToken(t.AccessToken), redact.MaskToken(t.RefreshToken), t.ExpiresAt.Format(time.RFC3339))
}

// extractToken uses a parameter mapping (from config) to extract
// AccessToken, RefreshToken, and an expiration value from a JSON response.
func extractToken(respMap map[string]interface{}, paramMapping map[string]string, tc *config.TokenConfig, now time.Time) (*Token, error) {
	token := &Token{}

	// Extract access token.
	if field, ok := paramMapping["AccessToken"]; ok {
		if v, exists := respMap[field]; exists {
			if s, valid := util.ToString(v); valid {
				token.AccessToken = s
			} else {
				return nil, fmt.Errorf("invalid type for field %s", field)
			}
		} else {
			return nil, fmt.Errorf("response missing field %s", field)
		}
	} else {
		return nil, fmt.Errorf("no mapping for AccessToken provided")
	}

	// Extract refresh token.
	if field, ok := paramMapping["RefreshToken"]; ok {
		if v, exists := respMap[field]; exists {
			if s, valid := util.ToString(v); valid {
				token.RefreshToken = s
			}
		} // leave empty if not provided
	}

	token.IssuedAt = now
	expiry := responseExpiry(respMap, paramMapping, token.IssuedAt)
	if expiry.IsZero() {
		token.ExpiresAt = token.IssuedAt.Add(tc.DefaultLifetimeDuration())
	} else {
		// A short-lived token keeps at least half its lifetime.
		buffer := min(tc.ExpiryBufferDuration(), max(expiry.Sub(token.IssuedAt)/2, 0))
		token.ExpiresAt = expiry.Add(-buffer)
	}
	redact.AddToken(token.AccessToken)
	redact.AddToken(token.RefreshToken)
	return token, nil
}

// responseExpiry reads the token's expiry from the ExpiresIn (seconds from
// now) or ExpiresAt (Unix time or RFC 3339) response field. It returns the
// zero time when neither is present and valid.
func responseExpiry(respMap map[string]interface{}, paramMapping map[string]string, now time.Time) time.Time {
	if field, ok := paramMapping["ExpiresIn"]; ok {
		// Values outside (0, ~31 years) are ignored rather than overflowing.
		if seconds, err := util.ToFloat64(respMap[field]); err == nil && seconds > 0 && seconds < 1e9 {
			return now.Add(time.Duration(seconds * float64(time.Second)))
		}
	}
	if field, ok := paramMapping["ExpiresAt"]; ok {
		v := respMap[field]
		if seconds, err := util.ToFloat64(v); err == nil {
			return time.Unix(int64(seconds), 0)
		}
		if str, ok := v.(string); ok {
			if t, err := time.Parse(time.RFC3339, str); err == nil {
				return t
			}
		}
	}
	return time.Time{}
}
