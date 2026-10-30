// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package token

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"oauth2relay.com/oauth2relay/v2/config"
	"oauth2relay.com/oauth2relay/v2/internal/util"
)

// JWT bearer grant (RFC 7523).

const (
	// jwtBearerGrantType is the RFC 7523 grant_type for a JWT assertion.
	jwtBearerGrantType  = "urn:ietf:params:oauth:grant-type:jwt-bearer" //nolint:gosec // G101: a URN, not a credential
	defaultJWTAlgorithm = "HS256"
	defaultJWTLifetime  = 300 // seconds
)

// buildJWTAssertion returns the form body for a JWT bearer grant: a signed
// assertion carrying iss, sub, aud, scope, iat, nbf, exp and a random jti,
// plus any jwt_claims.
func buildJWTAssertion(lc *config.LoginConfig) (string, error) {
	method, key, err := jwtSigningKey(lc)
	if err != nil {
		return "", err
	}
	if lc.JWTIssuer == "" {
		return "", fmt.Errorf("jwt grant requires jwt_issuer")
	}

	jti, err := util.RandomID()
	if err != nil {
		return "", fmt.Errorf("failed to generate jti: %w", err)
	}
	lifetime := lc.JWTLifetime
	if lifetime <= 0 {
		lifetime = defaultJWTLifetime
	}
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": lc.JWTIssuer,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(time.Duration(lifetime) * time.Second).Unix(),
		"jti": jti,
	}
	if lc.JWTSubject != "" {
		claims["sub"] = lc.JWTSubject
	}
	if lc.JWTAudience != "" {
		claims["aud"] = lc.JWTAudience
	}
	if lc.JWTScope != "" {
		claims["scope"] = lc.JWTScope
	}
	for k, v := range lc.JWTClaims {
		claims[k] = v
	}

	token := jwt.NewWithClaims(method, claims)
	if lc.JWTKeyID != "" {
		token.Header["kid"] = lc.JWTKeyID
	}
	signed, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	grantType := lc.JWTGrantType
	if grantType == "" {
		grantType = jwtBearerGrantType
	}
	return "grant_type=" + url.QueryEscape(grantType) + "&assertion=" + url.QueryEscape(signed), nil
}

// jwtSigningKey returns the signing method for jwt_algorithm and the key to
// sign with: jwt_key for HMAC algorithms, or the PEM private key from
// jwt_private_key / jwt_private_key_file for RSA, RSA-PSS and ECDSA.
func jwtSigningKey(lc *config.LoginConfig) (jwt.SigningMethod, interface{}, error) {
	alg := strings.ToUpper(strings.TrimSpace(lc.JWTAlgorithm))
	if alg == "" {
		alg = defaultJWTAlgorithm
	}
	method := jwt.GetSigningMethod(alg)
	if method == nil || alg == "NONE" {
		return nil, nil, fmt.Errorf("unsupported jwt_algorithm %q", lc.JWTAlgorithm)
	}

	switch method.(type) {
	case *jwt.SigningMethodHMAC:
		if lc.JWTKey == "" {
			return nil, nil, fmt.Errorf("jwt grant with %s requires jwt_key", alg)
		}
		return method, []byte(lc.JWTKey), nil
	case *jwt.SigningMethodRSA, *jwt.SigningMethodRSAPSS:
		pem, err := jwtPrivateKeyPEM(lc, alg)
		if err != nil {
			return nil, nil, err
		}
		key, err := jwt.ParseRSAPrivateKeyFromPEM(pem)
		if err != nil {
			return nil, nil, fmt.Errorf("jwt_private_key is not a valid RSA private key for %s: %w", alg, err)
		}
		return method, key, nil
	case *jwt.SigningMethodECDSA:
		pem, err := jwtPrivateKeyPEM(lc, alg)
		if err != nil {
			return nil, nil, err
		}
		key, err := jwt.ParseECPrivateKeyFromPEM(pem)
		if err != nil {
			return nil, nil, fmt.Errorf("jwt_private_key is not a valid EC private key for %s: %w", alg, err)
		}
		return method, key, nil
	default:
		return nil, nil, fmt.Errorf("unsupported jwt_algorithm %q", lc.JWTAlgorithm)
	}
}

// jwtPrivateKeyPEM returns the PEM private key from jwt_private_key or, if
// that is empty, from the file named by jwt_private_key_file. Keys stored
// on one line with literal "\n" sequences (common in environment variables
// and secret stores) are accepted.
func jwtPrivateKeyPEM(lc *config.LoginConfig, alg string) ([]byte, error) {
	key := lc.JWTPrivateKey
	if key == "" && lc.JWTPrivateKeyFile != "" {
		b, err := os.ReadFile(lc.JWTPrivateKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read jwt_private_key_file: %w", err)
		}
		key = string(b)
	}
	if key == "" {
		return nil, fmt.Errorf("jwt grant with %s requires jwt_private_key or jwt_private_key_file", alg)
	}
	if !strings.Contains(key, "\n") {
		key = strings.ReplaceAll(key, `\n`, "\n")
	}
	return []byte(key), nil
}

// ValidateLogin checks the login settings that can only be checked once
// secrets are resolved, so that a bad JWT key stops the relay at startup.
func ValidateLogin(lc *config.LoginConfig) error {
	if lc == nil || lc.GrantType != "jwt" {
		return nil
	}
	if _, err := buildJWTAssertion(lc); err != nil {
		return fmt.Errorf("login: %w", err)
	}
	return nil
}
