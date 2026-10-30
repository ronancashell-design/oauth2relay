// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package redact

import (
	"bytes"
	"fmt"
	"log"
	"strings"
	"testing"
)

func TestRedactPatterns(t *testing.T) {
	tests := []struct {
		name, in, leak string
	}{
		{"form body", "grant_type=password&username=bob&password=hunter22&client_secret=cs-123", "hunter22"},
		{"form client secret", "client_id=x&client_secret=cs-123456", "cs-123456"},
		{"jwt assertion", "grant_type=urn&assertion=eyJhbGciOi.eyJpc3Mi.sig", "eyJhbGciOi"},
		{"token exchange subject", "grant_type=urn%3Aietf&subject_token=eyJzdWJq.x.y&subject_token_type=urn", "eyJzdWJq"},
		{"token exchange actor", "actor_token=eyJhY3Rvcg.x.y&actor_token_type=urn", "eyJhY3Rvcg"},
		{"JSON token response", `{"access_token":"at-abcdef","refresh_token":"rt-abcdef","expires_in":3600}`, "at-abcdef"},
		{"JSON refresh", `{"access_token":"at-abcdef","refresh_token":"rt-abcdef"}`, "rt-abcdef"},
		{"bearer header", "map[Authorization:Bearer eyJ0eXAi.abc.def Content-Type:application/json]", "eyJ0eXAi"},
		{"basic header", "Authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"},
		{"api key header map", "map[X-Api-Key:[relay-key-1] Accept:[*/*]]", "relay-key-1"},
		{"PEM key", "key=-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----", "MIIEvQIBADANBg"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := String(tt.in)
			if strings.Contains(got, tt.leak) {
				t.Errorf("String(%q) = %q, still contains %q", tt.in, got, tt.leak)
			}
			if !strings.Contains(got, redactedText) {
				t.Errorf("String(%q) = %q, want %s marker", tt.in, got, redactedText)
			}
		})
	}

	if got := String("expires_in=3600&grant_type=client_credentials"); got != "expires_in=3600&grant_type=client_credentials" {
		t.Errorf("non-sensitive text changed: %q", got)
	}
}

func TestRegisteredSecretsAndTokens(t *testing.T) {
	AddSecret("vault-resolved-value-42")
	AddSecret("abc") // too short to register
	AddToken("tok_ABCDEFGHIJKLMNOP")

	got := String("connecting with vault-resolved-value-42 and token tok_ABCDEFGHIJKLMNOP; abc stays")
	if strings.Contains(got, "vault-resolved-value-42") || strings.Contains(got, "tok_ABCDEFGHIJKLMNOP") {
		t.Errorf("registered values leaked: %q", got)
	}
	if !strings.Contains(got, "tok_…(len=20)") {
		t.Errorf("token not masked with prefix and length: %q", got)
	}
	if !strings.Contains(got, "abc stays") {
		t.Errorf("short value was masked: %q", got)
	}
}

func TestRegisteredTokensBounded(t *testing.T) {
	for i := 0; i < maxRegisteredTokens+10; i++ {
		AddToken(fmt.Sprintf("bounded-token-%04d", i))
	}
	knownSecrets.mu.RLock()
	n := len(knownSecrets.tokens)
	knownSecrets.mu.RUnlock()
	if n != maxRegisteredTokens {
		t.Errorf("%d tokens registered, want %d", n, maxRegisteredTokens)
	}
	last := fmt.Sprintf("bounded-token-%04d", maxRegisteredTokens+9)
	if strings.Contains(String(last), last) {
		t.Error("most recent token not masked")
	}
}

func TestRedactingWriter(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(Writer{W: &buf}, "", 0)
	logger.Printf("Debug: Login request data: %s", "grant_type=client_credentials&client_id=x&client_secret=topsecret99")
	if strings.Contains(buf.String(), "topsecret99") {
		t.Errorf("log line leaked secret: %q", buf.String())
	}
}

// ---------------- Error responses ----------------
