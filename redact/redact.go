// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

// Package redact masks secrets in log output.
//
// The registry of known secrets is process-wide, like the log output it
// protects: a value registered by any connection is masked in every log
// line.
package redact

import (
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Every log line passes through Writer, in debug mode too. Two
// layers are applied:
//  1. Known secret values (resolved secrets, configured credentials and the
//     current tokens) are replaced wherever they appear.
//  2. Values of well-known sensitive fields in form, JSON and header text,
//     and Bearer/Basic credentials, are masked even if not registered.

const redactedText = "[REDACTED]"

// minSecretLen is the shortest value registered as a known secret; shorter
// values would mask ordinary text.
const minSecretLen = 6

// maxRegisteredTokens bounds how many past tokens stay masked, so a
// long-running relay that renews tokens hourly does not grow without limit.
// Older tokens have expired and are still caught by the field patterns.
const maxRegisteredTokens = 16

type secretRegistry struct {
	mu       sync.RWMutex
	secrets  map[string]bool // static secrets, masked as [REDACTED]
	tokens   []string        // most recent tokens, oldest first
	replacer *strings.Replacer
}

var knownSecrets = &secretRegistry{secrets: map[string]bool{}}

// AddSecret masks value in all later log output.
func AddSecret(value string) {
	value = strings.TrimSpace(value)
	if len(value) < minSecretLen {
		return
	}
	r := knownSecrets
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.secrets[value] {
		r.secrets[value] = true
		r.rebuild()
	}
}

// AddToken masks a token in all later log output, keeping a short
// prefix and the length so log lines can still be correlated.
func AddToken(token string) {
	token = strings.TrimSpace(token)
	if len(token) < minSecretLen {
		return
	}
	r := knownSecrets
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, t := range r.tokens {
		if t == token {
			return
		}
	}
	r.tokens = append(r.tokens, token)
	if len(r.tokens) > maxRegisteredTokens {
		r.tokens = r.tokens[len(r.tokens)-maxRegisteredTokens:]
	}
	r.rebuild()
}

// rebuild recreates the replacer. Longer values are replaced first so a
// secret containing another is masked whole. Callers hold r.mu.
func (r *secretRegistry) rebuild() {
	repl := make(map[string]string, len(r.secrets)+len(r.tokens))
	for _, t := range r.tokens {
		repl[t] = MaskToken(t)
	}
	for s := range r.secrets {
		repl[s] = redactedText
	}
	keys := make([]string, 0, len(repl))
	for k := range repl {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
	pairs := make([]string, 0, 2*len(keys))
	for _, k := range keys {
		pairs = append(pairs, k, repl[k])
	}
	r.replacer = strings.NewReplacer(pairs...)
}

func (r *secretRegistry) replace(s string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.replacer == nil {
		return s
	}
	return r.replacer.Replace(s)
}

// MaskToken shows the first 4 characters and the length of a token.
func MaskToken(token string) string {
	if token == "" {
		return ""
	}
	if len(token) <= 8 {
		return redactedText
	}
	return fmt.Sprintf("%s…(len=%d)", token[:4], len(token))
}

const sensitiveFields = `access_token|refresh_token|id_token|subject_token|actor_token|client_secret|password|passwd|assertion|client_assertion|code_verifier|api_key|apikey|secret_id|jwt_key|private_key`

var redactPatterns = []struct {
	re   *regexp.Regexp
	repl string
}{
	// form and query strings: password=xyz
	{regexp.MustCompile(`(?i)\b(` + sensitiveFields + `)=[^&\s"]+`), `${1}=` + redactedText},
	// JSON: "password":"xyz"
	{regexp.MustCompile(`(?i)"(` + sensitiveFields + `)"\s*:\s*"(?:[^"\\]|\\.)*"`), `"${1}":"` + redactedText + `"`},
	// Authorization credentials: Bearer xyz, Basic xyz
	{regexp.MustCompile(`(?i)\b(Bearer|Basic)\s+[A-Za-z0-9\-._~+/]+=*`), `${1} ` + redactedText},
	// API key headers as printed from header maps: X-Api-Key:[xyz] or X-API-Key: xyz
	{regexp.MustCompile(`(?i)(x-api-key"?\s*[:=]\s*\[?)[^\]\s,"]+`), `${1}` + redactedText},
	// PEM private keys
	{regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`), redactedText},
}

// String removes secrets from s.
func String(s string) string {
	// Field patterns run first so their [REDACTED] marker wins over the
	// token mask, which the Bearer pattern would otherwise split.
	for _, p := range redactPatterns {
		s = p.re.ReplaceAllString(s, p.repl)
	}
	return knownSecrets.replace(s)
}

// Writer redacts everything written to W.
type Writer struct {
	W io.Writer
}

func (rw Writer) Write(p []byte) (int, error) {
	if _, err := io.WriteString(rw.W, String(string(p))); err != nil {
		return 0, err
	}
	return len(p), nil
}

// ReplaceAttr redacts string and other values in slog attributes, for
// slog.HandlerOptions.
func ReplaceAttr(_ []string, a slog.Attr) slog.Attr {
	switch a.Value.Kind() {
	case slog.KindString:
		a.Value = slog.StringValue(String(a.Value.String()))
	case slog.KindAny:
		a.Value = slog.StringValue(String(fmt.Sprint(a.Value.Any())))
	}
	return a
}
