// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package token

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"oauth2relay.com/oauth2relay/v2/config"
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

// testManager returns a Manager for cfg's token settings.
func testManager(cfg *config.Config) *Manager {
	return NewManager(SettingsFrom(cfg), Options{})
}

// doLogin sends one login request for cfg.
func doLogin(cfg *config.Config) (*Token, error) {
	m := testManager(cfg)
	return m.login(context.Background(), m.settings.Load())
}

// doLoginWithRetry logs in for cfg with login.retry_attempts attempts.
func doLoginWithRetry(cfg *config.Config) (*Token, error) {
	m := testManager(cfg)
	return m.loginWithRetry(context.Background(), m.settings.Load())
}

// doRefresh sends one refresh request for cfg.
func doRefresh(cfg *config.Config) (*Token, error) {
	m := testManager(cfg)
	return m.refresh(context.Background(), m.settings.Load())
}

func TestIdPErrorPermanent(t *testing.T) {
	tests := []struct {
		err  IdPError
		want bool
	}{
		{IdPError{Status: 400, Code: "invalid_grant"}, true},
		{IdPError{Status: 401, Code: "invalid_client"}, true},
		{IdPError{Status: 403}, true},
		{IdPError{Status: 404}, true},
		{IdPError{Status: 408}, false},
		{IdPError{Status: 429}, false},
		{IdPError{Status: 500}, false},
		{IdPError{Status: 502}, false},
		{IdPError{Status: 503}, false},
		{IdPError{Status: 500, Code: "invalid_client"}, true},
	}
	for _, tt := range tests {
		if got := tt.err.Permanent(); got != tt.want {
			t.Errorf("%+v Permanent() = %v, want %v", tt.err, got, tt.want)
		}
	}
}

// newTokenEndpoint returns an IdP that answers each request with the next
// (status, content type, body) in responses, repeating the last one.
func newTokenEndpoint(t *testing.T, responses ...[3]string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(calls.Add(1)) - 1
		if n >= len(responses) {
			n = len(responses) - 1
		}
		resp := responses[n]
		w.Header().Set("Content-Type", resp[1])
		status := map[string]int{"200": 200, "401": 401, "400": 400, "502": 502, "503": 503}[resp[0]]
		w.WriteHeader(status)
		w.Write([]byte(resp[2]))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

const okTokenJSON = `{"access_token":"tok-1","expires_in":3600}`

func loginConfig(url string, attempts int) *config.Config {
	return &config.Config{Login: &config.LoginConfig{
		URL:           url,
		GrantType:     "client_credentials",
		ClientID:      "id",
		ClientSecret:  "secret",
		RetryAttempts: attempts,
		RetryInterval: 1,
		Parameters:    map[string]string{"AccessToken": "access_token", "ExpiresIn": "expires_in"},
	}}
}

func TestLoginPermanentErrorNotRetried(t *testing.T) {
	idp, calls := newTokenEndpoint(t, [3]string{"401", "application/json",
		`{"error":"invalid_client","error_description":"Client authentication failed"}`})

	_, err := doLoginWithRetry(loginConfig(idp.URL, 3))
	if err == nil {
		t.Fatal("expected an error")
	}
	if calls.Load() != 1 {
		t.Errorf("token endpoint called %d times, want 1 (no retries)", calls.Load())
	}
	var idpErr *IdPError
	if !errors.As(err, &idpErr) || idpErr.Status != 401 || idpErr.Code != "invalid_client" {
		t.Fatalf("error = %v, want IdPError 401 invalid_client", err)
	}
	if !strings.Contains(err.Error(), "Client authentication failed") {
		t.Errorf("error %q does not include error_description", err)
	}
}

func TestLoginTransientErrorRetried(t *testing.T) {
	idp, calls := newTokenEndpoint(t,
		[3]string{"503", "text/html", "<html>down</html>"},
		[3]string{"200", "application/json", okTokenJSON})

	tok, err := doLoginWithRetry(loginConfig(idp.URL, 3))
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	if tok.AccessToken != "tok-1" || calls.Load() != 2 {
		t.Errorf("token %q after %d calls, want tok-1 after 2", tok.AccessToken, calls.Load())
	}
}

func TestLoginErrorMessages(t *testing.T) {
	t.Run("non-JSON error page", func(t *testing.T) {
		idp, _ := newTokenEndpoint(t, [3]string{"502", "text/html", "<html>Bad Gateway</html>"})
		_, err := doLogin(loginConfig(idp.URL, 1))
		if err == nil || !strings.Contains(err.Error(), "502 Bad Gateway") {
			t.Errorf("error = %v, want it to mention 502 Bad Gateway", err)
		}
	})
	t.Run("200 with HTML body", func(t *testing.T) {
		idp, _ := newTokenEndpoint(t, [3]string{"200", "text/html", "<html>login page</html>"})
		_, err := doLogin(loginConfig(idp.URL, 1))
		if err == nil || !strings.Contains(err.Error(), "not a JSON object") || !strings.Contains(err.Error(), "text/html") {
			t.Errorf("error = %v, want a not-JSON error naming the content type", err)
		}
	})
}

func TestLoginConfigErrorNotRetried(t *testing.T) {
	idp, calls := newTokenEndpoint(t, [3]string{"200", "application/json", okTokenJSON})
	cfg := loginConfig(idp.URL, 3)
	cfg.Login.ClientSecret = ""

	_, err := doLoginWithRetry(cfg)
	if !errors.Is(err, errLoginConfig) {
		t.Fatalf("error = %v, want errLoginConfig", err)
	}
	if calls.Load() != 0 {
		t.Errorf("token endpoint called %d times, want 0", calls.Load())
	}
}

func TestRefreshNonSuccessStatus(t *testing.T) {
	idp, _ := newTokenEndpoint(t, [3]string{"400", "application/json", `{"error":"invalid_grant"}`})
	cfg := &config.Config{Refresh: &config.RefreshConfig{URL: idp.URL, Method: "POST", Token: "r1", Data: "refresh_token=${REFRESHTOKEN}",
		Parameters: map[string]string{"AccessToken": "access_token"}}}
	_, err := doRefresh(cfg)
	var idpErr *IdPError
	if !errors.As(err, &idpErr) || idpErr.Code != "invalid_grant" {
		t.Errorf("error = %v, want IdPError invalid_grant", err)
	}
}

// ---------------- JWT bearer grant ----------------

func rsaPEM(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func ecPEM(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalECPrivateKey(key)
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}

// parseAssertion decodes the form body built by buildJWTAssertion and
// verifies the assertion with verifyKey.
func parseAssertion(t *testing.T, body string, verifyKey interface{}) (url.Values, *jwt.Token) {
	t.Helper()
	form, err := url.ParseQuery(body)
	if err != nil {
		t.Fatalf("body is not form encoded: %v", err)
	}
	tok, err := jwt.Parse(form.Get("assertion"), func(*jwt.Token) (interface{}, error) { return verifyKey, nil })
	if err != nil {
		t.Fatalf("assertion does not verify: %v", err)
	}
	return form, tok
}

func TestJWTAssertionHS256Default(t *testing.T) {
	lc := &config.LoginConfig{GrantType: "jwt", JWTKey: "shared", JWTIssuer: "me", JWTAudience: "idp"}
	body, err := buildJWTAssertion(lc)
	if err != nil {
		t.Fatal(err)
	}
	form, tok := parseAssertion(t, body, []byte("shared"))
	if form.Get("grant_type") != jwtBearerGrantType {
		t.Errorf("grant_type = %q, want %q", form.Get("grant_type"), jwtBearerGrantType)
	}
	if tok.Method.Alg() != "HS256" {
		t.Errorf("alg = %s, want HS256", tok.Method.Alg())
	}
	claims := tok.Claims.(jwt.MapClaims)
	for _, c := range []string{"iss", "aud", "iat", "nbf", "exp", "jti"} {
		if _, ok := claims[c]; !ok {
			t.Errorf("claim %s missing", c)
		}
	}
	if _, ok := claims["sub"]; ok {
		t.Error("sub set although jwt_subject is empty")
	}
}

func TestJWTAssertionJTIUnique(t *testing.T) {
	lc := &config.LoginConfig{JWTKey: "k", JWTIssuer: "me"}
	b1, _ := buildJWTAssertion(lc)
	b2, _ := buildJWTAssertion(lc)
	_, t1 := parseAssertion(t, b1, []byte("k"))
	_, t2 := parseAssertion(t, b2, []byte("k"))
	if t1.Claims.(jwt.MapClaims)["jti"] == t2.Claims.(jwt.MapClaims)["jti"] {
		t.Error("jti repeated across assertions")
	}
}

func TestJWTAssertionRS256AllClaims(t *testing.T) {
	key, pemKey := rsaPEM(t)
	lc := &config.LoginConfig{
		JWTAlgorithm: "rs256", JWTPrivateKey: pemKey, JWTIssuer: "svc@example.iam", JWTSubject: "user@example.com",
		JWTAudience: "https://oauth2.example.com/token", JWTScope: "read write", JWTKeyID: "key-1",
		JWTLifetime: 120, JWTClaims: map[string]interface{}{"tenant": "acme"}, JWTGrantType: "custom-grant",
	}
	body, err := buildJWTAssertion(lc)
	if err != nil {
		t.Fatal(err)
	}
	form, tok := parseAssertion(t, body, &key.PublicKey)
	if form.Get("grant_type") != "custom-grant" {
		t.Errorf("grant_type = %q, want the jwt_grant_type override", form.Get("grant_type"))
	}
	if tok.Method.Alg() != "RS256" || tok.Header["kid"] != "key-1" {
		t.Errorf("header = %v", tok.Header)
	}
	claims := tok.Claims.(jwt.MapClaims)
	want := map[string]interface{}{"iss": "svc@example.iam", "sub": "user@example.com",
		"aud": "https://oauth2.example.com/token", "scope": "read write", "tenant": "acme"}
	for k, v := range want {
		if claims[k] != v {
			t.Errorf("claim %s = %v, want %v", k, claims[k], v)
		}
	}
	if exp, iat := claims["exp"].(float64), claims["iat"].(float64); exp-iat != 120 {
		t.Errorf("lifetime = %v, want 120", exp-iat)
	}
}

func TestJWTAssertionKeySources(t *testing.T) {
	rsaKey, rsaPem := rsaPEM(t)
	ecKey, ecPem := ecPEM(t)
	file := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(file, []byte(rsaPem), 0600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		lc     config.LoginConfig
		verify interface{}
	}{
		{"PS256 inline", config.LoginConfig{JWTAlgorithm: "PS256", JWTPrivateKey: rsaPem}, &rsaKey.PublicKey},
		{"RS256 from file", config.LoginConfig{JWTAlgorithm: "RS256", JWTPrivateKeyFile: file}, &rsaKey.PublicKey},
		{"RS256 escaped newlines", config.LoginConfig{JWTAlgorithm: "RS256", JWTPrivateKey: strings.ReplaceAll(rsaPem, "\n", `\n`)}, &rsaKey.PublicKey},
		{"ES256 inline", config.LoginConfig{JWTAlgorithm: "ES256", JWTPrivateKey: ecPem}, &ecKey.PublicKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.lc.JWTIssuer = "me"
			body, err := buildJWTAssertion(&tt.lc)
			if err != nil {
				t.Fatal(err)
			}
			parseAssertion(t, body, tt.verify)
		})
	}
}

func TestJWTAssertionErrors(t *testing.T) {
	_, ecPem := ecPEM(t)
	tests := []struct {
		name    string
		lc      config.LoginConfig
		wantErr string
	}{
		{"missing issuer", config.LoginConfig{JWTKey: "k"}, "jwt_issuer"},
		{"HMAC missing key", config.LoginConfig{JWTIssuer: "me"}, "requires jwt_key"},
		{"RSA missing key", config.LoginConfig{JWTIssuer: "me", JWTAlgorithm: "RS256"}, "requires jwt_private_key"},
		{"RSA given EC key", config.LoginConfig{JWTIssuer: "me", JWTAlgorithm: "RS256", JWTPrivateKey: ecPem}, "not a valid RSA private key"},
		{"garbage key", config.LoginConfig{JWTIssuer: "me", JWTAlgorithm: "ES256", JWTPrivateKey: "not a key"}, "not a valid EC private key"},
		{"missing file", config.LoginConfig{JWTIssuer: "me", JWTAlgorithm: "RS256", JWTPrivateKeyFile: "/nonexistent/key.pem"}, "jwt_private_key_file"},
		{"unknown alg", config.LoginConfig{JWTIssuer: "me", JWTAlgorithm: "XY999", JWTKey: "k"}, "unsupported jwt_algorithm"},
		{"alg none", config.LoginConfig{JWTIssuer: "me", JWTAlgorithm: "none", JWTKey: "k"}, "unsupported jwt_algorithm"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := buildJWTAssertion(&tt.lc)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateLoginConfig(t *testing.T) {
	if err := ValidateLogin(&config.LoginConfig{GrantType: "jwt", JWTIssuer: "me", JWTAlgorithm: "RS256"}); err == nil {
		t.Error("expected an error for a JWT grant without a private key")
	}
	if err := ValidateLogin(&config.LoginConfig{GrantType: "client_credentials"}); err != nil {
		t.Errorf("non-JWT grant: %v", err)
	}
	if err := ValidateLogin(nil); err != nil {
		t.Errorf("nil login: %v", err)
	}
}

func TestBuildGrantRequest(t *testing.T) {
	basic := func(id, secret string) string {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(id+":"+secret))
	}
	tests := []struct {
		name     string
		lc       config.LoginConfig
		wantBody string
		wantAuth string
	}{
		{
			name:     "client credentials",
			lc:       config.LoginConfig{GrantType: "client_credentials", ClientID: "id", ClientSecret: "s&cret"},
			wantBody: "grant_type=client_credentials&client_id=id&client_secret=s%26cret",
		},
		{
			name: "client credentials with scope, audience and resource",
			lc: config.LoginConfig{GrantType: "client_credentials", ClientID: "id", ClientSecret: "secret",
				Scope: "api://app/.default", Audience: "https://api.example", Resource: "https://api.example/v1"},
			wantBody: "grant_type=client_credentials&client_id=id&client_secret=secret&scope=api%3A%2F%2Fapp%2F.default" +
				"&audience=https%3A%2F%2Fapi.example&resource=https%3A%2F%2Fapi.example%2Fv1",
		},
		{
			name:     "client credentials with basic auth",
			lc:       config.LoginConfig{GrantType: "client_credentials", ClientID: "my id", ClientSecret: "a:b", ClientAuth: config.ClientAuthBasic, Scope: "read write"},
			wantBody: "grant_type=client_credentials&scope=read+write",
			// RFC 6749 section 2.3.1: each part is form-encoded first.
			wantAuth: basic("my+id", "a%3Ab"),
		},
		{
			name:     "password with scope",
			lc:       config.LoginConfig{GrantType: "password", User: "u", Password: "p", ClientID: "id", ClientSecret: "s", Scope: "openid"},
			wantBody: "grant_type=password&username=u&password=p&client_id=id&client_secret=s&scope=openid",
		},
		{
			name:     "password with basic auth",
			lc:       config.LoginConfig{GrantType: "password", User: "u", Password: "p", ClientID: "id", ClientSecret: "s", ClientAuth: config.ClientAuthBasic},
			wantBody: "grant_type=password&username=u&password=p",
			wantAuth: basic("id", "s"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, headers, err := buildGrantRequest(&tt.lc)
			if err != nil {
				t.Fatal(err)
			}
			if body != tt.wantBody {
				t.Errorf("body = %q\nwant   %q", body, tt.wantBody)
			}
			if headers["Authorization"] != tt.wantAuth {
				t.Errorf("Authorization = %q, want %q", headers["Authorization"], tt.wantAuth)
			}
			if headers["Content-Type"] != "application/x-www-form-urlencoded" {
				t.Errorf("Content-Type = %q", headers["Content-Type"])
			}
		})
	}
}

func TestBuildGrantRequestJWTParameters(t *testing.T) {
	lc := &config.LoginConfig{GrantType: "jwt", JWTKey: "shared", JWTIssuer: "me", JWTScope: "claim-scope", Scope: "form-scope", Audience: "aud"}
	body, headers, err := buildGrantRequest(lc)
	if err != nil {
		t.Fatal(err)
	}
	form, tok := parseAssertion(t, body, []byte("shared"))
	if form.Get("scope") != "form-scope" || form.Get("audience") != "aud" {
		t.Errorf("form = %v, want scope and audience parameters", form)
	}
	if form.Has("client_id") || headers["Authorization"] != "" {
		t.Errorf("jwt grant sent client credentials: form %v, headers %v", form, headers)
	}
	if claims := tok.Claims.(jwt.MapClaims); claims["scope"] != "claim-scope" {
		t.Errorf("scope claim = %v, want claim-scope", claims["scope"])
	}
}

func TestBuildGrantRequestHeaders(t *testing.T) {
	lc := &config.LoginConfig{GrantType: "client_credentials", ClientID: "id", ClientSecret: "s", ClientAuth: config.ClientAuthBasic,
		Headers: map[string]string{"x-gateway-key": "k", "content-type": "text/plain", "authorization": "Bearer other"}}
	_, headers, err := buildGrantRequest(lc)
	if err != nil {
		t.Fatal(err)
	}
	if headers["X-Gateway-Key"] != "k" {
		t.Errorf("login.headers not sent: %v", headers)
	}
	if headers["Content-Type"] != "application/x-www-form-urlencoded" || !strings.HasPrefix(headers["Authorization"], "Basic ") {
		t.Errorf("relay headers did not take precedence: %v", headers)
	}
	if len(headers) != 3 {
		t.Errorf("headers = %v, want three after merging case variants", headers)
	}
}

func intPtr(n int) *int { return &n }

func TestExtractTokenExpiry(t *testing.T) {
	mapping := map[string]string{"AccessToken": "access_token", "ExpiresIn": "expires_in", "ExpiresAt": "expires_at"}
	future := time.Now().Add(time.Hour).Truncate(time.Second)
	tests := []struct {
		name string
		resp map[string]interface{}
		tc   config.TokenConfig
		want time.Duration // ExpiresAt - IssuedAt
	}{
		{"expires_in with default buffer", map[string]interface{}{"expires_in": 3600.0}, config.TokenConfig{}, 3590 * time.Second},
		{"expires_in as string", map[string]interface{}{"expires_in": "120"}, config.TokenConfig{}, 110 * time.Second},
		{"configured buffer", map[string]interface{}{"expires_in": 3600.0}, config.TokenConfig{ExpiryBuffer: intPtr(60)}, 3540 * time.Second},
		{"zero buffer", map[string]interface{}{"expires_in": 3600.0}, config.TokenConfig{ExpiryBuffer: intPtr(0)}, 3600 * time.Second},
		{"short lifetime keeps half", map[string]interface{}{"expires_in": 8.0}, config.TokenConfig{}, 4 * time.Second},
		{"no expiry uses default lifetime", map[string]interface{}{}, config.TokenConfig{}, 300 * time.Second},
		{"configured default lifetime", map[string]interface{}{}, config.TokenConfig{DefaultLifetime: 900}, 900 * time.Second},
		{"negative expires_in ignored", map[string]interface{}{"expires_in": -5.0}, config.TokenConfig{}, 300 * time.Second},
		{"huge expires_in ignored", map[string]interface{}{"expires_in": 1e300}, config.TokenConfig{}, 300 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := map[string]interface{}{"access_token": "abc"}
			for k, v := range tt.resp {
				resp[k] = v
			}
			tok, err := extractToken(resp, mapping, &tt.tc, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if got := tok.ExpiresAt.Sub(tok.IssuedAt); got.Round(time.Second) != tt.want {
				t.Errorf("lifetime = %v, want %v", got, tt.want)
			}
		})
	}

	t.Run("expires_at", func(t *testing.T) {
		for _, v := range []interface{}{float64(future.Unix()), future.Format(time.RFC3339)} {
			tok, err := extractToken(map[string]interface{}{"access_token": "abc", "expires_at": v}, mapping, &config.TokenConfig{}, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if want := future.Add(-10 * time.Second); !tok.ExpiresAt.Equal(want) {
				t.Errorf("expires_at %v: ExpiresAt = %v, want %v", v, tok.ExpiresAt, want)
			}
		}
	})
}

func TestRetryDelay(t *testing.T) {
	base, maxWait := 2*time.Second, 10*time.Second
	for n, ceiling := range map[int]time.Duration{1: 2 * time.Second, 2: 4 * time.Second, 3: 8 * time.Second, 4: 10 * time.Second, 50: 10 * time.Second} {
		for range 200 {
			d := retryDelay(base, maxWait, n)
			if d < ceiling/2 || d > ceiling {
				t.Fatalf("retryDelay(n=%d) = %v, want between %v and %v", n, d, ceiling/2, ceiling)
			}
		}
	}
}

func TestLoginRetryTiming(t *testing.T) {
	tests := []struct {
		lc            *config.LoginConfig
		base, maxWait time.Duration
	}{
		{nil, 5 * time.Second, 60 * time.Second},
		{&config.LoginConfig{}, 5 * time.Second, 60 * time.Second},
		{&config.LoginConfig{RetryInterval: 2, RetryMaxInterval: 30}, 2 * time.Second, 30 * time.Second},
		// An interval above the cap stays constant, as before backoff.
		{&config.LoginConfig{RetryInterval: 90}, 90 * time.Second, 90 * time.Second},
	}
	for _, tt := range tests {
		base, maxWait := loginRetryTiming(tt.lc)
		if base != tt.base || maxWait != tt.maxWait {
			t.Errorf("loginRetryTiming(%+v) = %v, %v; want %v, %v", tt.lc, base, maxWait, tt.base, tt.maxWait)
		}
	}
}

func TestRefreshDue(t *testing.T) {
	issued := time.Now()
	tok := &Token{IssuedAt: issued, ExpiresAt: issued.Add(100 * time.Second)}
	if got := refreshDue(tok, 0.8); !got.Equal(issued.Add(80 * time.Second)) {
		t.Errorf("refreshDue = %v after issue, want 80s", got.Sub(issued))
	}
	short := &Token{IssuedAt: issued, ExpiresAt: issued.Add(500 * time.Millisecond)}
	if got := refreshDue(short, 0.8); !got.Equal(issued.Add(minRefreshInterval)) {
		t.Errorf("short-lived token due %v after issue, want %v", got.Sub(issued), minRefreshInterval)
	}
	if got := refreshDue(nil, 0.8); time.Until(got) > 0 {
		t.Errorf("nil token due in %v, want now", time.Until(got))
	}
}

// startRefresher runs the background refresher until the test ends.
func startRefresher(t *testing.T, m *Manager) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		m.RunRefresher(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestBackgroundRefreshRenewsBeforeExpiry(t *testing.T) {
	idp, calls := newTokenEndpoint(t, [3]string{"200", "application/json", `{"access_token":"tok-bg","expires_in":2}`})
	cfg := loginConfig(idp.URL, 1)
	cfg.Token = config.TokenConfig{ExpiryBuffer: intPtr(0), RefreshAt: 0.5}

	m := testManager(cfg)
	first, err := m.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	startRefresher(t, m)

	// Due one second after issue, a second before the token expires.
	waitFor(t, "a background renewal", 3*time.Second, func() bool { return m.Current() != first })
	if tok := m.Current(); !time.Now().Before(tok.ExpiresAt) {
		t.Errorf("renewed token already expired at %v", tok.ExpiresAt)
	}
	if time.Now().After(first.ExpiresAt) {
		t.Errorf("token was renewed after it expired")
	}
	if n := calls.Load(); n < 2 {
		t.Errorf("IdP calls = %d, want at least 2", n)
	}
}

func TestBackgroundRefreshFailureKeepsToken(t *testing.T) {
	idp, calls := newTokenEndpoint(t,
		[3]string{"200", "application/json", `{"access_token":"tok-old","expires_in":60}`},
		[3]string{"503", "application/json", `{"error":"temporarily_unavailable"}`},
	)
	cfg := loginConfig(idp.URL, 1)
	cfg.Token = config.TokenConfig{ExpiryBuffer: intPtr(0), RefreshAt: 0.01} // due after the 1s minimum
	m := testManager(cfg)
	first, err := m.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	startRefresher(t, m)

	waitFor(t, "a failed background renewal", 3*time.Second, func() bool {
		_, lastErr := m.Status()
		return lastErr != nil
	})
	if m.Current() != first {
		t.Error("a failed renewal replaced the token")
	}
	got, err := m.Token(context.Background())
	if err != nil || got != first {
		t.Errorf("Token = %v, %v; want the still-valid token", got, err)
	}
	if calls.Load() != 2 {
		t.Errorf("IdP calls = %d, want 2 (the retry waits at least half a second)", calls.Load())
	}
}

func TestRenewUnlessRenewedSkipsReplacedToken(t *testing.T) {
	idp, calls := newTokenEndpoint(t, [3]string{"200", "application/json", okTokenJSON})
	m := testManager(loginConfig(idp.URL, 1))
	m.record(&Token{AccessToken: "newer", IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}, nil)
	if err := m.renewUnlessRenewed(context.Background(), &Token{AccessToken: "stale"}); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Errorf("renewed although another renewal replaced the token")
	}
}

// ---------------- Configuration ----------------

func TestTokenStringMasked(t *testing.T) {
	tok := &Token{AccessToken: "access-1234567890", RefreshToken: "refresh-1234567890", ExpiresAt: time.Unix(0, 0).UTC()}
	for _, s := range []string{tok.String(), fmt.Sprintf("%+v", tok), fmt.Sprintf("%v", tok)} {
		if strings.Contains(s, "access-1234567890") || strings.Contains(s, "refresh-1234567890") {
			t.Errorf("token leaked in %q", s)
		}
	}
}

func FuzzExtractToken(f *testing.F) {
	for _, seed := range []string{
		`{"access_token":"abc","expires_in":3600}`, `{"access_token":"abc","expires_in":"60"}`,
		`{"access_token":"abc","expires_in":-1}`, `{"access_token":"abc","expires_in":1e308}`,
		`{"access_token":"abc","expires_in":"NaN"}`, `{"access_token":"abc","expires_at":"2030-01-01T00:00:00Z"}`,
		`{"access_token":"abc","expires_at":-9e18}`, `{"access_token":7}`, `{"access_token":null}`, `{}`,
	} {
		f.Add([]byte(seed))
	}
	mapping := map[string]string{"AccessToken": "access_token", "RefreshToken": "refresh_token",
		"ExpiresIn": "expires_in", "ExpiresAt": "expires_at"}
	f.Fuzz(func(t *testing.T, data []byte) {
		var resp map[string]interface{}
		if json.Unmarshal(data, &resp) != nil {
			return
		}
		tok, err := extractToken(resp, mapping, &config.TokenConfig{}, time.Now())
		if err != nil {
			return
		}
		if tok.IssuedAt.IsZero() || tok.ExpiresAt.IsZero() {
			t.Fatalf("token from %s has no issue or expiry time: %+v", data, tok)
		}
		if _, ok := resp["expires_at"]; !ok && tok.ExpiresAt.Before(tok.IssuedAt) {
			t.Fatalf("token from %s expires before it was issued", data)
		}
	})
}
