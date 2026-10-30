// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package token

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"oauth2relay.com/oauth2relay/v2/config"
)

// exchangeEndpoint is a token endpoint that records the last request and
// answers with status and body.
func exchangeEndpoint(t *testing.T, status int, body string) (*httptest.Server, *http.Request, *url.Values) {
	t.Helper()
	var gotReq http.Request
	var gotForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		gotForm, _ = url.ParseQuery(string(raw))
		gotReq = *r
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv, &gotReq, &gotForm
}

const exchangeOK = `{"access_token":"downstream-token-123","issued_token_type":"urn:ietf:params:oauth:token-type:access_token",
	"token_type":"Bearer","expires_in":300,"scope":"crm:read"}`

func TestExchange(t *testing.T) {
	srv, gotReq, gotForm := exchangeEndpoint(t, http.StatusOK, exchangeOK)
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	obs := &recordingObserver{}
	e := &Exchanger{Observer: obs, Now: func() time.Time { return now }}

	res, err := e.Exchange(context.Background(), &ExchangeRequest{
		URL:          srv.URL,
		ClientID:     "mcp-server",
		ClientSecret: "s3cret&=",
		SubjectToken: "user-jwt-abc",
		Audience:     []string{"https://crm.example/api", "https://billing.example"},
		Resource:     []string{"https://crm.example/api/v2"},
		Scope:        []string{"crm:read", "customer:profile"},
		Headers:      map[string]string{"x-tenant": "t1", "content-type": "text/plain"},
	})
	if err != nil {
		t.Fatal(err)
	}

	f := *gotForm
	for key, want := range map[string]string{
		"grant_type":         GrantTypeTokenExchange,
		"subject_token":      "user-jwt-abc",
		"subject_token_type": TokenTypeAccessToken,
		"scope":              "crm:read customer:profile",
		"client_id":          "mcp-server",
		"client_secret":      "s3cret&=",
	} {
		if got := f.Get(key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	if got := f["audience"]; len(got) != 2 || got[0] != "https://crm.example/api" || got[1] != "https://billing.example" {
		t.Errorf("audience = %q", got)
	}
	if got := f["resource"]; len(got) != 1 || got[0] != "https://crm.example/api/v2" {
		t.Errorf("resource = %q", got)
	}
	for _, absent := range []string{"actor_token", "actor_token_type", "requested_token_type"} {
		if f.Has(absent) {
			t.Errorf("%s sent but not requested", absent)
		}
	}
	if gotReq.Method != http.MethodPost || gotReq.Header.Get("Content-Type") != "application/x-www-form-urlencoded" ||
		gotReq.Header.Get("X-Tenant") != "t1" || gotReq.Header.Get("Authorization") != "" {
		t.Errorf("request %s with headers %v", gotReq.Method, gotReq.Header)
	}

	if res.AccessToken != "downstream-token-123" || res.TokenType != "Bearer" || res.Scope != "crm:read" ||
		res.IssuedTokenType != TokenTypeAccessToken || res.RefreshToken != "" {
		t.Errorf("result %+v", res)
	}
	if !res.IssuedAt.Equal(now) || !res.ExpiresAt.Equal(now.Add(300*time.Second)) {
		t.Errorf("issued %v expires %v; want %v and 300s later, without a buffer", res.IssuedAt, res.ExpiresAt, now)
	}
	if strings.Contains(res.String(), "downstream-token-123") {
		t.Errorf("String() shows the token: %s", res.String())
	}
	if obs.requests != 1 || len(obs.renewals) != 0 {
		t.Errorf("observed %d requests and renewals %v; want 1 and none", obs.requests, obs.renewals)
	}
}

func TestExchangeBasicAuthAndActor(t *testing.T) {
	srv, gotReq, gotForm := exchangeEndpoint(t, http.StatusOK, `{"access_token":"tok","token_type":"N_A"}`)
	res, err := (&Exchanger{}).Exchange(context.Background(), &ExchangeRequest{
		URL:                srv.URL,
		ClientID:           "id:with@chars",
		ClientSecret:       "p&ss word",
		ClientAuth:         config.ClientAuthBasic,
		SubjectToken:       "id-token",
		SubjectTokenType:   TokenTypeIDToken,
		ActorToken:         "actor",
		RequestedTokenType: TokenTypeJWT,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("id%3Awith%40chars:p%26ss+word"))
	if got := gotReq.Header.Get("Authorization"); got != want {
		t.Errorf("Authorization = %q, want %q", got, want)
	}
	f := *gotForm
	if f.Has("client_id") || f.Has("client_secret") {
		t.Error("client credentials sent in the body as well as the header")
	}
	if f.Get("subject_token_type") != TokenTypeIDToken || f.Get("actor_token") != "actor" ||
		f.Get("actor_token_type") != TokenTypeAccessToken || f.Get("requested_token_type") != TokenTypeJWT {
		t.Errorf("form %v", f)
	}
	if !res.ExpiresAt.IsZero() {
		t.Errorf("ExpiresAt = %v without expires_in, want zero", res.ExpiresAt)
	}
}

func TestExchangeErrors(t *testing.T) {
	srv, _, _ := exchangeEndpoint(t, http.StatusBadRequest,
		`{"error":"invalid_target","error_description":"unknown audience"}`)
	_, err := (&Exchanger{}).Exchange(context.Background(), &ExchangeRequest{URL: srv.URL, SubjectToken: "x"})
	var idpErr *IdPError
	if !errors.As(err, &idpErr) || idpErr.Code != "invalid_target" || !IsPermanent(err) {
		t.Errorf("400 invalid_target: %v (permanent %v)", err, IsPermanent(err))
	}

	srv, _, _ = exchangeEndpoint(t, http.StatusServiceUnavailable, `busy`)
	_, err = (&Exchanger{}).Exchange(context.Background(), &ExchangeRequest{URL: srv.URL, SubjectToken: "x"})
	if !errors.As(err, &idpErr) || IsPermanent(err) {
		t.Errorf("503: %v (permanent %v), want a transient IdPError", err, IsPermanent(err))
	}

	srv, _, _ = exchangeEndpoint(t, http.StatusOK, `{"token_type":"Bearer"}`)
	if _, err = (&Exchanger{}).Exchange(context.Background(), &ExchangeRequest{URL: srv.URL, SubjectToken: "x"}); err == nil ||
		!strings.Contains(err.Error(), "no access_token") {
		t.Errorf("response without access_token: %v", err)
	}

	for name, req := range map[string]*ExchangeRequest{
		"no URL":           {SubjectToken: "x"},
		"no subject":       {URL: srv.URL},
		"bad client_auth":  {URL: srv.URL, SubjectToken: "x", ClientAuth: "jwt"},
		"basic without id": {URL: srv.URL, SubjectToken: "x", ClientAuth: config.ClientAuthBasic},
		"bad URL":          {URL: "://nope", SubjectToken: "x"},
	} {
		_, err := (&Exchanger{}).Exchange(context.Background(), req)
		if err == nil || !IsPermanent(err) {
			t.Errorf("%s: %v, want a permanent error", name, err)
		}
	}
}

func TestExchangeContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (&Exchanger{}).Exchange(ctx, &ExchangeRequest{URL: "http://idp.invalid/token", SubjectToken: "x"})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}
