// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package token

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"oauth2relay.com/oauth2relay/v2/config"
)

// OAuth 2.0 Token Exchange (RFC 8693) identifiers. They name token types,
// they are not credentials.
//
//nolint:gosec // G101: URNs, not credentials
const (
	GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"

	TokenTypeAccessToken  = "urn:ietf:params:oauth:token-type:access_token"
	TokenTypeRefreshToken = "urn:ietf:params:oauth:token-type:refresh_token"
	TokenTypeIDToken      = "urn:ietf:params:oauth:token-type:id_token"
	TokenTypeJWT          = "urn:ietf:params:oauth:token-type:jwt"
)

// errExchangeRequest marks an ExchangeRequest that is incomplete. It is
// not sent, and IsPermanent reports true for it.
var errExchangeRequest = errors.New("invalid token exchange request")

// ExchangeRequest is an RFC 8693 token exchange: a subject token (for
// example the caller's access token) is traded for a token for another
// audience or resource.
type ExchangeRequest struct {
	// URL is the token endpoint.
	URL string

	// ClientID and ClientSecret authenticate the client, as ClientAuth
	// says: config.ClientAuthPost (the default) sends them in the body,
	// config.ClientAuthBasic in an Authorization header. Both may be empty
	// if the endpoint does not authenticate clients.
	ClientID     string
	ClientSecret string
	ClientAuth   string

	// SubjectToken is required. SubjectTokenType defaults to
	// TokenTypeAccessToken.
	SubjectToken     string
	SubjectTokenType string

	// ActorToken is optional (delegation). ActorTokenType is required with
	// it and defaults to TokenTypeAccessToken.
	ActorToken     string
	ActorTokenType string

	// RequestedTokenType, Audience, Resource and Scope are optional. Each
	// Audience and Resource value is sent as a separate parameter; Scope
	// values are joined with spaces.
	RequestedTokenType string
	Audience           []string
	Resource           []string
	Scope              []string

	// Headers are added to the request. Content-Type, and Authorization
	// with ClientAuthBasic, are set by Exchange.
	Headers map[string]string

	// Timeout limits the request (default config.DefaultIdPTimeout
	// seconds). The context passed to Exchange can shorten it.
	Timeout time.Duration
}

// ExchangeResult is the token endpoint's answer to an ExchangeRequest.
//
// Token.ExpiresAt is the expiry the endpoint gave in expires_in, without
// any buffer; it is zero if the response had no expires_in. The caller
// decides how long to cache the token.
type ExchangeResult struct {
	Token
	IssuedTokenType string // issued_token_type
	TokenType       string // token_type, for example "Bearer" or "N_A"
	Scope           string // scope, if the endpoint returned one
}

// Exchanger sends RFC 8693 token exchange requests. It holds no tokens:
// each call goes to the token endpoint, and caching the result is up to
// the caller. The zero Exchanger is ready to use and safe for concurrent
// use.
//
// Exchanged tokens are not added to the redaction registry, which only
// keeps the most recent few; the access_token and refresh_token fields are
// masked in log output by name instead.
type Exchanger struct {
	// Transport sends the requests (default http.DefaultTransport).
	Transport http.RoundTripper
	// Observer receives the duration of each request, with kind
	// "exchange" (default none).
	Observer Observer
	// Now returns the current time (default time.Now).
	Now func() time.Time
}

// Exchange sends req to the token endpoint. A non-2xx answer is returned
// as an *IdPError; IsPermanent says whether retrying could help.
func (e *Exchanger) Exchange(ctx context.Context, req *ExchangeRequest) (*ExchangeResult, error) {
	body, headers, err := buildExchangeRequest(req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, req.URL, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errExchangeRequest, err)
	}
	for k, v := range headers {
		httpReq.Header.Set(k, v)
	}

	transport, observer, now := e.Transport, e.Observer, e.Now
	if transport == nil {
		transport = http.DefaultTransport
	}
	if observer == nil {
		observer = nopObserver{}
	}
	if now == nil {
		now = time.Now
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = config.DefaultIdPTimeout * time.Second
	}

	issuedAt := now()
	respMap, err := postTokenRequest(transport, observer, httpReq, timeout, "Exchange")
	if err != nil {
		return nil, err
	}
	return exchangeResult(respMap, issuedAt)
}

// buildExchangeRequest returns the form body and headers for req.
func buildExchangeRequest(req *ExchangeRequest) (string, map[string]string, error) {
	switch {
	case req.URL == "":
		return "", nil, fmt.Errorf("%w: URL is required", errExchangeRequest)
	case req.SubjectToken == "":
		return "", nil, fmt.Errorf("%w: SubjectToken is required", errExchangeRequest)
	case req.ClientAuth != "" && req.ClientAuth != config.ClientAuthPost && req.ClientAuth != config.ClientAuthBasic:
		return "", nil, fmt.Errorf("%w: ClientAuth must be %q or %q", errExchangeRequest, config.ClientAuthPost, config.ClientAuthBasic)
	case req.ClientAuth == config.ClientAuthBasic && req.ClientID == "":
		return "", nil, fmt.Errorf("%w: ClientAuth %q requires ClientID", errExchangeRequest, config.ClientAuthBasic)
	}

	var body formBody
	body.add("grant_type", GrantTypeTokenExchange)
	for _, r := range req.Resource {
		body.add("resource", r)
	}
	for _, a := range req.Audience {
		body.add("audience", a)
	}
	body.add("scope", strings.Join(req.Scope, " "))
	body.add("requested_token_type", req.RequestedTokenType)
	body.add("subject_token", req.SubjectToken)
	body.add("subject_token_type", defaultTokenType(req.SubjectTokenType))
	if req.ActorToken != "" {
		body.add("actor_token", req.ActorToken)
		body.add("actor_token_type", defaultTokenType(req.ActorTokenType))
	}

	headers := make(map[string]string, len(req.Headers)+2)
	for k, v := range req.Headers {
		headers[http.CanonicalHeaderKey(k)] = v
	}
	headers["Content-Type"] = "application/x-www-form-urlencoded"
	if req.ClientAuth == config.ClientAuthBasic {
		// RFC 6749 section 2.3.1: form-encode each part before base64.
		creds := url.QueryEscape(req.ClientID) + ":" + url.QueryEscape(req.ClientSecret)
		headers["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(creds))
	} else {
		body.add("client_id", req.ClientID)
		body.add("client_secret", req.ClientSecret)
	}
	return body.String(), headers, nil
}

func defaultTokenType(t string) string {
	if t == "" {
		return TokenTypeAccessToken
	}
	return t
}

// exchangeResult reads an RFC 8693 section 2.2.1 response.
func exchangeResult(respMap map[string]interface{}, issuedAt time.Time) (*ExchangeResult, error) {
	accessToken, _ := respMap["access_token"].(string)
	if accessToken == "" {
		return nil, fmt.Errorf("token exchange response has no access_token")
	}
	res := &ExchangeResult{Token: Token{AccessToken: accessToken, IssuedAt: issuedAt}}
	res.RefreshToken, _ = respMap["refresh_token"].(string)
	res.IssuedTokenType, _ = respMap["issued_token_type"].(string)
	res.TokenType, _ = respMap["token_type"].(string)
	res.Scope, _ = respMap["scope"].(string)
	res.ExpiresAt = responseExpiry(respMap, map[string]string{"ExpiresIn": "expires_in"}, issuedAt)
	return res, nil
}
