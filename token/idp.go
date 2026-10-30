// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package token

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"oauth2relay.com/oauth2relay/v2/config"
)

// IdPError describes a token endpoint that answered with a non-2xx status.
// Code and Description come from the RFC 6749 section 5.2 error response
// when the body contains one.
type IdPError struct {
	Status      int
	Code        string
	Description string
}

func (e *IdPError) Error() string {
	msg := fmt.Sprintf("token endpoint returned %d %s", e.Status, http.StatusText(e.Status))
	if e.Code != "" {
		msg += ": " + e.Code
		if e.Description != "" {
			msg += " (" + e.Description + ")"
		}
	}
	return msg
}

// permanentOAuthErrors are RFC 6749 error codes that retrying cannot fix.
var permanentOAuthErrors = map[string]bool{
	"invalid_request":        true,
	"invalid_client":         true,
	"invalid_grant":          true,
	"unauthorized_client":    true,
	"unsupported_grant_type": true,
	"invalid_scope":          true,
}

// Permanent reports whether retrying the same request is pointless: the
// IdP rejected it with a 4xx status (other than 408 Request Timeout or
// 429 Too Many Requests) or with a permanent OAuth error code.
func (e *IdPError) Permanent() bool {
	if permanentOAuthErrors[e.Code] {
		return true
	}
	return e.Status >= 400 && e.Status < 500 &&
		e.Status != http.StatusRequestTimeout && e.Status != http.StatusTooManyRequests
}

// errRefreshUnavailable marks a refresh that was not attempted because there
// is no refresh configuration or no refresh token.
var errRefreshUnavailable = errors.New("refresh not possible")

// errLoginConfig marks login failures caused by the configuration (for
// example a missing client_id or an unreadable JWT key). They are not retried.
var errLoginConfig = errors.New("invalid login configuration")

// IsPermanent reports whether a login or exchange error cannot be fixed
// by retrying: the identity provider rejected the request, or the login
// configuration or ExchangeRequest is invalid.
func IsPermanent(err error) bool {
	var idpErr *IdPError
	if errors.As(err, &idpErr) {
		return idpErr.Permanent()
	}
	return errors.Is(err, errLoginConfig) || errors.Is(err, errExchangeRequest)
}

// doTokenRequest sends a login or refresh request and returns the decoded
// JSON response. A non-2xx status is returned as an *IdPError.
func (m *Manager) doTokenRequest(req *http.Request, timeout int, kind string) (map[string]interface{}, error) {
	if timeout <= 0 {
		timeout = config.DefaultIdPTimeout
	}
	return postTokenRequest(m.transport, m.observer, req, time.Duration(timeout)*time.Second, kind)
}

// postTokenRequest sends a request to a token endpoint and returns the
// decoded JSON response. A non-2xx status is returned as an *IdPError.
// kind names the request in logs and metrics.
func postTokenRequest(transport http.RoundTripper, observer Observer, req *http.Request, timeout time.Duration, kind string) (map[string]interface{}, error) {
	start := time.Now()
	defer func() {
		observer.ObserveIdPRequest(strings.ToLower(kind), time.Since(start))
	}()
	client := &http.Client{Transport: transport, Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, config.MaxIdPResponseBytes))
	if err != nil {
		return nil, err
	}
	slog.Debug(kind+" response", "status", resp.StatusCode, "body", string(respBytes))

	var respMap map[string]interface{}
	jsonErr := json.Unmarshal(respBytes, &respMap)

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		idpErr := &IdPError{Status: resp.StatusCode}
		if jsonErr == nil {
			idpErr.Code, _ = respMap["error"].(string)
			idpErr.Description, _ = respMap["error_description"].(string)
		}
		return nil, idpErr
	}
	if jsonErr != nil {
		return nil, fmt.Errorf("token endpoint returned %d with a body that is not a JSON object (Content-Type %q, %d bytes)",
			resp.StatusCode, resp.Header.Get("Content-Type"), len(respBytes))
	}
	return respMap, nil
}
