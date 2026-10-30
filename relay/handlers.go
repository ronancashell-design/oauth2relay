// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"oauth2relay.com/oauth2relay/v2/config"
	"oauth2relay.com/oauth2relay/v2/egress"
	"oauth2relay.com/oauth2relay/v2/internal/util"
	"oauth2relay.com/oauth2relay/v2/token"
)

// relayHandler is the main HTTP handler. For every incoming request it will:
//  1. Ensure a valid access token is available (or use a fixed token)
//  2. Resolve the target URL according to the relay mode (single,
//     passthrough or parameter) and build the outbound request by performing
//     substitutions in the headers and data.
//  3. Map incoming parameters (or built‐in values such as client IP and headers)
//     to outbound query parameters.
//  4. Send the request and relay the response back to the client.
func (s *Server) relayHandler(rw http.ResponseWriter, r *http.Request) {
	w := &statusWriter{ResponseWriter: rw}
	ri := s.newRequestInfo(w, r)
	route, routeErr := s.router.Route(r)
	cfg := s.live.Load()
	if routeErr == nil {
		cfg = route.Config
	}
	defer ri.finish(w, cfg)
	if routeErr != nil {
		if errors.Is(routeErr, ErrNoRoute) {
			ri.fail(w, http.StatusNotFound, "no_route", "No route matches the request", nil)
		} else {
			ri.fail(w, http.StatusInternalServerError, "internal_error", "The relay is misconfigured", routeErr)
		}
		return
	}

	// API Key Authentication
	if cfg.APIKey != "" {
		if !apiKeyMatches(r.Header.Get(config.APIKeyHeader), cfg.APIKey) {
			s.metrics.inboundAuthFailures.Inc()
			ri.fail(w, http.StatusUnauthorized, "unauthorized", "Missing or invalid API key", nil)
			return
		}
	}

	maxBody := cfg.MaxRequestBodyBytes
	if maxBody <= 0 {
		maxBody = config.DefaultMaxRequestBodyBytes
	}
	r.Body = http.MaxBytesReader(rw, r.Body, maxBody)

	// Determine which token to use (fixed token vs access token).
	var tokenVal string
	if cfg.Relay.FixedToken != "" {
		tokenVal = cfg.Relay.FixedToken
	} else if route.Tokens == nil {
		ri.fail(w, http.StatusInternalServerError, "internal_error", "The relay is misconfigured",
			errors.New("the route has neither a token source nor a fixed token"))
		return
	} else {
		tok, err := routeToken(r, route)
		if err != nil && r.Context().Err() != nil {
			ri.log.Debug("Request cancelled by the client while waiting for a token")
			return
		}
		if errors.Is(err, token.ErrWaitTimeout) {
			ri.fail(w, http.StatusServiceUnavailable, "token_unavailable",
				"Timed out waiting for an access token; try again later", err)
			return
		}
		if err != nil && !token.IsPermanent(err) {
			// The identity provider is unreachable or failing; a retry
			// may succeed once it recovers.
			ri.fail(w, http.StatusServiceUnavailable, "token_unavailable",
				"Could not obtain an access token; try again later", err)
			return
		}
		if err != nil {
			ri.fail(w, http.StatusInternalServerError, "token_error", "Could not obtain an access token", err)
			return
		}
		tokenVal = tok.AccessToken
	}

	// Build substitution variables for relay including ${IP}.
	vars := map[string]string{
		"ACCESSTOKEN": tokenVal,
		"FIXEDTOKEN":  cfg.Relay.FixedToken,
		"IP":          clientIP(r, cfg.TrustedNetworks()),
	}

	method := relayMethod(cfg.Relay.Method, r.Method)
	dataStr := util.Substitute(cfg.Relay.Data, vars)

	// Create a new map for substituted relay headers.
	subHeaders := make(map[string]string, len(cfg.Relay.Headers))
	for k, v := range cfg.Relay.Headers {
		subHeaders[k] = util.Substitute(v, vars)
	}

	// Parse the incoming parameters up front: in parameter mode the target URL
	// may arrive in the query string, a form body or a JSON body.
	query := r.URL.Query()
	ct := r.Header.Get("Content-Type")
	hasBody := method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch
	isForm := hasBody && strings.Contains(ct, "application/x-www-form-urlencoded")
	isJSON := hasBody && !isForm && strings.Contains(ct, "application/json")

	var formVals url.Values
	var jsonBody map[string]interface{}
	if isForm {
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			writeBodyReadError(w, ri, err)
			return
		}
		formVals, err = url.ParseQuery(string(bodyBytes))
		if err != nil {
			formVals = url.Values{}
		}
	} else if isJSON {
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			writeBodyReadError(w, ri, err)
			return
		}
		if len(bodyBytes) == 0 || json.Unmarshal(bodyBytes, &jsonBody) != nil || jsonBody == nil {
			jsonBody = make(map[string]interface{})
		}
	}

	// Work out where the request is going.
	var target string
	var targetFound bool
	if cfg.Relay.Mode == config.RelayModeParameter {
		target, targetFound = takeTargetParam(cfg.Relay.URLParam, query, formVals, jsonBody)
	} else {
		// Placeholders are only substituted in the configured URL, never in a
		// caller-supplied one.
		target, targetFound = util.Substitute(cfg.Relay.URL, vars), true
	}
	urlObj, status, err := resolveTargetURL(&cfg.Relay, target, targetFound, r.URL.Path)
	if err != nil {
		switch status {
		case http.StatusBadRequest:
			ri.fail(w, status, "bad_request", err.Error(), nil)
		case http.StatusForbidden:
			ri.fail(w, status, "forbidden", err.Error(), nil)
		default:
			ri.fail(w, http.StatusInternalServerError, "internal_error", "The relay is misconfigured", err)
		}
		return
	}
	ri.upstreamHost = upstreamLabel(&cfg.Relay, urlObj)

	var bodyReader io.Reader
	var streamBody bool
	if isForm {
		// Merge in query parameters from the URL.
		for key, vals := range query {
			for _, v := range vals {
				formVals.Add(key, v)
			}
		}
		// Merge in additional parameters from configuration.
		for outParam, configValue := range cfg.Relay.Parameters {
			formVals.Set(outParam, util.Substitute(configValue, vars))
		}
		mergedForm := formVals.Encode()
		bodyReader = bytes.NewBuffer([]byte(mergedForm))
		subHeaders["Content-Type"] = "application/x-www-form-urlencoded"
	} else if isJSON {
		// Merge in query parameters from the URL.
		for key, vals := range query {
			if len(vals) > 0 {
				jsonBody[key] = vals[0]
			}
		}
		// Merge in additional parameters from configuration.
		for outParam, configValue := range cfg.Relay.Parameters {
			jsonBody[outParam] = util.Substitute(configValue, vars)
		}
		mergedJSON, err := json.Marshal(jsonBody)
		if err != nil {
			ri.fail(w, http.StatusInternalServerError, "internal_error", "Could not build the relayed request", err)
			return
		}
		bodyReader = bytes.NewBuffer(mergedJSON)
		subHeaders["Content-Type"] = "application/json"
	} else {
		// Start with any query string on the target URL, then the incoming
		// query parameters, then the configured parameters (whose values may
		// contain placeholders).
		q := urlObj.Query()
		for key, vals := range query {
			q[key] = vals
		}
		for outParam, configValue := range cfg.Relay.Parameters {
			q.Set(outParam, util.Substitute(configValue, vars))
		}
		urlObj.RawQuery = q.Encode()

		// GET and HEAD carry no body. Other methods send the configured data,
		// or stream the caller's body through unchanged.
		if method != http.MethodGet && method != http.MethodHead {
			if dataStr != "" {
				bodyReader = strings.NewReader(dataStr)
			} else if r.ContentLength != 0 {
				bodyReader = r.Body
				streamBody = true
				if _, set := subHeaders["Content-Type"]; !set && ct != "" {
					subHeaders["Content-Type"] = ct
				}
			}
		}
	}

	ri.log.Debug("Relaying request",
		"mode", cfg.Relay.Mode,
		"url", urlObj.String(),
		"method", method,
		"headers", subHeaders)

	// Create outbound request.
	// The outbound request is tied to the incoming one, so it is cancelled
	// if the caller disconnects.
	outReq, err := http.NewRequestWithContext(r.Context(), method, urlObj.String(), bodyReader) //nolint:gosec // G704: see resolveTargetURL
	if err != nil {
		ri.fail(w, http.StatusInternalServerError, "internal_error", "Could not build the relayed request", err)
		return
	}
	if streamBody {
		// -1 (unknown length) makes the client send the body chunked.
		outReq.ContentLength = r.ContentLength
	}
	for k, v := range subHeaders {
		outReq.Header.Set(k, v)
	}
	if cfg.Relay.PushHeaders {
		pushIncomingHeaders(outReq.Header, r.Header, &cfg.Relay)
	}
	// Pass the request ID on so upstream logs can be correlated, unless
	// relay.headers sets the header itself or strip_headers lists it.
	if !hasHeader(subHeaders, requestIDHeader) && !containsFold(cfg.Relay.StripHeaders, requestIDHeader) {
		outReq.Header.Set(requestIDHeader, ri.ID)
	}

	// The target is fixed by config, or in parameter mode checked against
	// allowed_hosts by resolveTargetURL.
	resp, err := s.newRelayClient(&cfg.Relay).Do(outReq) //nolint:gosec // G704: relaying is the purpose
	if err != nil {
		if r.Context().Err() != nil {
			ri.log.Debug("Request cancelled by the client")
			return
		}
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			// The streamed request body went over max_request_body_bytes.
			writeBodyReadError(w, ri, err)
			return
		}
		if isTimeout(err) {
			ri.fail(w, http.StatusGatewayTimeout, "upstream_timeout", "The upstream service did not respond in time", err)
			return
		}
		if errors.Is(err, egress.ErrBlocked) {
			ri.fail(w, http.StatusForbidden, "destination_blocked", "The target address is not allowed", err)
			return
		}
		if errors.Is(err, errRedirectBlocked) {
			ri.fail(w, http.StatusBadGateway, "redirect_blocked", "The upstream service redirected to a location that is not allowed", err)
			return
		}
		ri.fail(w, http.StatusBadGateway, "upstream_error", "The upstream request failed", err)
		return
	}
	defer resp.Body.Close()

	removeHopByHop(resp.Header)
	for k, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil && r.Context().Err() == nil {
		// The status line has been sent, so the caller sees a truncated body.
		ri.log.Warn("Copying the upstream response failed", "error", err)
	}
}

// takeTargetParam looks for the parameter-mode target URL in the incoming
// query string, form body and JSON body (in that order) and removes it from
// all of them so that it is never sent on to the external endpoint.
func takeTargetParam(name string, query, form url.Values, jsonBody map[string]interface{}) (string, bool) {
	var target string
	found := false
	if vals, ok := query[name]; ok {
		if len(vals) > 0 {
			target, found = vals[0], true
		}
		delete(query, name)
	}
	if vals, ok := form[name]; ok {
		if !found && len(vals) > 0 {
			target, found = vals[0], true
		}
		delete(form, name)
	}
	if v, ok := jsonBody[name]; ok {
		if !found {
			// A non-string value is treated as an empty (invalid) URL.
			target, _ = v.(string)
			found = true
		}
		delete(jsonBody, name)
	}
	return target, found
}

// resolveTargetURL returns the outbound URL for the configured relay mode,
// or an HTTP status and error explaining why the request was rejected.
//   - single:      target is used as-is; the incoming path is ignored.
//   - passthrough: the incoming path is appended to target.
//   - parameter:   target came from the caller and must be an absolute
//     http(s) URL whose host is in allowed_hosts.
func resolveTargetURL(rc *config.RelayConfig, target string, found bool, incomingPath string) (*url.URL, int, error) {
	if rc.Mode != config.RelayModeParameter {
		urlObj, err := url.Parse(target)
		if err != nil {
			return nil, http.StatusInternalServerError, fmt.Errorf("invalid relay URL: %w", err)
		}
		if rc.Mode == config.RelayModePassthrough {
			urlObj.Path = path.Join(urlObj.Path, incomingPath)
		}
		return urlObj, 0, nil
	}

	if !found || strings.TrimSpace(target) == "" {
		return nil, http.StatusBadRequest, fmt.Errorf("missing required parameter %q", rc.URLParam)
	}
	urlObj, err := url.Parse(strings.TrimSpace(target))
	if err != nil {
		return nil, http.StatusBadRequest, fmt.Errorf("parameter %q is not a valid URL", rc.URLParam)
	}
	if urlObj.Scheme != "http" && urlObj.Scheme != "https" {
		return nil, http.StatusBadRequest, fmt.Errorf("parameter %q must be an absolute http or https URL", rc.URLParam)
	}
	if urlObj.Hostname() == "" || urlObj.User != nil {
		return nil, http.StatusBadRequest, fmt.Errorf("parameter %q must be an absolute http or https URL", rc.URLParam)
	}
	if !hostAllowed(urlObj, rc.AllowedHosts) {
		return nil, http.StatusForbidden, fmt.Errorf("host %q is not in relay.allowed_hosts", urlObj.Host)
	}
	urlObj.Fragment = ""
	return urlObj, 0, nil
}

// hostAllowed reports whether u's host matches an allowed_hosts entry
// (see egress.MatchHost).
func hostAllowed(u *url.URL, allowed []string) bool {
	_, ok := egress.MatchHost(u, allowed)
	return ok
}

// upstreamLabel is the upstream_host metrics label for a relayed request:
// the matching allowed_hosts entry in parameter mode, which keeps the number
// of label values bounded, and the target host otherwise.
func upstreamLabel(rc *config.RelayConfig, u *url.URL) string {
	if rc.Mode == config.RelayModeParameter {
		entry, _ := egress.MatchHost(u, rc.AllowedHosts)
		return entry
	}
	return strings.ToLower(u.Host)
}

// writeBodyReadError reports a failure to read the incoming request body:
// 413 if the body exceeded max_request_body_bytes, 400 otherwise.
func writeBodyReadError(w http.ResponseWriter, ri *requestInfo, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		ri.fail(w, http.StatusRequestEntityTooLarge, "request_too_large",
			fmt.Sprintf("Request body exceeds %d bytes", tooLarge.Limit), nil)
		return
	}
	ri.fail(w, http.StatusBadRequest, "bad_request", "Error reading request body", err)
}

// relayMethod returns the outbound HTTP method: the configured one, or the
// caller's own when relay.method is "inherit". An unset method means GET.
func relayMethod(configured, incoming string) string {
	m := strings.ToUpper(strings.TrimSpace(configured))
	switch m {
	case "":
		return http.MethodGet
	case config.MethodInherit:
		return strings.ToUpper(incoming)
	default:
		return m
	}
}

// routeToken waits at most token_wait_timeout seconds for the route's
// access token. The wait also ends if the caller goes away.
func routeToken(r *http.Request, route *Route) (*token.Token, error) {
	wait := route.Config.TokenWaitTimeout
	if wait <= 0 {
		wait = config.DefaultTokenWaitTimeout
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(wait)*time.Second)
	defer cancel()
	return route.Tokens.Token(ctx)
}
