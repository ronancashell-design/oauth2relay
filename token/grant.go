// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package token

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"oauth2relay.com/oauth2relay/v2/config"
	"oauth2relay.com/oauth2relay/v2/internal/util"
)

// buildGrantRequest returns the body and headers of the login request for
// the configured grant.
func buildGrantRequest(lc *config.LoginConfig) (string, map[string]string, error) {
	var body formBody
	switch lc.GrantType {
	case "client_credentials":
		if lc.ClientID == "" || lc.ClientSecret == "" {
			return "", nil, fmt.Errorf("client_credentials grant requires client_id and client_secret")
		}
		body.add("grant_type", "client_credentials")

	case "password":
		if lc.User == "" || lc.Password == "" || lc.ClientID == "" || lc.ClientSecret == "" {
			return "", nil, fmt.Errorf("password grant requires username, password, client_id, and client_secret")
		}
		body.add("grant_type", "password")
		body.add("username", lc.User)
		body.add("password", lc.Password)

	case "jwt":
		assertion, err := buildJWTAssertion(lc)
		if err != nil {
			return "", nil, err
		}
		body = formBody{assertion}

	case "", "custom": // Custom grant type (original behavior)
		vars := map[string]string{
			"USER":     lc.User,
			"PASSWORD": lc.Password,
			"DATA":     lc.Data,
		}
		if lc.AuthString != "" {
			vars["AUTHSTRING"] = lc.AuthString
		} else {
			creds := lc.User + ":" + lc.Password
			vars["AUTHSTRING"] = base64.StdEncoding.EncodeToString([]byte(creds))
		}
		dataStr := util.Substitute(lc.Data, vars)
		// Now substitute variables in header values as well.
		newHeaders := make(map[string]string, len(lc.Headers))
		for k, v := range lc.Headers {
			newHeaders[k] = util.Substitute(v, vars)
		}
		return dataStr, newHeaders, nil

	default:
		return "", nil, fmt.Errorf("unsupported grant type: %s", lc.GrantType)
	}

	// Standard grants: login.headers are sent as configured, but the relay
	// sets Content-Type and, for client_auth "basic", Authorization.
	headers := make(map[string]string, len(lc.Headers)+2)
	for k, v := range lc.Headers {
		headers[http.CanonicalHeaderKey(k)] = v
	}
	headers["Content-Type"] = "application/x-www-form-urlencoded"
	if lc.GrantType != "jwt" {
		if lc.ClientAuth == config.ClientAuthBasic {
			// RFC 6749 section 2.3.1: form-encode each part before base64.
			creds := url.QueryEscape(lc.ClientID) + ":" + url.QueryEscape(lc.ClientSecret)
			headers["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(creds))
		} else {
			body.add("client_id", lc.ClientID)
			body.add("client_secret", lc.ClientSecret)
		}
	}
	body.add("scope", lc.Scope)
	body.add("audience", lc.Audience)
	body.add("resource", lc.Resource)
	return body.String(), headers, nil
}

// formBody builds an application/x-www-form-urlencoded body, keeping the
// order fields are added in and skipping empty values.
type formBody []string

func (f *formBody) add(key, value string) {
	if value != "" {
		*f = append(*f, url.QueryEscape(key)+"="+url.QueryEscape(value))
	}
}

func (f formBody) String() string {
	return strings.Join(f, "&")
}
