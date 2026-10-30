// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package token_test

import (
	"context"
	"log"

	"oauth2relay.com/oauth2relay/v2/token"
)

// Exchange a caller's access token for one scoped to a downstream API.
func ExampleExchanger() {
	var e token.Exchanger
	callerToken := "eyJ..." // the validated inbound access token
	res, err := e.Exchange(context.Background(), &token.ExchangeRequest{
		URL:          "https://idp.example.com/oauth2/token",
		ClientID:     "knowledge-server",
		ClientSecret: "from-a-secret-manager",
		SubjectToken: callerToken,
		Audience:     []string{"https://crm.example.com/api"},
		Scope:        []string{"crm:read"},
	})
	if err != nil {
		log.Printf("exchange failed (permanent: %v): %v", token.IsPermanent(err), err)
		return
	}
	// Cache res.AccessToken until res.ExpiresAt, keyed by caller and audience.
	_ = res
}
