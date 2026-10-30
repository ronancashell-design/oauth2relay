// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package egress_test

import (
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"oauth2relay.com/oauth2relay/v2/egress"
)

// A client that only reaches allowed hosts, on public addresses or the
// listed internal network.
func Example() {
	allowedHosts := []string{"api.example.com", "*.partner.example"}
	guard := &egress.Guard{Allowed: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}}
	base := http.DefaultTransport.(*http.Transport)
	client := &http.Client{Transport: egress.NewTransport(base, guard), Timeout: 10 * time.Second}

	target, _ := url.Parse("https://internal.example.net/admin")
	if _, ok := egress.MatchHost(target, allowedHosts); !ok {
		fmt.Println("host not allowed:", target.Host)
		return
	}
	resp, err := client.Get(target.String())
	if err == nil {
		resp.Body.Close()
	}
	// Output: host not allowed: internal.example.net
}
