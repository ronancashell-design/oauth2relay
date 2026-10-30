// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package relay

import (
	"fmt"
	"net/http"
	"net/netip"

	"oauth2relay.com/oauth2relay/v2/egress"
)

// SSRF protection (parameter mode).
//
// In parameter mode the caller chooses the target URL. allowed_hosts limits
// the host names, and the egress guard refuses connections to non-public
// addresses that are not in relay.allowed_networks (see package egress).

// guardedTransportFor returns the server's guarded transport for allowed.
// One is kept per allowed_networks setting, so connections are pooled
// across requests and configuration swaps.
func (s *Server) guardedTransportFor(allowed []netip.Prefix) *http.Transport {
	key := fmt.Sprint(allowed)
	if t, ok := s.guarded.Load(key); ok {
		return t.(*http.Transport)
	}
	t, _ := s.guarded.LoadOrStore(key, egress.NewTransport(s.transport, &egress.Guard{Allowed: allowed}))
	return t.(*http.Transport)
}
