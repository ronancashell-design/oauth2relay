// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package relay

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// ---------------- Client IP ----------------

// clientIP returns the address used for ${IP}. Without trusted proxies it is
// the direct peer. When the peer is a trusted proxy, X-Forwarded-For is
// read from right to left and the first address that is not itself a
// trusted proxy is the client. Entries a caller could have forged (those
// left of the first untrusted hop) are never used.
func clientIP(r *http.Request, trusted []netip.Prefix) string {
	peer := r.RemoteAddr
	if host, _, err := net.SplitHostPort(peer); err == nil {
		peer = host
	}
	if len(trusted) == 0 {
		return peer
	}
	peerAddr, err := netip.ParseAddr(peer)
	if err != nil || !isTrusted(peerAddr, trusted) {
		return peer
	}

	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		for _, h := range strings.Split(v, ",") {
			hops = append(hops, strings.TrimSpace(h))
		}
	}
	client := peer
	for i := len(hops) - 1; i >= 0; i-- {
		addr, err := netip.ParseAddr(hops[i])
		if err != nil {
			// A malformed entry ends the chain we can trust.
			break
		}
		client = addr.Unmap().String()
		if !isTrusted(addr, trusted) {
			break
		}
	}
	return client
}

func isTrusted(addr netip.Addr, trusted []netip.Prefix) bool {
	addr = addr.Unmap()
	for _, p := range trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
