// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package relay

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"

	"oauth2relay.com/oauth2relay/v2/config"
)

// ---------------- Header handling ----------------

// hopByHopHeaders apply to a single connection and must not be forwarded by
// a proxy (RFC 9110 section 7.6.1).
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"TE",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// credentialHeaders carry the caller's own credentials. With pushheaders
// they are not forwarded unless listed in relay.forward_headers.
var credentialHeaders = []string{
	"Authorization",
	"Cookie",
}

// removeHopByHop deletes hop-by-hop headers from h, including any header
// named in the Connection header.
func removeHopByHop(h http.Header) {
	for _, v := range h.Values("Connection") {
		for _, name := range strings.Split(v, ",") {
			if name = strings.TrimSpace(name); name != "" {
				h.Del(name)
			}
		}
	}
	for _, name := range hopByHopHeaders {
		h.Del(name)
	}
}

// pushIncomingHeaders copies the caller's headers onto the outbound request
// when relay.pushheaders is enabled. Headers already set from relay.headers
// win. The API key and hop-by-hop headers are never forwarded. When
// relay.forward_headers is set only those headers are forwarded; otherwise
// everything except credential headers and relay.strip_headers is.
func pushIncomingHeaders(out, in http.Header, rc *config.RelayConfig) {
	incoming := in.Clone()
	removeHopByHop(incoming)
	incoming.Del(config.APIKeyHeader)
	for _, name := range rc.StripHeaders {
		incoming.Del(name)
	}

	if len(rc.ForwardHeaders) > 0 {
		allowed := make(http.Header, len(rc.ForwardHeaders))
		for _, name := range rc.ForwardHeaders {
			if vals := incoming.Values(name); len(vals) > 0 {
				allowed[http.CanonicalHeaderKey(name)] = vals
			}
		}
		incoming = allowed
	} else {
		for _, name := range credentialHeaders {
			incoming.Del(name)
		}
	}

	for k, values := range incoming {
		if out.Get(k) == "" {
			for _, v := range values {
				out.Add(k, v)
			}
		}
	}
}

// apiKeyMatches compares the supplied key with the configured one in
// constant time. Both are hashed first so the comparison does not reveal
// the key's length either.
func apiKeyMatches(supplied, configured string) bool {
	a := sha256.Sum256([]byte(supplied))
	b := sha256.Sum256([]byte(configured))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// hasHeader reports whether headers sets name, ignoring case.
func hasHeader(headers map[string]string, name string) bool {
	for k := range headers {
		if strings.EqualFold(k, name) {
			return true
		}
	}
	return false
}

// containsFold reports whether names includes name, ignoring case.
func containsFold(names []string, name string) bool {
	for _, n := range names {
		if strings.EqualFold(strings.TrimSpace(n), name) {
			return true
		}
	}
	return false
}
