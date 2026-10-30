// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package relay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"oauth2relay.com/oauth2relay/v2/config"
)

// Outbound HTTP clients.
//
// All of a Server's outbound traffic (relay and token endpoint) shares one
// Transport so that connections are pooled and reused. Clients themselves
// are cheap and are built per call with the timeout that applies to that
// call.

// newTransport returns the transport for a Server's outbound requests.
func newTransport() *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   20,
		IdleConnTimeout:       90 * time.Second,
	}
}

// maxRelayRedirects is the most redirects followed when relay.follow_redirects is on.
const maxRelayRedirects = 5

// errRedirectBlocked is returned when a redirect target fails the checks
// in relayRedirectPolicy.
var errRedirectBlocked = errors.New("redirect blocked")

// newRelayClient returns the client for relayed requests. Redirects are
// not followed unless relay.follow_redirects is set; the 3xx response is
// returned to the caller instead. When they are followed, every hop must
// stay on an allowed host (parameter mode) or on the original host (other
// modes), and may not downgrade from https to http.
//
// In parameter mode the client only connects to public addresses and those
// in relay.allowed_networks (see netguard.go).
func (s *Server) newRelayClient(rc *config.RelayConfig) *http.Client {
	timeout := rc.Timeout
	if timeout <= 0 {
		timeout = config.DefaultRelayTimeout
	}
	client := &http.Client{Transport: s.transport, Timeout: time.Duration(timeout) * time.Second}
	if rc.Mode == config.RelayModeParameter {
		client.Transport = s.guardedTransportFor(rc.AllowedNetworkPrefixes())
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if !rc.FollowRedirects {
			return http.ErrUseLastResponse
		}
		return relayRedirectPolicy(rc, req, via)
	}
	return client
}

func relayRedirectPolicy(rc *config.RelayConfig, req *http.Request, via []*http.Request) error {
	if len(via) > maxRelayRedirects {
		return fmt.Errorf("%w: stopped after %d redirects", errRedirectBlocked, maxRelayRedirects)
	}
	prev, next := via[len(via)-1].URL, req.URL
	if next.Scheme != "http" && next.Scheme != "https" {
		return fmt.Errorf("%w: unsupported scheme %q", errRedirectBlocked, next.Scheme)
	}
	if prev.Scheme == "https" && next.Scheme == "http" {
		return fmt.Errorf("%w: https to http downgrade to %s", errRedirectBlocked, next.Host)
	}
	if rc.Mode == config.RelayModeParameter {
		if !hostAllowed(next, rc.AllowedHosts) {
			return fmt.Errorf("%w: host %q is not in relay.allowed_hosts", errRedirectBlocked, next.Host)
		}
	} else if !strings.EqualFold(next.Host, via[0].URL.Host) {
		return fmt.Errorf("%w: host %q differs from the relay target %q", errRedirectBlocked, next.Host, via[0].URL.Host)
	}
	return nil
}

// isTimeout reports whether err was caused by a timeout or deadline.
func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
