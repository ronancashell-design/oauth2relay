// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

// Package egress limits where outbound requests may go: host allow-lists
// and a dial-time guard against server-side request forgery (SSRF).
//
// A host allow-list limits the names a request may use, but a name can
// resolve to an internal address, by mistake or on purpose (DNS
// rebinding). A Guard therefore refuses to connect to loopback, private,
// link-local (including cloud metadata at 169.254.169.254) and other
// non-public addresses unless they are in its allowed networks.
//
// The check runs in the dialer, on the address actually being connected
// to, after DNS resolution. A name cannot pass the check with one address
// and then connect to another, and redirects are checked the same way.
package egress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ErrBlocked is returned (wrapped) when a request would connect to an
// address the Guard does not allow.
var ErrBlocked = errors.New("destination address not allowed")

// nonPublicNetworks are blocked in addition to what the netip predicates
// catch (loopback, private, link-local, multicast, unspecified).
var nonPublicNetworks = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),     // "this network"
	netip.MustParsePrefix("100.64.0.0/10"), // carrier-grade NAT, also used by some cloud metadata services
	netip.MustParsePrefix("192.0.0.0/24"),  // IETF protocol assignments
	netip.MustParsePrefix("198.18.0.0/15"), // benchmarking
	netip.MustParsePrefix("240.0.0.0/4"),   // reserved, including broadcast
	netip.MustParsePrefix("64:ff9b::/96"),  // NAT64, which can reach IPv4 private addresses
	netip.MustParsePrefix("64:ff9b:1::/48"),
}

// IsPublic reports whether addr is a public unicast address.
func IsPublic(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || addr.IsLoopback() || addr.IsPrivate() || addr.IsUnspecified() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsInterfaceLocalMulticast() ||
		addr.IsMulticast() {
		return false
	}
	for _, p := range nonPublicNetworks {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

// Guard decides which destination addresses may be connected to: public
// addresses, and those in Allowed. The zero Guard allows public addresses
// only.
type Guard struct {
	Allowed []netip.Prefix
}

// Check returns an error wrapping ErrBlocked if addr is not allowed.
func (g *Guard) Check(addr netip.Addr) error {
	addr = addr.Unmap()
	if IsPublic(addr) {
		return nil
	}
	for _, p := range g.Allowed {
		if p.Contains(addr) {
			return nil
		}
	}
	return fmt.Errorf("%w: %s is not a public address and is not in the allowed networks", ErrBlocked, addr)
}

// Control is a net.Dialer Control function that rejects connections to
// addresses the guard does not allow.
func (g *Guard) Control(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("%w: cannot parse %q", ErrBlocked, address)
	}
	return g.Check(ap.Addr())
}

// CheckHost resolves host and checks every address it resolves to. It is
// used when an HTTP proxy makes the connection, so the dialer only sees the
// proxy's address. The proxy resolves the name again, so this does not
// protect against DNS rebinding the way the dialer check does.
func (g *Guard) CheckHost(ctx context.Context, host string) error {
	if addr, err := netip.ParseAddr(host); err == nil {
		return g.Check(addr)
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return err
	}
	for _, addr := range addrs {
		if err := g.Check(addr); err != nil {
			return err
		}
	}
	return nil
}

// NewTransport returns a copy of base that only connects to addresses g
// allows. Connections to an HTTP proxy chosen by base's Proxy function are
// not checked; the target's addresses are checked by name instead
// (CheckHost).
func NewTransport(base *http.Transport, g *Guard) *http.Transport {
	t := base.Clone()
	guarded := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: g.Control}
	plain := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	var proxies sync.Map // host:port of proxies in use

	proxy := base.Proxy
	t.Proxy = func(req *http.Request) (*url.URL, error) {
		if proxy == nil {
			return nil, nil
		}
		p, err := proxy(req)
		if err != nil || p == nil {
			return p, err
		}
		if err := g.CheckHost(req.Context(), req.URL.Hostname()); err != nil {
			return nil, err
		}
		proxies.Store(hostPort(p), true)
		return p, nil
	}
	t.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if _, isProxy := proxies.Load(addr); isProxy {
			return plain.DialContext(ctx, network, addr)
		}
		return guarded.DialContext(ctx, network, addr)
	}
	return t
}

// hostPort returns u's host and port, with the scheme's default port.
func hostPort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return u.Host
	}
	port := "80"
	if u.Scheme == "https" {
		port = "443"
	}
	return net.JoinHostPort(u.Hostname(), port)
}

// MatchHost returns the entry of allowed that u's host matches. Entries
// are matched case-insensitively against the hostname, or against
// host:port when the entry includes a port. A "*.example.com" entry
// matches any subdomain of example.com but not example.com itself.
func MatchHost(u *url.URL, allowed []string) (string, bool) {
	hostname := strings.ToLower(u.Hostname())
	hostport := strings.ToLower(u.Host)
	for _, entry := range allowed {
		pattern := strings.ToLower(entry)
		candidate := hostname
		if _, _, err := net.SplitHostPort(strings.TrimPrefix(pattern, "*.")); err == nil {
			candidate = hostport
		}
		if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
			if strings.HasSuffix(candidate, "."+suffix) {
				return entry, true
			}
		} else if candidate == pattern {
			return entry, true
		}
	}
	return "", false
}
